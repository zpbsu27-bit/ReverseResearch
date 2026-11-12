package webinspect

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"
)

const (
	DefaultSourceReadBytes = 8192
	MaxSourceReadBytes     = 65536
	maxMapItems            = 100000
	maxMapLabelBytes       = 4096
)

type sourceMapPayload struct {
	Version        int             `json:"version"`
	File           string          `json:"file"`
	SourceRoot     string          `json:"sourceRoot"`
	Sources        *[]*string      `json:"sources"`
	Names          []*string       `json:"names"`
	Mappings       *string         `json:"mappings"`
	SourcesContent json.RawMessage `json:"sourcesContent"`
	Sections       json.RawMessage `json:"sections"`
	contents       []*string
	sources        []string
	roots          []string
	segments       []mapSegment
	indexed        bool
}

func parseSourceMap(body []byte) (sourceMapPayload, error) {
	return parseMapTree(body, 0, &mapBudget{})
}

func parseClassicMap(body []byte) (sourceMapPayload, error) {
	var payload sourceMapPayload
	if err := decodeOfflineJSON(body, &payload); err != nil {
		return payload, fmt.Errorf("decode source map: %w", err)
	}
	if payload.Version != 3 {
		return payload, fmt.Errorf("unsupported source map version %d", payload.Version)
	}
	if payload.Sources == nil || payload.Mappings == nil {
		return payload, errors.New("classic source map requires sources array and mappings string")
	}
	if len(*payload.Sources) > maxMapItems || len(payload.Names) > maxMapItems {
		return payload, errors.New("source map inventory exceeds 100000 items")
	}
	if len(payload.File) > maxMapLabelBytes || len(payload.SourceRoot) > maxMapLabelBytes {
		return payload, errors.New("source map label exceeds 4096 bytes")
	}
	payload.sources = make([]string, 0, len(*payload.Sources))
	for _, name := range *payload.Sources {
		if name == nil {
			return payload, errors.New("sources must contain string names; null source declarations are unsupported")
		}
		if len(*name) > maxMapLabelBytes {
			return payload, errors.New("source map source name exceeds 4096 bytes")
		}
		payload.sources = append(payload.sources, *name)
	}
	for _, name := range payload.Names {
		if name == nil || len(*name) > maxMapLabelBytes {
			return payload, errors.New("source map names must contain strings")
		}
	}
	for _, ch := range *payload.Mappings {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || strings.ContainsRune("+/,;", ch)) {
			return payload, errors.New("source map mappings contains invalid encoded characters")
		}
	}
	if len(payload.SourcesContent) != 0 {
		if string(payload.SourcesContent) == "null" {
			return payload, errors.New("sourcesContent must be an array when present")
		}
		if err := json.Unmarshal(payload.SourcesContent, &payload.contents); err != nil {
			return payload, errors.New("sourcesContent must contain strings or null")
		}
		if len(payload.contents) != len(*payload.Sources) {
			return payload, errors.New("sourcesContent length must equal sources length")
		}
	}
	payload.roots = make([]string, len(payload.sources))
	for i := range payload.roots {
		payload.roots[i] = payload.SourceRoot
	}
	return payload, nil
}

func sourceMapSummary(payload sourceMapPayload, path, digest string, inline bool) *SourceMapSummary {
	embedded := 0
	for _, value := range payload.contents {
		if value != nil {
			embedded++
		}
	}
	sources := payload.sources
	count, bytes := 0, 0
	for count < len(sources) && count < 64 && bytes+len(sources[count]) <= 16384 {
		bytes += len(sources[count])
		count++
	}
	return &SourceMapSummary{
		Path: path, SHA256: digest, Version: payload.Version, File: payload.File,
		SourceRoot: payload.SourceRoot, Sources: sources[:count], SourcesCount: len(sources),
		SourcesTruncated: count != len(sources), NamesCount: len(payload.Names),
		HasMappings: len(payload.segments) != 0, EmbeddedCount: embedded, Inline: inline, Indexed: payload.indexed,
	}
}

func decodeInlineMap(ref string) ([]byte, string, error) {
	meta, encoded, found := strings.Cut(ref, ",")
	if !found || len(meta) > 128 {
		return nil, "", errors.New("invalid inline source-map data URL")
	}
	parts := strings.Split(strings.ToLower(meta), ";")
	if parts[0] != "data:application/json" {
		return nil, "", errors.New("inline source map must use application/json")
	}
	base64Encoded := false
	for _, option := range parts[1:] {
		switch option {
		case "base64":
			if base64Encoded {
				return nil, "", errors.New("duplicate inline source-map base64 option")
			}
			base64Encoded = true
		case "charset=utf-8", "charset=utf8":
		default:
			return nil, "", errors.New("unsupported inline source-map data URL option")
		}
	}
	var body []byte
	var err error
	if base64Encoded {
		body, err = base64.StdEncoding.Strict().DecodeString(encoded)
	} else {
		var decoded string
		decoded, err = url.PathUnescape(encoded)
		body = []byte(decoded)
	}
	if err != nil {
		return nil, "", errors.New("invalid inline source-map encoding")
	}
	if len(body) > MaxSourceMapBytes {
		return nil, "", errors.New("inline source map exceeds byte limit")
	}
	sum := sha256.Sum256(body)
	return body, hex.EncodeToString(sum[:]), nil
}

type SourceMapReadOptions struct {
	SourceIndex    int    `json:"source_index"`
	Offset         int    `json:"offset"`
	Limit          int    `json:"limit"`
	ExpectedSHA256 string `json:"expected_sha256,omitempty"`
}

type SourceMapReadReport struct {
	Path               string `json:"path"`
	SHA256             string `json:"sha256"`
	SourceIndex        int    `json:"source_index"`
	SourceCount        int    `json:"source_count"`
	Source             string `json:"source"`
	SourceRoot         string `json:"source_root,omitempty"`
	ContentAvailable   bool   `json:"content_available"`
	UnavailableReason  string `json:"unavailable_reason,omitempty"`
	ContentSHA256      string `json:"content_sha256,omitempty"`
	TotalBytes         int    `json:"total_bytes"`
	Offset             int    `json:"offset"`
	ReadBytes          int    `json:"read_bytes"`
	NextOffset         *int   `json:"next_offset,omitempty"`
	Text               string `json:"text"`
	CoverageComplete   bool   `json:"coverage_complete"`
	Truncated          bool   `json:"truncated"`
	ExecutionPerformed bool   `json:"execution_performed"`
	NetworkInteraction bool   `json:"network_interaction"`
}

// Only return embedded Unicode text. sourceRoot and sources are labels, never
// paths to open or URLs to fetch. Its digest identifies decoded UTF-8 content.
func ReadSourceMap(path string, options SourceMapReadOptions) (SourceMapReadReport, error) {
	if options.Limit == 0 {
		options.Limit = DefaultSourceReadBytes
	}
	if options.Offset < 0 || options.Limit < 4 || options.Limit > MaxSourceReadBytes || options.SourceIndex < 0 {
		return SourceMapReadReport{}, errors.New("source_index/offset must be nonnegative; limit must be 4..65536 bytes")
	}
	body, absolute, digest, err := readBoundedFile(path, MaxSourceMapBytes)
	if err != nil {
		return SourceMapReadReport{}, err
	}
	if err := checkExpectedSHA256(digest, options.ExpectedSHA256); err != nil {
		return SourceMapReadReport{}, err
	}
	payload, err := parseSourceMap(body)
	if err != nil {
		return SourceMapReadReport{}, err
	}
	if options.SourceIndex >= len(payload.sources) {
		return SourceMapReadReport{}, errors.New("source_index is outside the source inventory")
	}
	report := SourceMapReadReport{
		Path: absolute, SHA256: digest, SourceIndex: options.SourceIndex,
		SourceCount: len(payload.sources), Source: payload.sources[options.SourceIndex],
		SourceRoot: payload.roots[options.SourceIndex], Offset: options.Offset,
	}
	if payload.contents == nil || payload.contents[options.SourceIndex] == nil {
		report.UnavailableReason = "selected source has no embedded sourcesContent; external source loading is not performed"
		if options.Offset != 0 {
			return SourceMapReadReport{}, errors.New("offset must be zero when embedded content is unavailable")
		}
		return report, nil
	}
	content := *payload.contents[options.SourceIndex]
	if options.Offset > len(content) || (options.Offset < len(content) && !utf8.RuneStart(content[options.Offset])) {
		return SourceMapReadReport{}, errors.New("offset must be within embedded content at a UTF-8 boundary")
	}
	end := min(len(content), options.Offset+options.Limit)
	for end < len(content) && !utf8.RuneStart(content[end]) {
		end--
	}
	sum := sha256.Sum256([]byte(content))
	report.ContentAvailable, report.ContentSHA256 = true, hex.EncodeToString(sum[:])
	report.TotalBytes, report.ReadBytes = len(content), end-options.Offset
	report.Text = content[options.Offset:end]
	report.CoverageComplete = options.Offset == 0 && end == len(content)
	report.Truncated = !report.CoverageComplete
	if end < len(content) {
		report.NextOffset = &end
	}
	return report, nil
}
