package webinspect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"reverseresearch/internal/targetidentity"
	"reverseresearch/internal/toolindex"
)

const (
	DefaultCDPTimeout = 3 * time.Second
	MaxCDPTimeout     = 15 * time.Second
	MaxSourceBytes    = 32 << 20
	MaxSourceMapBytes = 32 << 20
	MaxWASMBytes      = 64 << 20
)

var profileIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$`)

type Backend struct {
	Name                  string `json:"name"`
	Available             bool   `json:"available"`
	Path                  string `json:"path,omitempty"`
	Source                string `json:"source"`
	Protocol              string `json:"protocol"`
	IntegrationPolicy     string `json:"integration_policy"`
	RedistributionAllowed bool   `json:"redistribution_allowed"`
	SHA256                string `json:"sha256,omitempty"`
	Size                  int64  `json:"size,omitempty"`
}

type BackendStatus struct {
	Backends []Backend `json:"backends"`
}

func Backends(index toolindex.Index) BackendStatus {
	names := []string{"chrome", "msedge"}
	out := BackendStatus{}
	for _, name := range names {
		tool, _ := index.ByName(name)
		backend := Backend{
			Name: name, Available: tool.Available, Path: tool.Path, Source: tool.Source,
			Protocol:              "Chrome DevTools Protocol",
			IntegrationPolicy:     "installed-only; ReverseResearch does not bundle or redistribute the browser",
			RedistributionAllowed: false,
		}
		if tool.Available {
			if identity, err := targetidentity.Inspect(tool.Path); err == nil {
				backend.SHA256 = identity.SHA256
				backend.Size = identity.Size
			}
		}
		out.Backends = append(out.Backends, backend)
	}
	return out
}

type ProfilePlan struct {
	ProfileID        string   `json:"profile_id"`
	ProfilePath      string   `json:"profile_path"`
	Browser          Backend  `json:"browser"`
	Arguments        []string `json:"arguments"`
	DailyProfileSafe bool     `json:"daily_profile_safe"`
}

func PrepareProfile(root, profileID, browserName string, index toolindex.Index) (ProfilePlan, error) {
	profileID = strings.TrimSpace(profileID)
	if !profileIDPattern.MatchString(profileID) {
		return ProfilePlan{}, errors.New("profile_id must match [A-Za-z0-9][A-Za-z0-9._-]{0,79}")
	}
	browserName = strings.ToLower(strings.TrimSpace(browserName))
	if browserName == "" {
		browserName = "chrome"
	}
	if browserName != "chrome" && browserName != "msedge" {
		return ProfilePlan{}, fmt.Errorf("unsupported browser %q; expected chrome or msedge", browserName)
	}
	status := Backends(index)
	var browser Backend
	for _, candidate := range status.Backends {
		if candidate.Name == browserName {
			browser = candidate
			break
		}
	}
	if !browser.Available {
		return ProfilePlan{}, fmt.Errorf("%s backend unavailable; run tools scan and use an installed browser", browserName)
	}
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return ProfilePlan{}, fmt.Errorf("resolve project root: %w", err)
	}
	base := filepath.Join(absoluteRoot, "state", "web-profiles")
	profilePath := filepath.Join(base, profileID)
	if err := os.MkdirAll(profilePath, 0o700); err != nil {
		return ProfilePlan{}, fmt.Errorf("create isolated web profile: %w", err)
	}
	resolvedBase, err := filepath.Abs(base)
	if err != nil {
		return ProfilePlan{}, err
	}
	resolvedProfile, err := filepath.Abs(profilePath)
	if err != nil {
		return ProfilePlan{}, err
	}
	rel, err := filepath.Rel(resolvedBase, resolvedProfile)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
		return ProfilePlan{}, errors.New("isolated profile escaped state/web-profiles")
	}
	return ProfilePlan{
		ProfileID:   profileID,
		ProfilePath: resolvedProfile,
		Browser:     browser,
		Arguments: []string{
			"--user-data-dir=" + resolvedProfile,
			"--remote-debugging-address=127.0.0.1",
			"--remote-debugging-port=0",
			"--no-first-run",
			"--no-default-browser-check",
		},
		DailyProfileSafe: true,
	}, nil
}

type CDPVersion struct {
	Browser              string `json:"Browser"`
	ProtocolVersion      string `json:"Protocol-Version"`
	UserAgent            string `json:"User-Agent"`
	V8Version            string `json:"V8-Version"`
	WebKitVersion        string `json:"WebKit-Version"`
	WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
}

type CDPTarget struct {
	ID                   string `json:"id"`
	Type                 string `json:"type"`
	Title                string `json:"title"`
	URL                  string `json:"url"`
	WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
}

type CDPReport struct {
	Endpoint string      `json:"endpoint"`
	Version  CDPVersion  `json:"version"`
	Targets  []CDPTarget `json:"targets"`
}

func InspectCDP(ctx context.Context, endpoint string, timeout time.Duration) (CDPReport, error) {
	base, err := validateLoopbackEndpoint(endpoint)
	if err != nil {
		return CDPReport{}, err
	}
	if timeout <= 0 {
		timeout = DefaultCDPTimeout
	}
	if timeout > MaxCDPTimeout {
		return CDPReport{}, fmt.Errorf("CDP timeout %s exceeds maximum %s", timeout, MaxCDPTimeout)
	}
	client := &http.Client{Timeout: timeout}
	versionURL := strings.TrimRight(base.String(), "/") + "/json/version"
	targetsURL := strings.TrimRight(base.String(), "/") + "/json/list"
	var version CDPVersion
	if err := getJSON(ctx, client, versionURL, &version); err != nil {
		return CDPReport{}, fmt.Errorf("read CDP version: %w", err)
	}
	var targets []CDPTarget
	if err := getJSON(ctx, client, targetsURL, &targets); err != nil {
		return CDPReport{}, fmt.Errorf("read CDP targets: %w", err)
	}
	return CDPReport{Endpoint: base.String(), Version: version, Targets: targets}, nil
}

func validateLoopbackEndpoint(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("CDP endpoint is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse CDP endpoint: %w", err)
	}
	if u.Scheme != "http" {
		return nil, errors.New("CDP endpoint must use http")
	}
	host := u.Hostname()
	if host == "" {
		return nil, errors.New("CDP endpoint host is required")
	}
	ip := net.ParseIP(host)
	if strings.EqualFold(host, "localhost") {
		return u, nil
	}
	if ip == nil || !ip.IsLoopback() {
		return nil, errors.New("CDP endpoint must be loopback-only")
	}
	return u, nil
}

func getJSON(ctx context.Context, client *http.Client, target string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %s", resp.Status)
	}
	limited := io.LimitReader(resp.Body, 4<<20)
	decoder := json.NewDecoder(limited)
	if err := decoder.Decode(out); err != nil {
		return err
	}
	return nil
}

type SourceMapSummary struct {
	Path             string   `json:"path"`
	SHA256           string   `json:"sha256"`
	Version          int      `json:"version"`
	File             string   `json:"file,omitempty"`
	SourceRoot       string   `json:"source_root,omitempty"`
	Sources          []string `json:"sources"`
	SourcesCount     int      `json:"sources_count"`
	SourcesTruncated bool     `json:"sources_truncated"`
	Inline           bool     `json:"inline"`
	Indexed          bool     `json:"indexed"`
	NamesCount       int      `json:"names_count"`
	HasMappings      bool     `json:"has_mappings"`
	EmbeddedCount    int      `json:"embedded_source_count"`
}

type SourceReport struct {
	Path                      string            `json:"path"`
	SHA256                    string            `json:"sha256"`
	Bytes                     int               `json:"bytes"`
	SourceMappingURL          string            `json:"source_mapping_url,omitempty"`
	SourceMappingURLTruncated bool              `json:"source_mapping_url_truncated"`
	SourceMap                 *SourceMapSummary `json:"source_map,omitempty"`
}

func AnalyzeSource(path string) (SourceReport, error) {
	body, absolute, digest, err := readBoundedFile(path, MaxSourceBytes)
	if err != nil {
		return SourceReport{}, err
	}
	report := SourceReport{Path: absolute, SHA256: digest, Bytes: len(body)}
	ref := findSourceMappingURL(body)
	report.SourceMappingURL = ref
	if ref == "" {
		return report, nil
	}
	if strings.HasPrefix(ref, "data:") {
		// The encoded map can fill the input budget; it does not belong inline
		// in an MCP result. Return its decoded digest and bounded inventory.
		meta, _, _ := strings.Cut(ref, ",")
		report.SourceMappingURL = meta + ",[inline content omitted]"
		report.SourceMappingURLTruncated = true
		mapBody, mapDigest, err := decodeInlineMap(ref)
		if err != nil {
			return SourceReport{}, err
		}
		payload, err := parseSourceMap(mapBody)
		if err != nil {
			return SourceReport{}, err
		}
		report.SourceMap = sourceMapSummary(payload, absolute+"#sourceMappingURL", mapDigest, true)
		return report, nil
	}
	if len(ref) > maxMapLabelBytes {
		return SourceReport{}, errors.New("sourceMappingURL exceeds 4096 bytes")
	}
	reference, err := url.Parse(ref)
	if err != nil {
		return SourceReport{}, errors.New("invalid sourceMappingURL")
	}
	if reference.IsAbs() || reference.Host != "" {
		return report, nil
	}
	mapPath := filepath.Join(filepath.Dir(absolute), filepath.FromSlash(reference.Path))
	mapBody, mapAbsolute, mapDigest, err := readBoundedFile(mapPath, MaxSourceMapBytes)
	if err != nil {
		return SourceReport{}, fmt.Errorf("read referenced source map: %w", err)
	}
	payload, err := parseSourceMap(mapBody)
	if err != nil {
		return SourceReport{}, err
	}
	report.SourceMap = sourceMapSummary(payload, mapAbsolute, mapDigest, false)
	return report, nil
}

func findSourceMappingURL(body []byte) string {
	// Avoid Scanner's line-size ceiling for minified bundles and inline maps.
	js, css := []byte("//# sourceMappingURL="), []byte("/*# sourceMappingURL=")
	j, c := bytes.LastIndex(body, js), bytes.LastIndex(body, css)
	if j < 0 && c < 0 {
		return ""
	}
	start, cssComment := j+len(js), c > j
	if cssComment {
		start = c + len(css)
	}
	value := body[start:]
	if end := bytes.IndexAny(value, "\r\n"); end >= 0 {
		value = value[:end]
	}
	if cssComment {
		if end := bytes.Index(value, []byte("*/")); end >= 0 {
			value = value[:end]
		}
	}
	return strings.TrimSpace(string(value))
}

type WASMImport struct {
	Module string `json:"module"`
	Name   string `json:"name"`
	Kind   string `json:"kind"`
}

type WASMExport struct {
	Name  string `json:"name"`
	Kind  string `json:"kind"`
	Index uint32 `json:"index"`
}

type WASMSection struct {
	ID            byte   `json:"id"`
	Name          string `json:"name"`
	Size          uint32 `json:"size"`
	PayloadOffset int    `json:"payload_offset"`
	PayloadEnd    int    `json:"payload_end"`
}

type WASMReport struct {
	Path     string        `json:"path"`
	SHA256   string        `json:"sha256"`
	Version  uint32        `json:"version"`
	Sections []WASMSection `json:"sections"`
	Imports  []WASMImport  `json:"imports"`
	Exports  []WASMExport  `json:"exports"`
	WABT     *WABTReport   `json:"wabt,omitempty"`
}

func InspectWASM(path string) (WASMReport, error) {
	body, absolute, digest, err := readBoundedFile(path, MaxWASMBytes)
	if err != nil {
		return WASMReport{}, err
	}
	report, err := wasmEnvelope(body, absolute, digest)
	if err != nil {
		return WASMReport{}, err
	}
	for _, section := range report.Sections {
		payload := body[section.PayloadOffset:section.PayloadEnd]
		switch section.ID {
		case 2:
			report.Imports, err = parseImports(payload)
		case 7:
			report.Exports, err = parseExports(payload)
		}
		if err != nil {
			return WASMReport{}, fmt.Errorf("parse %s: %w", section.Name, err)
		}
	}
	return report, nil
}

// wasmEnvelope is the shared byte-range owner. It does not establish module
// semantics; full validation is delegated to the explicitly selected WABT profile.
func wasmEnvelope(body []byte, absolute, digest string) (WASMReport, error) {
	if len(body) < 8 || !bytes.Equal(body[:4], []byte{0x00, 0x61, 0x73, 0x6d}) {
		return WASMReport{}, errors.New("file is not a WebAssembly binary")
	}
	version := uint32(body[4]) | uint32(body[5])<<8 | uint32(body[6])<<16 | uint32(body[7])<<24
	report := WASMReport{Path: absolute, SHA256: digest, Version: version}
	if version != 1 {
		return WASMReport{}, errors.New("unsupported WebAssembly binary version")
	}
	cursor := 8
	for cursor < len(body) {
		if len(report.Sections) >= 4096 {
			return WASMReport{}, errors.New("WebAssembly section count exceeds 4096")
		}
		id := body[cursor]
		cursor++
		size, n, err := readULEB(body[cursor:])
		if err != nil {
			return WASMReport{}, fmt.Errorf("section size: %w", err)
		}
		cursor += n
		end := cursor + int(size)
		if end < cursor || end > len(body) {
			return WASMReport{}, errors.New("WebAssembly section exceeds file bounds")
		}
		name := sectionName(id)
		report.Sections = append(report.Sections, WASMSection{ID: id, Name: name, Size: size, PayloadOffset: cursor, PayloadEnd: end})
		cursor = end
	}
	return report, nil
}

func parseImports(body []byte) ([]WASMImport, error) {
	count, n, err := readULEB(body)
	if err != nil {
		return nil, err
	}
	if count > 100000 || uint64(count)*4 > uint64(len(body)-n) {
		return nil, errors.New("WebAssembly import count exceeds payload or budget")
	}
	cursor := n
	out := make([]WASMImport, 0, count)
	for i := uint32(0); i < count; i++ {
		module, used, err := readName(body[cursor:])
		if err != nil {
			return nil, err
		}
		cursor += used
		name, used, err := readName(body[cursor:])
		if err != nil {
			return nil, err
		}
		cursor += used
		if cursor >= len(body) {
			return nil, io.ErrUnexpectedEOF
		}
		kind := body[cursor]
		cursor++
		used, err = skipImportType(body[cursor:], kind)
		if err != nil {
			return nil, err
		}
		cursor += used
		out = append(out, WASMImport{Module: module, Name: name, Kind: externalKind(kind)})
	}
	if cursor != len(body) {
		return nil, errors.New("trailing WebAssembly import bytes")
	}
	return out, nil
}

func parseExports(body []byte) ([]WASMExport, error) {
	count, n, err := readULEB(body)
	if err != nil {
		return nil, err
	}
	if count > 100000 || uint64(count)*3 > uint64(len(body)-n) {
		return nil, errors.New("WebAssembly export count exceeds payload or budget")
	}
	cursor := n
	out := make([]WASMExport, 0, count)
	for i := uint32(0); i < count; i++ {
		name, used, err := readName(body[cursor:])
		if err != nil {
			return nil, err
		}
		cursor += used
		if cursor >= len(body) {
			return nil, io.ErrUnexpectedEOF
		}
		kind := body[cursor]
		cursor++
		index, used, err := readULEB(body[cursor:])
		if err != nil {
			return nil, err
		}
		cursor += used
		out = append(out, WASMExport{Name: name, Kind: externalKind(kind), Index: index})
	}
	if cursor != len(body) {
		return nil, errors.New("trailing WebAssembly export bytes")
	}
	return out, nil
}

func skipImportType(body []byte, kind byte) (int, error) {
	switch kind {
	case 0:
		_, n, err := readULEB(body)
		return n, err
	case 1:
		return skipTableType(body)
	case 2:
		return skipLimits(body)
	case 3:
		if len(body) < 2 {
			return 0, io.ErrUnexpectedEOF
		}
		return 2, nil
	case 4:
		if len(body) < 1 {
			return 0, io.ErrUnexpectedEOF
		}
		_, n, err := readULEB(body[1:])
		return 1 + n, err
	default:
		return 0, fmt.Errorf("unknown import kind %d", kind)
	}
}

func skipTableType(body []byte) (int, error) {
	if len(body) < 1 {
		return 0, io.ErrUnexpectedEOF
	}
	n, err := skipLimits(body[1:])
	if err != nil {
		return 0, err
	}
	return 1 + n, nil
}

func skipLimits(body []byte) (int, error) {
	if len(body) < 1 {
		return 0, io.ErrUnexpectedEOF
	}
	flags := body[0]
	cursor := 1
	_, n, err := readULEB(body[cursor:])
	if err != nil {
		return 0, err
	}
	cursor += n
	if flags&0x01 != 0 {
		_, n, err = readULEB(body[cursor:])
		if err != nil {
			return 0, err
		}
		cursor += n
	}
	return cursor, nil
}

func readName(body []byte) (string, int, error) {
	length, n, err := readULEB(body)
	if err != nil {
		return "", 0, err
	}
	end := n + int(length)
	if end < n || end > len(body) {
		return "", 0, io.ErrUnexpectedEOF
	}
	return string(body[n:end]), end, nil
}

func readULEB(body []byte) (uint32, int, error) {
	var value uint32
	for i := 0; i < 5; i++ {
		if i >= len(body) {
			return 0, 0, io.ErrUnexpectedEOF
		}
		b := body[i]
		if i == 4 && b&0xf0 != 0 {
			return 0, 0, errors.New("ULEB128 value exceeds uint32")
		}
		value |= uint32(b&0x7f) << (7 * i)
		if b&0x80 == 0 {
			return value, i + 1, nil
		}
	}
	return 0, 0, errors.New("ULEB128 value exceeds uint32")
}

func externalKind(kind byte) string {
	switch kind {
	case 0:
		return "function"
	case 1:
		return "table"
	case 2:
		return "memory"
	case 3:
		return "global"
	case 4:
		return "tag"
	default:
		return strconv.Itoa(int(kind))
	}
}

func sectionName(id byte) string {
	switch id {
	case 0:
		return "custom"
	case 1:
		return "type"
	case 2:
		return "import"
	case 3:
		return "function"
	case 4:
		return "table"
	case 5:
		return "memory"
	case 6:
		return "global"
	case 7:
		return "export"
	case 8:
		return "start"
	case 9:
		return "element"
	case 10:
		return "code"
	case 11:
		return "data"
	case 12:
		return "data-count"
	case 13:
		return "tag"
	default:
		return "unknown"
	}
}

func readBoundedFile(path string, limit int64) ([]byte, string, string, error) {
	return targetidentity.CaptureFile(strings.TrimSpace(path), limit)
}
