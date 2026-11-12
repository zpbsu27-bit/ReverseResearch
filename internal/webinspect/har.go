package webinspect

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"
)

func parseHAR(body []byte) ([]json.RawMessage, []HAREntry, error) {
	var p struct {
		Log *struct {
			Version string             `json:"version"`
			Entries *[]json.RawMessage `json:"entries"`
		} `json:"log"`
	}
	if err := decodeOfflineJSON(body, &p); err != nil {
		return nil, nil, err
	}
	if p.Log == nil || p.Log.Version != "1.2" || p.Log.Entries == nil {
		return nil, nil, errors.New("HAR requires log.version=1.2 and log.entries array")
	}
	raw := *p.Log.Entries
	if len(raw) > maxHAREntries {
		return nil, nil, errors.New("HAR exceeds 100000 entry limit")
	}
	entries := make([]HAREntry, 0, len(raw))
	for i, r := range raw {
		e, err := projectHAREntry(r, i)
		if err != nil {
			return nil, nil, fmt.Errorf("HAR entry %d: %w", i, err)
		}
		entries = append(entries, e)
	}
	return raw, entries, nil
}

const (
	MaxHARBytes        = 32 << 20
	DefaultHARPageSize = 50
	MaxHARPageSize     = 200
	maxHAREntries      = 100000
	maxHARPageBytes    = 48 << 10
)

type HAROptions struct {
	Offset         int    `json:"offset"`
	Limit          int    `json:"limit"`
	ExpectedSHA256 string `json:"expected_sha256,omitempty"`
}

type HAREntry struct {
	Ordinal     int      `json:"ordinal"`
	JSONPointer string   `json:"json_pointer"`
	Method      string   `json:"method"`
	URL         string   `json:"url"`
	QueryKeys   []string `json:"query_keys"`
	Status      int      `json:"status"`
	MimeType    string   `json:"mime_type,omitempty"`
	StartedAt   string   `json:"started_at,omitempty"`
	DurationMS  *float64 `json:"duration_ms,omitempty"`
}

type HARReport struct {
	Path               string     `json:"path"`
	SHA256             string     `json:"sha256"`
	Bytes              int        `json:"bytes"`
	Version            string     `json:"version"`
	ValidationProfile  string     `json:"validation_profile"`
	EvidenceAuthority  string     `json:"evidence_authority"`
	TotalEntries       int        `json:"total_entries"`
	Offset             int        `json:"offset"`
	ReturnedEntries    int        `json:"returned_entries"`
	OmittedEntries     int        `json:"omitted_entries"`
	NextOffset         *int       `json:"next_offset,omitempty"`
	Entries            []HAREntry `json:"entries"`
	CoverageComplete   bool       `json:"coverage_complete"`
	Truncated          bool       `json:"truncated"`
	PageBytesLimit     int        `json:"page_bytes_limit"`
	ExcludedFields     []string   `json:"excluded_fields"`
	Limitations        []string   `json:"limitations"`
	ExecutionPerformed bool       `json:"execution_performed"`
	NetworkInteraction bool       `json:"network_interaction"`
}

type harEntryInput struct {
	Request *struct {
		Method string `json:"method"`
		URL    string `json:"url"`
	} `json:"request"`
	Response *struct {
		Status  *int `json:"status"`
		Content struct {
			MimeType string `json:"mimeType"`
		} `json:"content"`
	} `json:"response"`
	StartedAt  string   `json:"startedDateTime"`
	DurationMS *float64 `json:"time"`
}

// InspectHAR is a summary projection, not a HAR validator, replay client or
// browser capture owner. Validate every entry before returning a bounded page.
func InspectHAR(path string, options HAROptions) (HARReport, error) {
	if options.Limit == 0 {
		options.Limit = DefaultHARPageSize
	}
	if options.Offset < 0 || options.Limit < 1 || options.Limit > MaxHARPageSize {
		return HARReport{}, errors.New("HAR offset must be nonnegative; limit must be 1..200 entries")
	}
	body, absolute, digest, err := readBoundedFile(path, MaxHARBytes)
	if err != nil {
		return HARReport{}, err
	}
	if err := checkExpectedSHA256(digest, options.ExpectedSHA256); err != nil {
		return HARReport{}, err
	}
	_, entries, err := parseHAR(body)
	if err != nil {
		return HARReport{}, err
	}
	if options.Offset > len(entries) {
		return HARReport{}, errors.New("HAR offset is outside retained entries")
	}
	end := min(len(entries), options.Offset+options.Limit)
	report := HARReport{
		Path: absolute, SHA256: digest, Bytes: len(body), Version: "1.2",
		ValidationProfile: "rr.har-summary.v1", EvidenceAuthority: "historical-producer-record",
		TotalEntries: len(entries), Offset: options.Offset, Entries: make([]HAREntry, 0, end-options.Offset),
		PageBytesLimit: maxHARPageBytes,
		ExcludedFields: []string{"URL userinfo, query values and fragment", "headers", "cookies", "request/response bodies", "unknown extensions"},
		Limitations: []string{
			"Stored producer records do not establish current browser, server or runtime identity; no request is replayed.",
			"This summary validates projected fields and JSON structure, not the complete HAR 1.2 schema or decoded body bytes.",
			"Host, URL path, query names and source path remain visible; exclusion is not general-purpose secret detection.",
		},
	}
	pageBytes, pageFull := 0, false
	for ordinal, entry := range entries {
		if ordinal >= options.Offset && ordinal < end && !pageFull {
			encoded, err := json.Marshal(entry)
			if err != nil {
				return HARReport{}, err
			}
			if len(encoded)+1 > maxHARPageBytes {
				return HARReport{}, fmt.Errorf("HAR entry %d exceeds page byte budget", ordinal)
			}
			if pageBytes+len(encoded)+1 > maxHARPageBytes {
				pageFull = true
				continue
			}
			pageBytes += len(encoded) + 1
			report.Entries = append(report.Entries, entry)
		}
	}
	report.ReturnedEntries = len(report.Entries)
	report.OmittedEntries = len(entries) - len(report.Entries)
	report.CoverageComplete = report.OmittedEntries == 0
	report.Truncated = !report.CoverageComplete
	next := options.Offset + len(report.Entries)
	if next < len(entries) {
		report.NextOffset = &next
	}
	return report, nil
}

func projectHAREntry(raw json.RawMessage, ordinal int) (HAREntry, error) {
	var input harEntryInput
	if err := json.Unmarshal(raw, &input); err != nil {
		return HAREntry{}, errors.New("projected HAR fields have invalid types")
	}
	if input.Request == nil || input.Response == nil || input.Response.Status == nil {
		return HAREntry{}, errors.New("request, response and response.status are required")
	}
	if !validHARMethod(input.Request.Method) {
		return HAREntry{}, errors.New("request.method must be an HTTP token of at most 64 bytes")
	}
	if len(input.Request.URL) > 8192 {
		return HAREntry{}, errors.New("request.url exceeds 8192 bytes")
	}
	u, err := url.Parse(input.Request.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return HAREntry{}, errors.New("request.url must be a bounded absolute HTTP(S) URL")
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return HAREntry{}, errors.New("request.url query is malformed")
	}
	if *input.Response.Status < 0 || *input.Response.Status > 999 {
		return HAREntry{}, errors.New("response.status must be 0..999; zero preserves an unreported HTTP response")
	}
	if len(input.Response.Content.MimeType) > 1024 {
		return HAREntry{}, errors.New("response MIME type exceeds 1024 bytes")
	}
	if input.StartedAt != "" {
		if _, err := time.Parse(time.RFC3339Nano, input.StartedAt); err != nil {
			return HAREntry{}, errors.New("startedDateTime must be RFC3339 when supplied")
		}
	}
	if input.DurationMS != nil && *input.DurationMS < 0 {
		return HAREntry{}, errors.New("time must be nonnegative when supplied")
	}
	u.User, u.RawQuery, u.Fragment, u.RawFragment = nil, "", "", ""
	u.ForceQuery = false
	keys := make([]string, 0, len(query))
	for key := range query {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return HAREntry{
		Ordinal: ordinal, JSONPointer: fmt.Sprintf("/log/entries/%d", ordinal),
		Method: input.Request.Method, URL: u.String(), QueryKeys: keys,
		Status: *input.Response.Status, MimeType: input.Response.Content.MimeType,
		StartedAt: input.StartedAt, DurationMS: input.DurationMS,
	}, nil
}

func validHARMethod(method string) bool {
	if len(method) == 0 || len(method) > 64 {
		return false
	}
	for _, ch := range method {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", ch)) {
			return false
		}
	}
	return true
}
