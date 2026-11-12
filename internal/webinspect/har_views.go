package webinspect

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

func harHash(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func harOutput(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > 48<<10 {
		return errors.New("HAR projection exceeds 48 KiB; reduce limit")
	}
	return nil
}
func harPage(o HAROptions, total int) (int, int, error) {
	if o.Limit == 0 {
		o.Limit = 50
	}
	if o.Offset < 0 || o.Offset > total || o.Limit < 1 || o.Limit > 200 {
		return 0, 0, errors.New("invalid HAR view offset/limit")
	}
	return o.Offset, min(total, o.Offset+o.Limit), nil
}

type HAREndpoint struct {
	Method            string         `json:"method"`
	URL               string         `json:"url"`
	Count             int            `json:"count"`
	Statuses          map[int]int    `json:"statuses"`
	MimeTypes         map[string]int `json:"mime_types"`
	QueryKeys         []string       `json:"query_keys"`
	Ordinals          []int          `json:"producer_ordinals"`
	OrdinalsTruncated bool           `json:"ordinals_truncated"`
}
type HARAPIReport struct {
	Path               string        `json:"path"`
	SHA256             string        `json:"sha256"`
	TotalEntries       int           `json:"total_entries"`
	TotalEndpoints     int           `json:"total_endpoints"`
	Offset             int           `json:"offset"`
	Endpoints          []HAREndpoint `json:"endpoints"`
	NextOffset         *int          `json:"next_offset,omitempty"`
	CoverageComplete   bool          `json:"coverage_complete"`
	EvidenceAuthority  string        `json:"evidence_authority"`
	ExecutionPerformed bool          `json:"execution_performed"`
	NetworkInteraction bool          `json:"network_interaction"`
	Limitations        []string      `json:"limitations"`
}

func endpointGroups(entries []HAREntry) []HAREndpoint {
	groups := map[string]*HAREndpoint{}
	queries := map[string]map[string]bool{}
	for _, e := range entries {
		key := e.Method + " " + e.URL
		g := groups[key]
		if g == nil {
			g = &HAREndpoint{Method: e.Method, URL: e.URL, Statuses: map[int]int{}, MimeTypes: map[string]int{}, QueryKeys: []string{}, Ordinals: []int{}}
			groups[key] = g
			queries[key] = map[string]bool{}
		}
		g.Count++
		g.Statuses[e.Status]++
		g.MimeTypes[e.MimeType]++
		for _, q := range e.QueryKeys {
			queries[key][q] = true
		}
		if len(g.Ordinals) < 32 {
			g.Ordinals = append(g.Ordinals, e.Ordinal)
		} else {
			g.OrdinalsTruncated = true
		}
	}
	keys := []string{}
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := []HAREndpoint{}
	for _, k := range keys {
		g := groups[k]
		for q := range queries[k] {
			g.QueryKeys = append(g.QueryKeys, q)
		}
		sort.Strings(g.QueryKeys)
		out = append(out, *g)
	}
	return out
}
func InspectHARAPI(path string, o HAROptions) (HARAPIReport, error) {
	b, abs, hash, err := readBoundedFile(path, MaxHARBytes)
	if err != nil {
		return HARAPIReport{}, err
	}
	if err = checkExpectedSHA256(hash, o.ExpectedSHA256); err != nil {
		return HARAPIReport{}, err
	}
	_, entries, err := parseHAR(b)
	if err != nil {
		return HARAPIReport{}, err
	}
	endpoints := endpointGroups(entries)
	start, end, err := harPage(o, len(endpoints))
	if err != nil {
		return HARAPIReport{}, err
	}
	r := HARAPIReport{Path: abs, SHA256: hash, TotalEntries: len(entries), TotalEndpoints: len(endpoints), Offset: start, Endpoints: endpoints[start:end], CoverageComplete: start == 0 && end == len(endpoints), EvidenceAuthority: "historical-producer-record", Limitations: []string{"groups exact visible method/URL declarations; no path template, schema or live API inference", "query values/headers/cookies/bodies excluded; path and query names remain visible", "group count covers the whole admitted capture; ordinal samples capped at 32 per endpoint"}}
	if end < len(endpoints) {
		r.NextOffset = &end
	}
	return r, harOutput(r)
}

type HARBodyOptions struct {
	EntryOrdinal   int    `json:"entry_ordinal"`
	Side           string `json:"side"`
	Offset         int    `json:"offset"`
	Limit          int    `json:"limit"`
	ExpectedSHA256 string `json:"expected_sha256,omitempty"`
}
type HARBodyReport struct {
	Path               string   `json:"path"`
	SHA256             string   `json:"sha256"`
	EntryOrdinal       int      `json:"entry_ordinal"`
	JSONPointer        string   `json:"json_pointer"`
	Side               string   `json:"side"`
	Available          bool     `json:"available"`
	UnavailableReason  string   `json:"unavailable_reason,omitempty"`
	ProducerEncoding   string   `json:"producer_encoding"`
	ContentSHA256      string   `json:"content_sha256,omitempty"`
	TotalBytes         int      `json:"total_bytes"`
	Offset             int      `json:"offset"`
	ReadBytes          int      `json:"read_bytes"`
	DataBase64         string   `json:"data_base64"`
	NextOffset         *int     `json:"next_offset,omitempty"`
	CoverageComplete   bool     `json:"coverage_complete"`
	EvidenceAuthority  string   `json:"evidence_authority"`
	NetworkInteraction bool     `json:"network_interaction"`
	ExecutionPerformed bool     `json:"execution_performed"`
	Limitations        []string `json:"limitations"`
}

func ReadHARBody(path string, o HARBodyOptions) (HARBodyReport, error) {
	if o.Limit == 0 {
		o.Limit = 8192
	}
	if o.Offset < 0 || o.EntryOrdinal < 0 || o.Limit < 1 || o.Limit > 16384 || o.Side != "request" && o.Side != "response" {
		return HARBodyReport{}, errors.New("valid entry_ordinal/side/offset and limit 1..16384 required")
	}
	b, abs, hash, err := readBoundedFile(path, MaxHARBytes)
	if err != nil {
		return HARBodyReport{}, err
	}
	if err = checkExpectedSHA256(hash, o.ExpectedSHA256); err != nil {
		return HARBodyReport{}, err
	}
	raw, _, err := parseHAR(b)
	if err != nil {
		return HARBodyReport{}, err
	}
	if o.EntryOrdinal >= len(raw) {
		return HARBodyReport{}, errors.New("entry ordinal outside capture")
	}
	var e struct {
		Request struct {
			PostData *struct {
				Text *string `json:"text"`
			} `json:"postData"`
		} `json:"request"`
		Response struct {
			Content *struct {
				Text     *string `json:"text"`
				Encoding string  `json:"encoding"`
			} `json:"content"`
		} `json:"response"`
	}
	if err = json.Unmarshal(raw[o.EntryOrdinal], &e); err != nil {
		return HARBodyReport{}, errors.New("selected body fields have invalid types")
	}
	r := HARBodyReport{Path: abs, SHA256: hash, EntryOrdinal: o.EntryOrdinal, Side: o.Side, Offset: o.Offset, EvidenceAuthority: "historical-decoded-producer-field", Limitations: []string{"selected body only; other entries' body fields are not decoded or validated", "UTF-8 JSON text/base64-decoded producer bytes are not proven original wire bytes", "explicit body reading may expose captured application data; no network or replay"}}
	var text *string
	encoding := "text"
	if o.Side == "request" {
		r.JSONPointer = fmt.Sprintf("/log/entries/%d/request/postData/text", o.EntryOrdinal)
		if e.Request.PostData != nil {
			text = e.Request.PostData.Text
		}
	} else {
		r.JSONPointer = fmt.Sprintf("/log/entries/%d/response/content/text", o.EntryOrdinal)
		if e.Response.Content != nil {
			text = e.Response.Content.Text
			if e.Response.Content.Encoding != "" {
				encoding = e.Response.Content.Encoding
			}
		}
	}
	r.ProducerEncoding = encoding
	if text == nil {
		if o.Offset != 0 {
			return r, errors.New("unavailable body requires zero offset")
		}
		r.UnavailableReason = "producer did not retain a text body"
		return r, nil
	}
	if len(*text) > 12<<20 {
		return r, errors.New("retained body exceeds byte limit")
	}
	content := []byte(*text)
	if encoding == "base64" {
		content, err = base64.StdEncoding.Strict().DecodeString(*text)
		if err != nil {
			return r, errors.New("malformed retained base64 body")
		}
	} else if encoding != "text" {
		return r, errors.New("unsupported producer body encoding")
	}
	if len(content) > 8<<20 || o.Offset > len(content) {
		return r, errors.New("body size/offset exceeds admitted range")
	}
	end := min(len(content), o.Offset+o.Limit)
	r.Available = true
	r.ContentSHA256 = harHash(content)
	r.TotalBytes = len(content)
	r.ReadBytes = end - o.Offset
	r.DataBase64 = base64.StdEncoding.EncodeToString(content[o.Offset:end])
	r.CoverageComplete = o.Offset == 0 && end == len(content)
	if end < len(content) {
		r.NextOffset = &end
	}
	return r, harOutput(r)
}

type HARCompareOptions struct {
	HAROptions
	ExpectedLeftSHA256  string `json:"expected_left_sha256,omitempty"`
	ExpectedRightSHA256 string `json:"expected_right_sha256,omitempty"`
}
type HAREndpointChange struct {
	Key         string       `json:"key"`
	Before      *HAREndpoint `json:"before,omitempty"`
	After       *HAREndpoint `json:"after,omitempty"`
	SameSummary bool         `json:"same_summary"`
}
type HARComparison struct {
	LeftSHA256         string              `json:"left_sha256"`
	RightSHA256        string              `json:"right_sha256"`
	ComparisonSHA256   string              `json:"comparison_sha256"`
	TotalItems         int                 `json:"total_items"`
	Offset             int                 `json:"offset"`
	Items              []HAREndpointChange `json:"items"`
	NextOffset         *int                `json:"next_offset,omitempty"`
	CoverageComplete   bool                `json:"coverage_complete"`
	EvidenceAuthority  string              `json:"evidence_authority"`
	NetworkInteraction bool                `json:"network_interaction"`
	ExecutionPerformed bool                `json:"execution_performed"`
	Limitations        []string            `json:"limitations"`
}

func CompareHAR(left, right string, o HARCompareOptions) (HARComparison, error) {
	a, lp, lh, err := readBoundedFile(left, MaxHARBytes)
	if err != nil {
		return HARComparison{}, err
	}
	if err = checkExpectedSHA256(lh, o.ExpectedLeftSHA256); err != nil {
		return HARComparison{}, err
	}
	b, rp, rh, err := readBoundedFile(right, MaxHARBytes)
	if err != nil {
		return HARComparison{}, err
	}
	if err = checkExpectedSHA256(rh, o.ExpectedRightSHA256); err != nil {
		return HARComparison{}, err
	}
	_, ae, err := parseHAR(a)
	if err != nil {
		return HARComparison{}, err
	}
	_, be, err := parseHAR(b)
	if err != nil {
		return HARComparison{}, err
	}
	body, _ := json.Marshal([]string{"rr-har-api-comparison-v1", lp, rp, lh, rh})
	hash := harHash(body)
	if err = checkExpectedSHA256(hash, o.ExpectedSHA256); err != nil {
		return HARComparison{}, err
	}
	before, after := map[string]HAREndpoint{}, map[string]HAREndpoint{}
	keys := map[string]bool{}
	for _, e := range endpointGroups(ae) {
		key := e.Method + " " + e.URL
		before[key] = e
		keys[key] = true
	}
	for _, e := range endpointGroups(be) {
		key := e.Method + " " + e.URL
		after[key] = e
		keys[key] = true
	}
	sorted := []string{}
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	items := []HAREndpointChange{}
	for _, k := range sorted {
		item := HAREndpointChange{Key: k}
		if e, ok := before[k]; ok {
			item.Before = &e
		}
		if e, ok := after[k]; ok {
			item.After = &e
		}
		if item.Before != nil && item.After != nil {
			a := *item.Before
			b := *item.After
			a.Ordinals = nil
			b.Ordinals = nil
			a.OrdinalsTruncated = false
			b.OrdinalsTruncated = false
			ab, _ := json.Marshal(a)
			bb, _ := json.Marshal(b)
			item.SameSummary = string(ab) == string(bb)
		}
		items = append(items, item)
	}
	start, end, err := harPage(o.HAROptions, len(items))
	if err != nil {
		return HARComparison{}, err
	}
	r := HARComparison{LeftSHA256: lh, RightSHA256: rh, ComparisonSHA256: hash, TotalItems: len(items), Offset: start, Items: items[start:end], CoverageComplete: start == 0 && end == len(items), EvidenceAuthority: "historical-capture-summary-comparison", Limitations: []string{"groups exact redacted method/URL; query values, headers, cookies and bodies are not compared", "same_summary compares counts/status/MIME/query names only, excluding producer ordinals", "comparison does not establish identical requests, behavior, chronology or live server/browser identity"}}
	if end < len(items) {
		r.NextOffset = &end
	}
	return r, harOutput(r)
}
