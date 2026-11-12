package webinspect

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"unicode/utf8"
)

func reaFixture(name string) string {
	return filepath.Join("..", "..", "testdata", "rea-web-"+name)
}

func writeREAInput(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestREAReadSourceMapUTF8CoverageAndAvailability(t *testing.T) {
	path := reaFixture("source.map")
	whole, err := ReadSourceMap(path, SourceMapReadOptions{})
	if err != nil || !whole.CoverageComplete || !whole.ContentAvailable || whole.SourceCount != 3 {
		t.Fatalf("whole=%+v err=%v", whole, err)
	}
	var text strings.Builder
	for offset := 0; ; {
		page, err := ReadSourceMap(path, SourceMapReadOptions{Offset: offset, Limit: 4, ExpectedSHA256: whole.SHA256})
		if err != nil || !utf8.ValidString(page.Text) || page.ReadBytes > 4 || !page.Truncated || page.CoverageComplete {
			t.Fatalf("page=%+v err=%v", page, err)
		}
		text.WriteString(page.Text)
		if page.NextOffset == nil {
			break
		}
		if *page.NextOffset <= offset {
			t.Fatal("UTF-8 page did not advance")
		}
		offset = *page.NextOffset
	}
	if text.String() != whole.Text {
		t.Fatalf("paged text=%q whole=%q", text.String(), whole.Text)
	}
	empty, err := ReadSourceMap(path, SourceMapReadOptions{SourceIndex: 1})
	if err != nil || !empty.ContentAvailable || !empty.CoverageComplete || empty.ContentSHA256 == "" || empty.TotalBytes != 0 {
		t.Fatalf("empty=%+v err=%v", empty, err)
	}
	missing, err := ReadSourceMap(path, SourceMapReadOptions{SourceIndex: 2})
	if err != nil || missing.ContentAvailable || missing.CoverageComplete || missing.ContentSHA256 != "" || missing.UnavailableReason == "" {
		t.Fatalf("missing=%+v err=%v", missing, err)
	}
	for _, options := range []SourceMapReadOptions{{SourceIndex: -1}, {SourceIndex: 3}, {Offset: 3}, {Offset: 999}, {Limit: 3}, {Limit: MaxSourceReadBytes + 1}, {ExpectedSHA256: strings.Repeat("0", 64)}} {
		if _, err := ReadSourceMap(path, options); err == nil {
			t.Fatalf("invalid options accepted: %+v", options)
		}
	}
}

func TestREASourceMapRejectsAmbiguousAndUnsupportedArtifacts(t *testing.T) {
	for _, body := range []string{
		`{"version":3,"version":3,"sources":[],"mappings":""}`,
		`{"version":3,"\u0076ersion":3,"sources":[],"mappings":""}`,
		`{"version":3,"sections":[]}`,
		`{"version":4,"sources":[],"mappings":""}`,
		`{"version":3,"sources":["a"],"mappings":"","sourcesContent":[]}`,
		`{"version":3,"sources":["a"],"mappings":"","sourcesContent":[42]}`,
		`{"version":3,"sources":[null],"mappings":""}`,
		`{"version":3,"sources":null,"mappings":""}`,
		`{"version":3,"sources":[],"mappings":"!"}`,
		`{"version":3,"sources":[],"mappings":""} {}`,
	} {
		if _, err := ReadSourceMap(writeREAInput(t, "bad.map", body), SourceMapReadOptions{}); err == nil {
			t.Fatalf("malformed map accepted: %s", body)
		}
	}
	path := writeREAInput(t, "changed.map", `{"version":3,"sources":["a"],"mappings":"","sourcesContent":["before"]}`)
	first, err := ReadSourceMap(path, SourceMapReadOptions{Limit: 4})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"version":3,"sources":["a"],"mappings":"","sourcesContent":["after"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSourceMap(path, SourceMapReadOptions{ExpectedSHA256: first.SHA256}); err == nil {
		t.Fatal("changed source map accepted with old digest")
	}
}

func TestREAInlineSourceMapsAndLongBundleLines(t *testing.T) {
	body, err := os.ReadFile(reaFixture("source.map"))
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{
		"data:application/json;charset=utf-8;base64," + base64.StdEncoding.EncodeToString(body),
		"data:application/json," + url.PathEscape(string(body)),
	} {
		path := writeREAInput(t, "app.js", strings.Repeat("x", (2<<20)+1)+"\n//# sourceMappingURL="+ref+"\n")
		report, err := AnalyzeSource(path)
		if err != nil || report.SourceMap == nil || !report.SourceMap.Inline || report.SourceMap.EmbeddedCount != 2 || report.SourceMap.SourcesCount != 3 || !report.SourceMappingURLTruncated {
			t.Fatalf("inline report=%+v err=%v", report, err)
		}
		encoded, _ := json.Marshal(report)
		if len(encoded) > 2048 {
			t.Fatalf("inline map leaked into result: %d bytes", len(encoded))
		}
	}
	if _, err := AnalyzeSource(writeREAInput(t, "bad.js", "//# sourceMappingURL=data:application/json;base64,!!!!")); err == nil {
		t.Fatal("invalid inline encoding accepted")
	}
	remote, err := AnalyzeSource(writeREAInput(t, "remote.js", "//# sourceMappingURL=//example.test/app.map"))
	if err != nil || remote.SourceMap != nil {
		t.Fatalf("remote=%+v err=%v", remote, err)
	}
}

func TestREASourceInventoryIsBounded(t *testing.T) {
	sources := make([]string, 65)
	for i := range sources {
		sources[i] = "source.ts"
	}
	body, _ := json.Marshal(map[string]any{"version": 3, "sources": sources, "mappings": ""})
	mapPath := writeREAInput(t, "app.map", string(body))
	jsPath := filepath.Join(filepath.Dir(mapPath), "app.js")
	if err := os.WriteFile(jsPath, []byte("//# sourceMappingURL=app.map?build=1"), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := AnalyzeSource(jsPath)
	if err != nil || report.SourceMap == nil || report.SourceMap.SourcesCount != 65 || len(report.SourceMap.Sources) != 64 || !report.SourceMap.SourcesTruncated {
		t.Fatalf("report=%+v err=%v", report, err)
	}
}

func TestREAHARPreservesOrdinalsExcludesSensitiveFieldsAndDoesNotFetch(t *testing.T) {
	path := reaFixture("capture.har")
	page, err := InspectHAR(path, HAROptions{Limit: 1})
	if err != nil || page.TotalEntries != 2 || page.ReturnedEntries != 1 || page.OmittedEntries != 1 || !page.Truncated || page.CoverageComplete || page.NextOffset == nil || *page.NextOffset != 1 {
		t.Fatalf("page=%+v err=%v", page, err)
	}
	if page.Entries[0].URL != "https://example.test/feature" || page.Entries[0].JSONPointer != "/log/entries/0" || page.Entries[0].QueryKeys[0] != "token" {
		t.Fatalf("entry=%+v", page.Entries[0])
	}
	encoded, _ := json.Marshal(page)
	if strings.Contains(string(encoded), "SYNTHETIC_") || page.ExecutionPerformed || page.NetworkInteraction {
		t.Fatalf("capture fields escaped projection: %s", encoded)
	}
	second, err := InspectHAR(path, HAROptions{Offset: 1, ExpectedSHA256: page.SHA256})
	if err != nil || second.Entries[0].Ordinal != 1 || second.CoverageComplete || second.NextOffset != nil {
		t.Fatalf("second=%+v err=%v", second, err)
	}
	var fetched atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fetched.Add(1) }))
	defer server.Close()
	capture := `{"log":{"version":"1.2","entries":[{"request":{"method":"GET","url":"` + server.URL + `/capture"},"response":{"status":200}}]}}`
	if _, err := InspectHAR(writeREAInput(t, "capture.har", capture), HAROptions{}); err != nil {
		t.Fatal(err)
	}
	if fetched.Load() != 0 {
		t.Fatal("historical URL was fetched")
	}
}

func TestREAHARValidatesOutsideThePageAndInputBounds(t *testing.T) {
	good := `{"request":{"method":"GET","url":"https://example.test/a"},"response":{"status":200}}`
	for _, bad := range []string{
		`{"request":{"method":"GET","url":"https://example.test/b"},"response":{"status":"bad"}}`,
		`{"request":{"method":"GET","url":"https://example.test/b"},"response":{"status":200},"ignored":{"key":1,"key":2}}`,
		`{"request":{"method":"GET","url":"file:///secret"},"response":{"status":200}}`,
		`null`,
	} {
		body := `{"log":{"version":"1.2","entries":[` + good + `,` + bad + `]}}`
		if _, err := InspectHAR(writeREAInput(t, "bad.har", body), HAROptions{Limit: 1}); err == nil {
			t.Fatal("malformed record outside selected page accepted")
		}
	}
	for _, options := range []HAROptions{{Offset: -1}, {Offset: 3}, {Limit: -1}, {Limit: 201}, {ExpectedSHA256: strings.Repeat("0", 64)}} {
		if _, err := InspectHAR(reaFixture("capture.har"), options); err == nil {
			t.Fatalf("invalid options accepted: %+v", options)
		}
	}
	empty, err := InspectHAR(writeREAInput(t, "empty.har", `{"log":{"version":"1.2","entries":[]}}`), HAROptions{})
	if err != nil || !empty.CoverageComplete || empty.Truncated || empty.NextOffset != nil || len(empty.Entries) != 0 {
		t.Fatalf("empty=%+v err=%v", empty, err)
	}
	file, err := os.Create(filepath.Join(t.TempDir(), "large.har"))
	if err != nil {
		t.Fatal(err)
	}
	path := file.Name()
	if err := file.Truncate(MaxHARBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectHAR(path, HAROptions{}); err == nil {
		t.Fatal("oversized HAR accepted")
	}
}

func TestREAHARPageByteBudget(t *testing.T) {
	entries := make([]any, 80)
	for i := range entries {
		entries[i] = map[string]any{"request": map[string]any{"method": "GET", "url": "https://example.test/" + strings.Repeat("a", 1000)}, "response": map[string]any{"status": 200}}
	}
	body, _ := json.Marshal(map[string]any{"log": map[string]any{"version": "1.2", "entries": entries}})
	report, err := InspectHAR(writeREAInput(t, "budget.har", string(body)), HAROptions{Limit: 200})
	if err != nil || report.NextOffset == nil || *report.NextOffset != report.ReturnedEntries || report.ReturnedEntries <= 0 || report.ReturnedEntries >= 80 {
		t.Fatalf("budget report=%+v err=%v", report, err)
	}
	encoded, _ := json.Marshal(report)
	if len(encoded) > 64<<10 {
		t.Fatalf("report exceeded output budget: %d", len(encoded))
	}
}
