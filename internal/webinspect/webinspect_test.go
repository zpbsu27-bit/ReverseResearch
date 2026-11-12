package webinspect

import (
	"context"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"reverseresearch/internal/toolindex"
)

func TestPrepareProfileUsesProjectOwnedIsolation(t *testing.T) {
	root := t.TempDir()
	browser := filepath.Join(root, "chrome.exe")
	if err := os.WriteFile(browser, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	index := toolindex.Index{Tools: []toolindex.Tool{{Name: "chrome", Available: true, Path: browser, Source: "test"}}}
	plan, err := PrepareProfile(root, "case-01", "chrome", index)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.DailyProfileSafe || !strings.Contains(plan.ProfilePath, filepath.Join("state", "web-profiles", "case-01")) {
		t.Fatalf("unexpected profile plan: %#v", plan)
	}
	for _, arg := range plan.Arguments {
		if strings.Contains(strings.ToLower(arg), "user data") && !strings.Contains(arg, plan.ProfilePath) {
			t.Fatalf("profile argument escaped isolated path: %s", arg)
		}
	}
}

func TestInspectCDPIsLoopbackReadOnly(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/json/version", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"Browser":"Chrome/123","Protocol-Version":"1.3"}`))
	})
	mux.HandleFunc("/json/list", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"id":"p1","type":"page","title":"fixture","url":"https://example.test/"}]`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	report, err := InspectCDP(context.Background(), server.URL, 0)
	if err != nil {
		t.Fatal(err)
	}
	if report.Version.ProtocolVersion != "1.3" || len(report.Targets) != 1 {
		t.Fatalf("unexpected report: %#v", report)
	}
	if _, err := InspectCDP(context.Background(), "https://example.com:9222", 0); err == nil {
		t.Fatal("non-loopback CDP endpoint accepted")
	}
}

func TestAnalyzeSourceMap(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "app.js.map"), []byte(`{"version":3,"file":"app.js","sources":["src/a.ts"],"names":["x"],"mappings":"AAAA","sourcesContent":["const x=1;"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	js := "console.log(1);\n//# sourceMappingURL=app.js.map\n"
	path := filepath.Join(root, "app.js")
	if err := os.WriteFile(path, []byte(js), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := AnalyzeSource(path)
	if err != nil {
		t.Fatal(err)
	}
	if report.SourceMap == nil || report.SourceMap.Version != 3 || report.SourceMap.EmbeddedCount != 1 {
		t.Fatalf("unexpected source report: %#v", report)
	}
}

func TestInspectWASMImportsExports(t *testing.T) {
	root := t.TempDir()
	body := []byte{0x00, 0x61, 0x73, 0x6d, 1, 0, 0, 0}
	importPayload := []byte{1, 3, 'e', 'n', 'v', 3, 'l', 'o', 'g', 0, 0}
	body = append(body, 2, byte(len(importPayload)))
	body = append(body, importPayload...)
	exportPayload := []byte{1, 3, 'r', 'u', 'n', 0, 0}
	body = append(body, 7, byte(len(exportPayload)))
	body = append(body, exportPayload...)
	path := filepath.Join(root, "m.wasm")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := InspectWASM(path)
	if err != nil {
		t.Fatal(err)
	}
	if report.Version != 1 || len(report.Imports) != 1 || report.Imports[0].Name != "log" || len(report.Exports) != 1 || report.Exports[0].Name != "run" {
		t.Fatalf("unexpected wasm report: %#v", report)
	}
}

func TestInspectWASMRejectsTruncatedSection(t *testing.T) {
	root := t.TempDir()
	body := make([]byte, 8)
	copy(body[:4], []byte{0x00, 0x61, 0x73, 0x6d})
	binary.LittleEndian.PutUint32(body[4:], 1)
	body = append(body, 7, 10, 1)
	path := filepath.Join(root, "bad.wasm")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectWASM(path); err == nil {
		t.Fatal("truncated wasm accepted")
	}
}
