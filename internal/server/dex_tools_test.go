package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"reverseresearch/internal/appinspect"
	"reverseresearch/internal/appinspect/testfixture"
)

func TestDEXMCPPreservesWideLiteralAcrossStructuredTransport(t *testing.T) {
	_, session, _, _ := workflowTestSession(t)
	p := filepath.Join(t.TempDir(), "wide.dex")
	code := []uint16{0x0018, 0x0123, 0, 0, 0x8000, 0x7012, 0x000f}
	if err := os.WriteFile(p, testfixture.DEXWithInstructions(code, 2, 0), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "app_dex_inspect", Arguments: map[string]any{"path": p, "view": "instructions", "method_index": 2}})
	if err != nil || r == nil || r.IsError {
		t.Fatalf("wide MCP request failed: %+v %v", r, err)
	}
	raw, err := json.Marshal(r.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var report appinspect.DEXReport
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Instructions) != 3 || report.Instructions[0].Literal == nil || *report.Instructions[0].Literal != -9223372036854775517 {
		t.Fatalf("wide literal rounded through structured transport: %s", raw)
	}
	var wire struct {
		Instructions []struct {
			Literal string `json:"literal"`
		} `json:"instructions"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil || wire.Instructions[0].Literal != "-9223372036854775517" {
		t.Fatalf("wide JSON must carry exact decimal text: %s %v", raw, err)
	}
}

func TestDEXMCPMatchesCanonicalMetadataAndRejectsInvalidRequests(t *testing.T) {
	runtime, session, _, _ := workflowTestSession(t)
	p := filepath.Join(t.TempDir(), "classes.dex")
	if err := os.WriteFile(p, testfixture.DEX(), 0600); err != nil {
		t.Fatal(err)
	}
	var actual appinspect.DEXReport
	workflowCall(t, session, "app_dex_inspect", map[string]any{"path": p, "view": "methods"}, &actual)
	want, err := appinspect.InspectDEX(p, appinspect.DEXOptions{View: "methods"})
	if err != nil {
		t.Fatal(err)
	}
	if actual.ContentSHA256 != want.ContentSHA256 || actual.TotalMethods != 4 || actual.DefinedMethods != 3 || actual.Methods[3].Defined || actual.ExecutionPerformed || actual.NetworkInteraction {
		t.Fatalf("MCP metadata ownership drift: %+v", actual)
	}
	for _, view := range []string{"instructions", "cfg", "edges"} {
		var code appinspect.DEXReport
		workflowCall(t, session, "app_dex_inspect", map[string]any{"path": p, "view": view, "method_index": 2}, &code)
		if !code.CodeAvailable || code.Method == nil || code.Method.Index != 2 || code.Method.Descriptor != "()I" || code.TotalInstructions != 2 || code.TotalBlocks != 1 || code.ExecutionPerformed {
			t.Fatalf("MCP selected code identity lost: %+v", code)
		}
	}
	for _, a := range []map[string]any{
		{"path": p, "unexpected": true},
		{"path": p, "view": "methods", "string_index": 1},
		{"path": p, "view": "string-bytes"},
		{"path": p, "view": "classes", "offset": 1},
		{"path": p, "expected_sha256": strings.Repeat("0", 64)},
		{"path": p, "limit": 201},
		{"path": p, "view": "instructions"},
		{"path": p, "view": "instructions", "method_index": 3},
		{"path": p, "view": "methods", "method_index": 2},
		{"path": p, "view": "cfg", "method_index": 2, "offset": 1},
	} {
		v, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "app_dex_inspect", Arguments: a})
		if err == nil && (v == nil || !v.IsError) {
			t.Fatalf("invalid DEX request accepted: %+v", a)
		}
	}
	for _, s := range runtime.statuses() {
		if s.State != "idle" {
			t.Fatalf("offline DEX started backend: %+v", s)
		}
	}
}
