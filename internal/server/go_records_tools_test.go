package server

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"reverseresearch/internal/appinspect"
	"reverseresearch/internal/appinspect/testfixture"
)

func TestGoSemanticMCPPreservesPartialBytesAndExactDecodedField(t *testing.T) {
	runtime, session, _, _ := workflowTestSession(t)
	body := []byte("path\tapp\nmod\tmodule\t(devel)\nbuild\tbinary=\"\\xff\"\nfuture\tvalue\n")
	p := filepath.Join(t.TempDir(), "module.elf")
	if err := os.WriteFile(p, testfixture.GoMetadataELF(testfixture.GoInlineRecord([]byte("go-fixture"), testfixture.GoFramedModule(body))), 0600); err != nil {
		t.Fatal(err)
	}
	var info appinspect.GoBinaryReport
	workflowCall(t, session, "app_go_inspect", map[string]any{"path": p}, &info)
	if !info.ModuleSemanticsAvailable || info.GrammarComplete || info.TextSummaryComplete || info.UnparsedRecords != 1 || info.TotalSettingsObserved != 1 || len(info.Settings) != 0 {
		t.Fatalf("MCP normalized partial metadata: %+v", info)
	}
	var records appinspect.GoMetadataReport
	workflowCall(t, session, "app_go_metadata_read", map[string]any{"path": p, "part": "records", "limit": 2}, &records)
	if records.TotalRecords != 4 || len(records.Records) != 2 || records.NextOffset == nil {
		t.Fatalf("MCP record pagination unavailable: %+v", records)
	}
	var value appinspect.GoMetadataReport
	workflowCall(t, session, "app_go_metadata_read", map[string]any{"path": p, "part": "record-field", "record_index": 2, "field": "value"}, &value)
	if value.DataBase64 != "/w==" || value.DecodedField == nil || value.DecodedField.UTF8 || value.DecodedField.Bytes != 1 || value.ExecutionPerformed {
		t.Fatalf("MCP escaped bytes lost: %+v", value)
	}
	for _, args := range []map[string]any{
		{"path": p, "part": "records", "limit": 201}, {"path": p, "part": "records", "record_index": 0},
		{"path": p, "part": "record-field", "record_index": 2, "field": "unknown"}, {"path": p, "part": "record-field", "field": "value"},
		{"path": p, "part": "records", "offset": 2}, {"path": p, "part": "records", "expected_sha256": strings.Repeat("0", 64)},
		{"path": p, "part": "record-field", "record_index": 3, "field": "value"},
	} {
		r, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "app_go_metadata_read", Arguments: args})
		if err == nil && (r == nil || !r.IsError) {
			t.Fatalf("invalid semantic request accepted: %+v", args)
		}
	}
	for _, s := range runtime.statuses() {
		if s.State != "idle" {
			t.Fatalf("Go observation started backend: %+v", s)
		}
	}
}
