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

func TestEVMMCPPublishesInterfaceThroughExistingToolAndAdmissionOwner(t *testing.T) {
	runtime, session, _, _ := workflowTestSession(t)
	path := filepath.Join(t.TempDir(), "code.raw")
	if err := os.WriteFile(path, testfixture.EVMInterfaceProbe(), 0600); err != nil {
		t.Fatal(err)
	}
	var r appinspect.EVMReport
	workflowCall(t, session, "app_evm_inspect", map[string]any{"path": path, "encoding": "raw", "view": "interface"}, &r)
	if r.Interface == nil || r.Interface.TotalFunctions != 1 || r.Interface.FunctionPage.Functions[0].Selector != "0xfae7ab82" || r.EVMInstructionReport != nil || r.ExecutionPerformed || resourceWeight("app_evm_inspect") != globalResourceCapacity {
		t.Fatalf("MCP did not preserve inference/admission: %+v", r)
	}
	var p appinspect.EVMReport
	workflowCall(t, session, "app_evm_inspect", map[string]any{"path": path, "encoding": "raw", "view": "interface-bytes", "offset": 1, "limit": 13, "expected_sha256": r.SHA256, "expected_result_sha256": r.Interface.ResultSHA256}, &p)
	if p.Result == nil || p.Result.Bytes != 13 || p.Result.Offset != 1 || p.Result.NextOffset == nil || *p.Result.NextOffset != 14 || p.Result.SHA256 != r.Interface.ResultSHA256 {
		t.Fatalf("MCP byte page lost: %+v", p)
	}
	for _, a := range []map[string]any{
		{"path": path, "encoding": "raw", "view": "interface", "limit": 201},
		{"path": path, "encoding": "raw", "view": "interface-bytes", "offset": 1},
		{"path": path, "encoding": "raw", "view": "interface", "expected_result_sha256": strings.Repeat("0", 64)},
		{"path": path, "encoding": "raw", "view": "interface", "expected_sha256": strings.Repeat("0", 64)},
		{"path": path, "encoding": "raw", "view": "interface", "view_extra": "unsupported"},
	} {
		result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "app_evm_inspect", Arguments: a})
		if err == nil && (result == nil || !result.IsError) {
			t.Fatalf("MCP accepted invalid EVM request: %+v", a)
		}
	}
	for _, s := range runtime.statuses() {
		if s.State != "idle" {
			t.Fatalf("offline EVM analysis started backend: %+v", s)
		}
	}
}
