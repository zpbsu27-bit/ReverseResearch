package server

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"reverseresearch/internal/toolindex"
	"reverseresearch/internal/webinspect"
)

func TestExistingWASMToolWABTProfile(t *testing.T) {
	root, sourceRoot := isolatedServerRoot(t)
	tools, err := toolindex.DiscoverWABT(sourceRoot)
	if err != nil {
		t.Fatal(err)
	}
	var bin string
	for _, tool := range tools {
		if tool.Name == "wasm-validate" && tool.Available {
			bin = filepath.Dir(tool.Path)
		}
	}
	if bin == "" {
		t.Skip("WABT is not supplied")
	}
	t.Setenv("REVERSERESEARCH_TOOLS", bin)
	runtime, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	go func() { _ = runtime.Run(ctx, serverTransport) }()
	client := mcp.NewClient(&mcp.Implementation{Name: "wabt-profile-test", Version: "1"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	path := filepath.Join(t.TempDir(), "module.wasm")
	if err := os.WriteFile(path, []byte{0, 97, 115, 109, 1, 0, 0, 0}, 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "web_wasm_inspect", Arguments: map[string]any{"path": path, "use_wabt": true, "view": "wat", "limit": 4}})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("WABT MCP: %+v %v", result, err)
	}
	var report webinspect.WASMReport
	decodeStructured(t, result.StructuredContent, &report)
	if !report.WABT.Validated || report.WABT.Output != "(mod" || report.WABT.OutputComplete || !report.WABT.TemporaryCopyDisposed {
		t.Fatalf("MCP=%+v", report.WABT)
	}
	result, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "web_wasm_inspect", Arguments: map[string]any{"path": path, "use_wabt": true, "view": "wat", "expected_sha256": strings.Repeat("0", 64)}})
	if err == nil && (result == nil || !result.IsError) {
		t.Fatal("MCP accepted stale WASM")
	}
	bad := []byte{0, 97, 115, 109, 1, 0, 0, 0, 1, 4, 1, 0x60, 0, 0, 3, 2, 1, 0, 10, 4, 1, 2, 0, 1}
	if err := os.WriteFile(path, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	result, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "web_wasm_inspect", Arguments: map[string]any{"path": path, "use_wabt": true, "view": "wat"}})
	if err != nil || result == nil || !result.IsError {
		t.Fatalf("MCP lost invalid-module failure: %+v %v", result, err)
	}
	decodeStructured(t, result.StructuredContent, &report)
	if report.WABT.Validated || report.WABT.Status != "invalid-module" || len(report.WABT.Commands) != 4 || report.WABT.Commands[3].Diagnostics == "" {
		t.Fatalf("partial provenance=%+v", report.WABT)
	}
	for _, status := range runtime.statuses() {
		if status.State != "idle" {
			t.Fatalf("WASM started backend: %+v", status)
		}
	}
}
