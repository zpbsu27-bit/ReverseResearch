package server

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"reverseresearch/internal/webinspect"
)

func TestREAWebMCPUsesOfflineCoreAndKeepsBackendsIdle(t *testing.T) {
	root, sourceRoot := isolatedServerRoot(t)
	runtime, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	go func() { _ = runtime.Run(ctx, serverTransport) }()
	client := mcp.NewClient(&mcp.Implementation{Name: "rea-web-test", Version: "1"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	mapPath := filepath.Join(sourceRoot, "testdata", "rea-web-source.map")
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "web_source_map_read", Arguments: map[string]any{"path": mapPath, "source_index": 0, "limit": 4}})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("source-map MCP result=%+v err=%v", result, err)
	}
	var source webinspect.SourceMapReadReport
	decodeStructured(t, result.StructuredContent, &source)
	if source.Text != "ab" || !source.Truncated || source.CoverageComplete || source.NextOffset == nil || *source.NextOffset != 2 {
		t.Fatalf("MCP lost UTF-8/coverage contract: %+v", source)
	}
	harPath := filepath.Join(sourceRoot, "testdata", "rea-web-capture.har")
	result, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "web_har_inspect", Arguments: map[string]any{"path": harPath, "limit": 1}})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("HAR MCP result=%+v err=%v", result, err)
	}
	var har webinspect.HARReport
	decodeStructured(t, result.StructuredContent, &har)
	if har.TotalEntries != 2 || len(har.Entries) != 1 || har.Entries[0].Ordinal != 0 || har.CoverageComplete || har.ExecutionPerformed || har.NetworkInteraction {
		t.Fatalf("MCP lost historical capture contract: %+v", har)
	}
	result, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "web_har_inspect", Arguments: map[string]any{"path": harPath, "expected_sha256": strings.Repeat("0", 64)}})
	if err == nil && (result == nil || !result.IsError) {
		t.Fatal("MCP accepted stale capture digest")
	}
	ssePath := filepath.Join(sourceRoot, "testdata", "protocol-stream.sse")
	result, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "web_sse_inspect", Arguments: map[string]any{"path": ssePath, "limit": 1, "data_preview_bytes": 256}})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("SSE MCP result=%+v err=%v", result, err)
	}
	var sse webinspect.SSEReport
	decodeStructured(t, result.StructuredContent, &sse)
	if sse.TotalEvents != 4 || sse.ReturnedEvents != 1 || sse.Events[0].DataPreview == nil || sse.Events[0].DataLines != 2 || !sse.PendingDataAtEOF || sse.CoverageComplete || sse.ApplicationCompletion != "unverified" || sse.ExecutionPerformed || sse.NetworkInteraction {
		t.Fatalf("MCP lost SSE framing/gap contract: %+v", sse)
	}
	result, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "web_sse_inspect", Arguments: map[string]any{"path": ssePath, "expected_sha256": strings.Repeat("0", 64)}})
	if err == nil && (result == nil || !result.IsError) {
		t.Fatal("MCP accepted stale SSE digest")
	}
	for _, status := range runtime.statuses() {
		if status.State != "idle" {
			t.Fatalf("offline inspection started backend %s: %s", status.Name, status.State)
		}
	}
}
