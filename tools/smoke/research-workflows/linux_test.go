package main

import (
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestEngineContentRequiresActualSemanticEvidence(t *testing.T) {
	for _, result := range []*mcp.CallToolResult{
		nil,
		{IsError: true},
		{},
		{Content: []mcp.Content{&mcp.TextContent{Text: "null"}}},
		{Content: []mcp.Content{&mcp.TextContent{Text: `{"success":false}`}}},
		{StructuredContent: map[string]any{"error": "decompiler unavailable"}},
		{Content: []mcp.Content{&mcp.TextContent{Text: "{}"}, &mcp.TextContent{Text: "{}"}}},
	} {
		_, err := engineValue(result)
		if err == nil {
			t.Fatalf("missing/failed engine evidence was accepted: %+v", result)
		}
	}
	value, err := engineValue(&mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: `{"file_type":"ELF","bitness":64}`}}})
	if err != nil || value.(map[string]any)["file_type"] != "ELF" {
		t.Fatalf("text-only backend result was lost: %v %v", value, err)
	}
}
