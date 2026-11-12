package server

import (
	"reflect"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestStructuredResultPreservesSmallJSONMirror(t *testing.T) {
	value := map[string]any{"ok": true, "count": 3}
	result, err := structuredResult(value)
	if err != nil {
		t.Fatal(err)
	}
	if result.StructuredContent == nil {
		t.Fatal("structured content was dropped")
	}
	if len(result.Content) != 1 {
		t.Fatalf("content len=%d want=1", len(result.Content))
	}
	textContent, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("content type=%T", result.Content[0])
	}
	if textContent.Text != `{"count":3,"ok":true}` {
		t.Fatalf("text mirror=%q", textContent.Text)
	}
}

func TestStructuredResultOmitsLargeTextMirrorBeforeFullCopy(t *testing.T) {
	payload := strings.Repeat("x", maxStructuredTextMirrorBytes)
	value := map[string]any{"payload": payload}
	result, err := structuredResult(value)
	if err != nil {
		t.Fatal(err)
	}
	if result.StructuredContent == nil {
		t.Fatal("structured content was dropped")
	}
	textContent, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("content type=%T", result.Content[0])
	}
	if strings.Contains(textContent.Text, payload[:1024]) {
		t.Fatal("large payload was mirrored into text content")
	}
	if !strings.Contains(textContent.Text, "text_mirror_limit_bytes") {
		t.Fatalf("unexpected omission notice: %q", textContent.Text)
	}
	if structuredMirrorWithinLimit(reflect.ValueOf(value), maxStructuredTextMirrorBytes, 0) {
		t.Fatal("preflight accepted a result that should be omitted")
	}
}
