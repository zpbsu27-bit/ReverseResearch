package main

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestModuleResultMetaPreservesOriginalMCPResult(t *testing.T) {
	for _, structured := range []any{nil, map[string]any{
		"_meta": map[string]any{"owner": "payload"}, "value": 7,
	}} {
		result := &mcp.CallToolResult{
			Meta: mcp.Meta{"owner": "provider", "pagination": map[string]any{"returned": 1, "total": 3}},
			Content: []mcp.Content{&mcp.TextContent{
				Text: "original text", Meta: mcp.Meta{"owner": "content"},
				Annotations: &mcp.Annotations{Audience: []mcp.Role{"user"}, Priority: 0.75, LastModified: "2026-10-15T00:00:00Z"},
			}},
			StructuredContent: structured,
		}
		before, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		value, err := moduleResultValue(result)
		if err != nil {
			t.Fatal(err)
		}
		original, ok := value.(*mcp.CallToolResult)
		if !ok || original != result {
			t.Fatalf("metadata result was flattened or replaced: %T", value)
		}
		after, err := json.Marshal(value)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatalf("MCP fields changed: before=%s after=%s err=%v", before, after, err)
		}
	}
	result := &mcp.CallToolResult{Meta: mcp.Meta{"unavailable": nil}}
	if got, err := moduleResultValue(result); err != nil || got != result {
		t.Fatalf("opaque null metadata was dropped: %v %v", got, err)
	}
}

func TestModuleResultEmptyMetaKeepsLegacyFlatOutput(t *testing.T) {
	payload := map[string]any{"_meta": map[string]any{"owner": "payload-only"}, "value": 7}
	for _, test := range []struct {
		name   string
		result *mcp.CallToolResult
		want   any
	}{
		{"default", &mcp.CallToolResult{}, map[string]any{"text": ""}},
		{"nil-meta-text", &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "first"}, &mcp.TextContent{Text: "second"}}}, map[string]any{"text": "first\nsecond"}},
		{"empty-meta-text", &mcp.CallToolResult{Meta: mcp.Meta{}, Content: []mcp.Content{&mcp.TextContent{Text: "text"}}}, map[string]any{"text": "text"}},
		{"nil-meta-structured", &mcp.CallToolResult{StructuredContent: payload}, payload},
		{"empty-meta-structured", &mcp.CallToolResult{Meta: mcp.Meta{}, StructuredContent: payload}, payload},
		{"structured-array", &mcp.CallToolResult{StructuredContent: []string{"a", "b"}}, []string{"a", "b"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := moduleResultValue(test.result)
			if err != nil || !reflect.DeepEqual(got, test.want) {
				t.Fatalf("legacy value=%#v want=%#v err=%v", got, test.want, err)
			}
			var written bytes.Buffer
			if err := writeModuleResult(&written, test.result); err != nil {
				t.Fatal(err)
			}
			expected, err := json.Marshal(test.want)
			if err != nil {
				t.Fatal(err)
			}
			var gotJSON, expectedJSON any
			if err := json.Unmarshal(written.Bytes(), &gotJSON); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(expected, &expectedJSON); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(gotJSON, expectedJSON) {
				t.Fatalf("legacy JSON changed: %s", written.Bytes())
			}
		})
	}
}

func TestModuleResultMetaDoesNotBypassFailures(t *testing.T) {
	for _, test := range []struct {
		name    string
		result  *mcp.CallToolResult
		message string
	}{
		{"nil", nil, "module returned no result"},
		{"error-with-meta", &mcp.CallToolResult{Meta: mcp.Meta{"owner": "provider"}, IsError: true,
			Content:           []mcp.Content{&mcp.TextContent{Text: "first error"}, &mcp.TextContent{Text: "second error"}},
			StructuredContent: map[string]any{"success": true}}, "module tool error: first error\nsecond error"},
		{"error-without-meta", &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "failure"}}}, "module tool error: failure"},
	} {
		t.Run(test.name, func(t *testing.T) {
			value, err := moduleResultValue(test.result)
			if value != nil || err == nil || err.Error() != test.message {
				t.Fatalf("failure changed: value=%#v err=%v", value, err)
			}
			var written bytes.Buffer
			if err := writeModuleResult(&written, test.result); err == nil || err.Error() != test.message || written.Len() != 0 {
				t.Fatalf("failure emitted JSON: %q err=%v", written.Bytes(), err)
			}
		})
	}
}

func TestWriteModuleResultMetaUsesStandardMCPJSON(t *testing.T) {
	result := &mcp.CallToolResult{
		Meta: mcp.Meta{"owner": "provider", "pagination": map[string]any{"returned": 1, "total": 3}},
		Content: []mcp.Content{&mcp.TextContent{
			Text: "first <value>", Meta: mcp.Meta{"owner": "content"},
			Annotations: &mcp.Annotations{Audience: []mcp.Role{"user"}, Priority: 0.75, LastModified: "2026-10-15T00:00:00Z"},
		}, &mcp.TextContent{Text: "second"}},
		StructuredContent: map[string]any{"_meta": map[string]any{"owner": "payload"}, "value": 7},
	}
	var written bytes.Buffer
	if err := writeModuleResult(&written, result); err != nil {
		t.Fatal(err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(written.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if len(document) != 3 || document["_meta"] == nil || document["content"] == nil || document["structuredContent"] == nil {
		t.Fatalf("output is not a standard MCP result: %s", written.Bytes())
	}
	var decoded struct {
		Meta    map[string]any `json:"_meta"`
		Content []struct {
			Type        string            `json:"type"`
			Text        string            `json:"text"`
			Meta        map[string]string `json:"_meta"`
			Annotations struct {
				Audience     []string `json:"audience"`
				Priority     float64  `json:"priority"`
				LastModified string   `json:"lastModified"`
			} `json:"annotations"`
		} `json:"content"`
		StructuredContent struct {
			Meta  map[string]string `json:"_meta"`
			Value int               `json:"value"`
		} `json:"structuredContent"`
	}
	if err := json.Unmarshal(written.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Meta["owner"] != "provider" || decoded.StructuredContent.Meta["owner"] != "payload" || decoded.StructuredContent.Value != 7 {
		t.Fatalf("transport and payload metadata collided: %s", written.Bytes())
	}
	pagination, ok := decoded.Meta["pagination"].(map[string]any)
	if !ok || pagination["returned"] != float64(1) || pagination["total"] != float64(3) || len(pagination) != 2 {
		t.Fatalf("pagination was changed or guessed: %#v", decoded.Meta)
	}
	if len(decoded.Content) != 2 || decoded.Content[0].Type != "text" || decoded.Content[0].Text != "first <value>" || decoded.Content[1].Text != "second" || decoded.Content[0].Meta["owner"] != "content" {
		t.Fatalf("content was flattened: %s", written.Bytes())
	}
	annotations := decoded.Content[0].Annotations
	if !reflect.DeepEqual(annotations.Audience, []string{"user"}) || annotations.Priority != 0.75 || annotations.LastModified != "2026-10-15T00:00:00Z" {
		t.Fatalf("content annotations were lost: %+v", annotations)
	}
	if strings.Contains(written.String(), `"truncated"`) {
		t.Fatalf("CLI invented truncation status: %s", written.Bytes())
	}
}
