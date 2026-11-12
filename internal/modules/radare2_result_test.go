package modules

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"reverseresearch/internal/backend"
)

// Retained H3 responses: DOC65 analyze, DOC94 decompile, and the speed-family
// disassemble failure. These fixtures are evidence of provider text, not of
// analysis completion or execution of the target.
const r2RealTimeout = "Analysis stopped after 10 seconds at level 0.\nFound 2276 functions so far.\n\n<log>\n[INFO] Analyze all flags starting with sym. and entry0 (aa)\n[INFO] Timeout interruption after 0s\n[WARN] Stopped because of timeout\n\n</log>\n"
const r2RealMissingIn = "<log>\n[ERROR] Cannot find function in 0x010ab610\n\n</log>\n"
const r2RealMissingAt = "<log>\n[ERROR] Cannot find function at 0x0043f258\n\n</log>\n"
const r2Completed = "Analysis completed with level 0.\nFound 1026 functions."

func r2TextResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}
}

func r2Status(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	meta, ok := result.Meta[r2ResultMetaKey].(map[string]any)
	if !ok {
		t.Fatalf("missing observation metadata: %#v", result.Meta)
	}
	if meta["completionVerified"] != false {
		t.Fatalf("completion must remain unverified: %#v", meta)
	}
	status, ok := meta["status"].(string)
	if !ok {
		t.Fatalf("invalid status: %#v", meta)
	}
	return status
}

func TestR2ResultProfilesAndSharedIssueClassification(t *testing.T) {
	tests := []struct {
		name, tool, text, status string
		issue                    bool
	}{
		{"real timeout", "analyze", r2RealTimeout, "timeout_observed", true},
		{"completed", "analyze", r2Completed, "provider_reported_completion", false},
		{"completed with ordinary log", "analyze", r2Completed + "\n\n<log>\n[INFO] Recovering variables (afva@@F)\n\n</log>\n", "provider_reported_completion", false},
		{"completed contradicted by timeout", "analyze", r2Completed + "\n\n<log>\n[INFO] Timeout interruption after 0s\n\n</log>\n", "timeout_observed", true},
		{"completed contradicted by stop log", "analyze", r2Completed + "\n\n<log>\n[WARN] Stopped because of timeout\n\n</log>\n", "timeout_observed", true},
		{"cached same level", "analyze", "File was already analyzed at level 0. Found 2276 functions. Re-analysis skipped.", "cached_unverified", false},
		{"cached higher level", "analyze", "File was already analyzed at level 3 (>= requested level 0). Found 2276 functions. Re-analysis skipped.", "cached_unverified", false},
		{"unknown", "analyze", "Different provider response", "unknown", false},
		{"no timeout log", "analyze", "Analysis stopped after 10 seconds at level 0.\nFound 2276 functions so far.", "unknown", false},
		{"trailing unrecognized text", "analyze", r2Completed + "\nThis is another response.", "unknown", false},
		{"prefixed header", "analyze", "// " + r2Completed, "unknown", false},
		{"header in source", "analyze", "void f() {\n/* " + r2RealTimeout + " */\n}", "unknown", false},
		{"diagnostic word in log", "analyze", r2Completed + "\n\n<log>\n[INFO] Configuration timeout is disabled\n\n</log>\n", "provider_reported_completion", false},
		{"quoted diagnostic in log", "analyze", r2Completed + "\n\n<log>\n[INFO] Example: [WARN] Stopped because of timeout\n\n</log>\n", "provider_reported_completion", false},
		{"malformed log", "analyze", r2Completed + "\n\n<log>\nint timeout = 0;\n</log>\n", "unknown", false},
		{"nested log", "analyze", r2Completed + "\n\n<log>\n<log>\n[WARN] Stopped because of timeout\n</log>\n</log>", "unknown", false},
		{"missing function in", "decompile_function", r2RealMissingIn, "function_not_found", true},
		{"missing function at", "disassemble_function", r2RealMissingAt, "function_not_found", true},
		{"normal decompilation", "decompile_function", "int f(void) { return 1; }", "unknown", false},
		{"normal disassembly", "disassemble_function", "0x0043f258 push ebp\n0x0043f259 mov ebp, esp", "unknown", false},
		{"source contains diagnostic", "decompile_function", "void f() { puts(\"Cannot find function at 0x0043f258\"); int timeout = 0; }", "unknown", false},
		{"source contains log", "decompile_function", "void f() {\n/*\n" + r2RealMissingIn + "*/\n}", "unknown", false},
		{"source with trailing diagnostic", "decompile_function", "int f(void) { return 1; }\n" + r2RealMissingIn, "unknown", false},
		{"bare diagnostic", "decompile_function", "[ERROR] Cannot find function in 0x010ab610", "unknown", false},
		{"wrong address shape", "decompile_function", "<log>\n[ERROR] Cannot find function in not-an-address\n</log>", "unknown", false},
		{"additional diagnostic", "decompile_function", "<log>\n[WARN] Other warning\n[ERROR] Cannot find function in 0x010ab610\n</log>", "unknown", false},
		{"quoted missing function", "decompile_function", "<log>\n[ERROR] Example: Cannot find function in 0x010ab610\n</log>", "unknown", false},
		{"analysis log under function tool", "decompile_function", r2RealTimeout, "unknown", false},
		{"function log under analyze tool", "analyze", r2RealMissingAt, "unknown", false},
		{"CRLF mirror", "analyze", strings.ReplaceAll(r2RealTimeout, "\n", "\r\n"), "timeout_observed", true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			original := r2TextResult(test.text)
			before, err := json.Marshal(original)
			if err != nil {
				t.Fatal(err)
			}
			got, err := withR2ResultMetadata("r2", test.tool, original)
			if err != nil {
				t.Fatal(err)
			}
			if test.tool != "analyze" && test.status != "function_not_found" {
				if got != original || len(got.Meta) != 0 {
					t.Fatal("ordinary function result changed its original success shape")
				}
			} else if status := r2Status(t, got); status != test.status {
				t.Fatalf("status=%q want %q", status, test.status)
			}
			if issue := R2ToolResultIssue("r2", test.tool, original); (issue != nil) != test.issue {
				t.Fatalf("issue=%v want error=%v", issue, test.issue)
			}
			if issue := R2ToolResultIssue("r2", test.tool, got); (issue != nil) != test.issue {
				t.Fatalf("annotated issue=%v want error=%v", issue, test.issue)
			}
			after, err := json.Marshal(original)
			if err != nil || string(after) != string(before) {
				t.Fatalf("original result changed: %s -> %s (%v)", before, after, err)
			}
			if got.IsError {
				t.Fatal("interpretation changed original IsError")
			}
		})
	}
}

func TestR2ResultStructuredAndTextEnvelopeProfiles(t *testing.T) {
	envelope, err := json.Marshal(map[string]any{"content": r2RealMissingIn})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		result *mcp.CallToolResult
		status string
	}{
		{"structured only", &mcp.CallToolResult{StructuredContent: map[string]any{"content": r2RealMissingIn}}, "function_not_found"},
		{"string map", &mcp.CallToolResult{StructuredContent: map[string]string{"content": r2RealMissingIn}}, "function_not_found"},
		{"raw structured", &mcp.CallToolResult{StructuredContent: json.RawMessage(envelope)}, "function_not_found"},
		{"JSON text", r2TextResult(string(envelope)), "function_not_found"},
		{"both mirrors", &mcp.CallToolResult{StructuredContent: map[string]any{"content": r2RealMissingIn}, Content: r2TextResult(string(envelope)).Content}, "function_not_found"},
		{"both direct and structured", &mcp.CallToolResult{StructuredContent: map[string]any{"content": r2RealMissingIn}, Content: r2TextResult(r2RealMissingIn).Content}, "function_not_found"},
		{"conflicting mirrors", &mcp.CallToolResult{StructuredContent: map[string]any{"content": r2RealMissingIn}, Content: r2TextResult("int f(void) { return 1; }").Content}, "unknown"},
		{"arbitrary structured field", &mcp.CallToolResult{StructuredContent: map[string]any{"comment": r2RealMissingIn}}, "unknown"},
		{"additional structured field", &mcp.CallToolResult{StructuredContent: map[string]any{"content": r2RealMissingIn, "comment": "code"}}, "unknown"},
		{"additional JSON field", r2TextResult("{\"content\":" + string(envelope[len("{\"content\":"):len(envelope)-1]) + ",\"comment\":\"code\"}"), "unknown"},
		{"duplicate JSON keys", r2TextResult("{\"content\":\"code\",\"content\":" + string(envelope[len("{\"content\":"):len(envelope)-1]) + "}"), "unknown"},
		{"trailing JSON", r2TextResult(string(envelope) + "{}"), "unknown"},
		{"nested structured", &mcp.CallToolResult{StructuredContent: map[string]any{"content": map[string]any{"content": r2RealMissingIn}}}, "unknown"},
		{"nontext content", &mcp.CallToolResult{StructuredContent: map[string]any{"content": r2RealMissingIn}, Content: []mcp.Content{&mcp.ImageContent{MIMEType: "image/png", Data: []byte{1}}}}, "unknown"},
		{"oversized", r2TextResult(strings.Repeat(" ", 64*1024) + r2RealMissingIn), "unknown"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got, err := withR2ResultMetadata("r2", "decompile_function", test.result)
			if err != nil {
				t.Fatal(err)
			}
			if test.status != "function_not_found" {
				if got != test.result || len(got.Meta) != 0 {
					t.Fatal("unknown function response changed its original success shape")
				}
			} else if status := r2Status(t, got); status != test.status {
				t.Fatalf("status=%q want %q", status, test.status)
			}
			if issue := R2ToolResultIssue("r2", "decompile_function", test.result); (issue != nil) != (test.status == "function_not_found") {
				t.Fatalf("issue=%v status=%s", issue, test.status)
			}
		})
	}
}

func TestR2ResultPreservesMetadataContentAnnotationsAndStructuredValue(t *testing.T) {
	original := r2TextResult(r2RealMissingIn)
	content := original.Content[0].(*mcp.TextContent)
	content.Annotations = &mcp.Annotations{Audience: []mcp.Role{"assistant"}, Priority: 0.5}
	content.Meta = mcp.Meta{"content-owner": "provider"}
	original.StructuredContent = map[string]any{"content": r2RealMissingIn}
	original.Meta = mcp.Meta{"provider": map[string]any{"owned": true}, "reverseresearch/r2-pagination": map[string]any{"nextCursor": "20"}}
	before, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	got, err := withR2ResultMetadata("r2", "decompile_function", original)
	if err != nil {
		t.Fatal(err)
	}
	if got == original || got.Content[0] != original.Content[0] || !reflect.DeepEqual(got.StructuredContent, original.StructuredContent) {
		t.Fatal("result clone lost or replaced original fields")
	}
	if len(got.Meta) != len(original.Meta)+1 {
		t.Fatalf("metadata lost: %#v", got.Meta)
	}
	for key, value := range original.Meta {
		if !reflect.DeepEqual(got.Meta[key], value) {
			t.Fatalf("metadata %s changed", key)
		}
	}
	got.Meta["clone-only"] = true
	if _, exists := original.Meta["clone-only"]; exists {
		t.Fatal("result metadata map was not cloned")
	}
	after, err := json.Marshal(original)
	if err != nil || string(after) != string(before) {
		t.Fatalf("original changed: %v", err)
	}
}

func TestR2ResultLeavesOtherRoutesAndOriginalErrorsUntouched(t *testing.T) {
	for _, route := range []struct{ module, tool string }{
		{"ghidra", "analyze"}, {"r2", "disassemble"}, {"r2", "list_functions"}, {"R2", "analyze"}, {"r2", "Analyze"},
	} {
		original := r2TextResult(r2RealTimeout)
		got, err := withR2ResultMetadata(route.module, route.tool, original)
		if err != nil || got != original || len(got.Meta) != 0 || R2ToolResultIssue(route.module, route.tool, original) != nil {
			t.Fatalf("unmatched route changed: %+v result=%#v error=%v", route, got, err)
		}
	}
	for _, original := range []*mcp.CallToolResult{nil, {IsError: true, Content: r2TextResult(r2RealTimeout).Content}} {
		got, err := withR2ResultMetadata("r2", "analyze", original)
		if err != nil || got != original || R2ToolResultIssue("r2", "analyze", original) != nil {
			t.Fatalf("nil/original IsError handling changed: %#v %v", got, err)
		}
	}
}

func TestR2ResultNamespaceCollisionPreservesOriginalAndIssueIgnoresForgedMeta(t *testing.T) {
	original := r2TextResult(r2RealMissingIn)
	original.Meta = mcp.Meta{r2ResultMetaKey: map[string]any{"status": "function_not_found", "completionVerified": true}}
	before, _ := json.Marshal(original)
	got, err := withR2ResultMetadata("r2", "decompile_function", original)
	if err == nil || !strings.Contains(err.Error(), r2ResultMetaKey) || got != original {
		t.Fatalf("collision result=%#v error=%v", got, err)
	}
	after, _ := json.Marshal(original)
	if string(before) != string(after) {
		t.Fatal("namespace collision mutated the result")
	}
	success := r2TextResult("int f(void) { return 1; }")
	success.Meta = original.Meta
	unchanged, err := withR2ResultMetadata("r2", "decompile_function", success)
	if err != nil || unchanged != success {
		t.Fatalf("ordinary success metadata namespace was inspected or changed: %v", err)
	}
	if R2ToolResultIssue("r2", "decompile_function", success) != nil {
		t.Fatal("helper trusted forged metadata instead of the raw response")
	}
}

func TestR2ResultCommonCallPathUsesOneObservationWithoutRetry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	calls := 0
	server := mcp.NewServer(&mcp.Implementation{Name: "r2-result-test", Version: "1"}, nil)
	server.AddTool(&mcp.Tool{Name: "analyze", InputSchema: map[string]any{"type": "object"}},
		func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			calls++
			return r2TextResult(r2RealTimeout), nil
		})
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer serverSession.Close()
	target := backend.NewLazy("radare2", func(startCtx context.Context) (*mcp.ClientSession, func() error, error) {
		client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1"}, nil)
		session, err := client.Connect(startCtx, clientTransport, nil)
		return session, nil, err
	})
	defer target.Close()
	got, err := callModuleBackend(ctx, target, "r2", "analyze", map[string]any{"level": 0})
	if err != nil || got == nil || got.IsError || r2Status(t, got) != "timeout_observed" {
		t.Fatalf("shared result=%#v error=%v", got, err)
	}
	if R2ToolResultIssue("r2", "analyze", got) == nil || calls != 1 {
		t.Fatalf("observation/retry mismatch: calls=%d", calls)
	}
}

func TestR2ResultCommonCallPathPreservesSuccessfulFunctionResults(t *testing.T) {
	tests := []struct {
		name, tool, body string
		meta             mcp.Meta
	}{
		{"decompile no metadata", "decompile_function", "int f(void) { return 1; }", nil},
		{"disassemble no metadata", "disassemble_function", "0x0043f258 push ebp\n0x0043f259 mov ebp, esp", nil},
		{"decompile provider metadata", "decompile_function", "int f(void) { return 1; }", mcp.Meta{"provider": "retained"}},
		{"disassemble pagination metadata", "disassemble_function", "0x0043f258 push ebp", mcp.Meta{"reverseresearch/r2-pagination": map[string]any{"nextCursor": "20"}}},
		{"success retains existing observation namespace", "decompile_function", "int f(void) { return 1; }", mcp.Meta{r2ResultMetaKey: map[string]any{"external": true}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			original := r2TextResult(test.body)
			original.Meta = test.meta
			original.StructuredContent = map[string]any{"content": test.body}
			content := original.Content[0].(*mcp.TextContent)
			content.Annotations = &mcp.Annotations{Priority: 0.5}
			before, err := json.Marshal(original)
			if err != nil {
				t.Fatal(err)
			}
			unchanged, err := withR2ResultMetadata("r2", test.tool, original)
			after, marshalErr := json.Marshal(original)
			if err != nil || marshalErr != nil || unchanged != original || string(after) != string(before) {
				t.Fatalf("ordinary success changed before transport: result=%s want=%s error=%v marshal=%v", after, before, err, marshalErr)
			}
			calls := 0
			server := mcp.NewServer(&mcp.Implementation{Name: "r2-success-test", Version: "1"}, nil)
			server.AddTool(&mcp.Tool{Name: test.tool, InputSchema: map[string]any{"type": "object"}},
				func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
					calls++
					return original, nil
				})
			clientTransport, serverTransport := mcp.NewInMemoryTransports()
			serverSession, err := server.Connect(ctx, serverTransport, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer serverSession.Close()
			target := backend.NewLazy("radare2", func(startCtx context.Context) (*mcp.ClientSession, func() error, error) {
				client := mcp.NewClient(&mcp.Implementation{Name: "success-client", Version: "1"}, nil)
				session, err := client.Connect(startCtx, clientTransport, nil)
				return session, nil, err
			})
			defer target.Close()
			got, err := callModuleBackend(ctx, target, "r2", test.tool, map[string]any{"address": "0x0043f258"})
			if err != nil || got == nil {
				t.Fatalf("common call result=%#v error=%v", got, err)
			}
			// SDK servers may add protocol metadata after the handler returns.
			// Compare against that actual wire baseline, not the pre-SDK object.
			expected, err := json.Marshal(original)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := json.Marshal(got)
			if err != nil || string(actual) != string(expected) || calls != 1 {
				t.Fatalf("success changed or retried: calls=%d result=%s want=%s error=%v", calls, actual, expected, err)
			}
			unchanged, err = withR2ResultMetadata("r2", test.tool, got)
			if err != nil || unchanged != got || R2ToolResultIssue("r2", test.tool, got) != nil {
				t.Fatalf("ordinary success was cloned, rejected, or reinterpreted: %v", err)
			}
		})
	}
}
