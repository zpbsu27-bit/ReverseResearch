package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const moduleTimeoutText = "Analysis stopped after 10 seconds at level 0.\nFound 2276 functions so far.\n\n<log>\n[INFO] Timeout interruption after 0s\n[WARN] Stopped because of timeout\n\n</log>\n"

const moduleFunctionMissingLog = "<log>\n[ERROR] Cannot find function in 0x010ab610\n\n</log>\n"
const moduleFunctionMissingJSON = `{"content":"<log>\n[ERROR] Cannot find function in 0x010ab610\n\n</log>\n"}`

type moduleScriptReply struct {
	result *mcp.CallToolResult
	err    error
}

type moduleScriptCall struct {
	module, tool string
	arguments    any
}

type moduleScriptCaller struct {
	replies []moduleScriptReply
	calls   []moduleScriptCall
}

func (s *moduleScriptCaller) Call(_ context.Context, module, tool string, arguments any) (*mcp.CallToolResult, error) {
	index := len(s.calls)
	s.calls = append(s.calls, moduleScriptCall{module, tool, arguments})
	if index >= len(s.replies) {
		return nil, errors.New("unexpected module call after script ended")
	}
	return s.replies[index].result, s.replies[index].err
}

func moduleTextResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}
}

func moduleFunctionMissingResult() *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Meta: mcp.Meta{"owner": "provider", "reverseresearch/r2-pagination": map[string]any{"nextCursor": "20"}},
		Content: []mcp.Content{&mcp.TextContent{
			Text: moduleFunctionMissingJSON, Meta: mcp.Meta{"owner": "content"},
			Annotations: &mcp.Annotations{Audience: []mcp.Role{"user"}, Priority: 0.75},
		}},
		StructuredContent: map[string]any{"content": moduleFunctionMissingLog},
	}
}

func moduleJSONValue(t *testing.T, value any) any {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var decoded any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestModuleCallRejectsR2SemanticFailures(t *testing.T) {
	for _, test := range []struct {
		name, tool string
		result     *mcp.CallToolResult
	}{
		{"analysis-timeout", "analyze", moduleTextResult(moduleTimeoutText)},
		{"decompile-function-missing", "decompile_function", moduleFunctionMissingResult()},
		{"disassemble-function-missing", "disassemble_function", moduleTextResult("<log>\n[ERROR] Cannot find function at 0x0043f258\n\n</log>\n")},
	} {
		t.Run(test.name, func(t *testing.T) {
			caller := &moduleScriptCaller{replies: []moduleScriptReply{{result: test.result}}}
			before := moduleJSONValue(t, test.result)
			var stdout, stderr bytes.Buffer
			err := runModuleCallCLI(context.Background(), caller, "r2", []string{test.tool}, &stdout, &stderr)
			if err == nil || stdout.Len() != 0 || len(caller.calls) != 1 {
				t.Fatalf("semantic failure err=%v stdout=%q calls=%d", err, stdout.String(), len(caller.calls))
			}
			if !reflect.DeepEqual(before, moduleJSONValue(t, test.result)) {
				t.Fatal("CLI changed the provider's result or error flag")
			}
		})
	}
}

func TestModuleCallPreservesOriginalFailures(t *testing.T) {
	transportErr := errors.New("transport failed")
	providerError := moduleFunctionMissingResult()
	providerError.IsError = true
	for _, test := range []struct {
		name  string
		reply moduleScriptReply
		want  string
	}{
		{"nil", moduleScriptReply{}, "module returned no result"},
		{"is-error", moduleScriptReply{result: providerError}, "module tool error: " + moduleFunctionMissingJSON},
		{"transport-with-result", moduleScriptReply{result: providerError, err: transportErr}, "transport failed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			caller := &moduleScriptCaller{replies: []moduleScriptReply{test.reply}}
			var stdout, stderr bytes.Buffer
			err := runModuleCallCLI(context.Background(), caller, "r2", []string{"decompile_function"}, &stdout, &stderr)
			if err == nil || err.Error() != test.want || stdout.Len() != 0 || len(caller.calls) != 1 {
				t.Fatalf("original failure err=%v stdout=%q calls=%d", err, stdout.String(), len(caller.calls))
			}
			if test.reply.err != nil && !errors.Is(err, test.reply.err) {
				t.Fatalf("original Go error was lost: %v", err)
			}
		})
	}
}

func TestModuleCallPreservesSuccessfulResultFormats(t *testing.T) {
	withMeta := &mcp.CallToolResult{
		Meta: mcp.Meta{"owner": "provider"},
		Content: []mcp.Content{&mcp.TextContent{
			Text: "original", Meta: mcp.Meta{"owner": "content"},
			Annotations: &mcp.Annotations{Audience: []mcp.Role{"user"}, Priority: 0.5},
		}},
		StructuredContent: map[string]any{"_meta": map[string]any{"owner": "payload"}, "count": 7},
	}
	for _, test := range []struct {
		name, module, tool string
		result             *mcp.CallToolResult
		want               any
	}{
		{"flat-text", "r2", "disassemble", moduleTextResult("mov eax, ebx"), map[string]any{"text": "mov eax, ebx"}},
		{"flat-structured", "r2", "show_info", &mcp.CallToolResult{StructuredContent: []string{"a", "b"}}, []string{"a", "b"}},
		{"full-meta", "r2", "show_info", withMeta, withMeta},
		{"other-module", "ghidra", "decompile_function", moduleFunctionMissingResult(), moduleFunctionMissingResult()},
		{"other-tool", "r2", "show_info", moduleFunctionMissingResult(), moduleFunctionMissingResult()},
		{"source-contains-error-words", "r2", "decompile_function", moduleTextResult("int f(void) { puts(\"Cannot find function\"); }"), map[string]any{"text": "int f(void) { puts(\"Cannot find function\"); }"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			caller := &moduleScriptCaller{replies: []moduleScriptReply{{result: test.result}}}
			var stdout, stderr bytes.Buffer
			err := runModuleCallCLI(context.Background(), caller, test.module, []string{test.tool, "--json", `{"address":"0x401000"}`}, &stdout, &stderr)
			if err != nil || len(caller.calls) != 1 {
				t.Fatalf("success err=%v calls=%d", err, len(caller.calls))
			}
			var got any
			if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, moduleJSONValue(t, test.want)) {
				t.Fatalf("successful format changed: %s", stdout.Bytes())
			}
			if !reflect.DeepEqual(caller.calls[0].arguments, map[string]any{"address": "0x401000"}) {
				t.Fatalf("arguments changed: %#v", caller.calls[0].arguments)
			}
		})
	}
}

func TestModuleBatchPreservesFailurePrefix(t *testing.T) {
	transportErr := errors.New("transport failed after response")
	providerError := moduleFunctionMissingResult()
	providerError.IsError = true
	for _, test := range []struct {
		name, tool string
		reply      moduleScriptReply
		want       string
	}{
		{"semantic-function", "decompile_function", moduleScriptReply{result: moduleFunctionMissingResult()}, ""},
		{"semantic-timeout", "analyze", moduleScriptReply{result: moduleTextResult(moduleTimeoutText)}, ""},
		{"provider-is-error", "decompile_function", moduleScriptReply{result: providerError}, "module tool error: " + moduleFunctionMissingJSON},
		{"transport-with-result", "show_info", moduleScriptReply{result: moduleFunctionMissingResult(), err: transportErr}, transportErr.Error()},
		{"transport-without-result", "show_info", moduleScriptReply{err: transportErr}, transportErr.Error()},
		{"nil-result", "show_info", moduleScriptReply{}, "module returned no result"},
	} {
		t.Run(test.name, func(t *testing.T) {
			prefix := moduleFunctionMissingResult() // show_info treats this as opaque provider data.
			prefixBefore := moduleJSONValue(t, prefix)
			failedBefore := moduleJSONValue(t, test.reply.result)
			caller := &moduleScriptCaller{replies: []moduleScriptReply{{result: prefix}, test.reply}}
			steps := []moduleBatchStep{{Module: "r2", Tool: "show_info"}, {Module: "r2", Tool: test.tool}, {Module: "r2", Tool: "close_file"}}
			body, err := json.Marshal(steps)
			if err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			err = runModuleBatchCLI(context.Background(), caller, []string{"--json", string(body)}, &stdout, &stderr)
			if err == nil || !strings.Contains(err.Error(), "batch step 1 r2."+test.tool+": ") || len(caller.calls) != 2 {
				t.Fatalf("batch err=%v calls=%d stdout=%s", err, len(caller.calls), stdout.Bytes())
			}
			if test.reply.err != nil && !errors.Is(err, test.reply.err) {
				t.Fatalf("original Go error was lost: %v", err)
			}
			var report struct {
				Status  string `json:"status"`
				Results []struct {
					Index  int    `json:"index"`
					Module string `json:"module"`
					Tool   string `json:"tool"`
					Result any    `json:"result"`
				} `json:"results"`
				Failure struct {
					Index  int             `json:"index"`
					Module string          `json:"module"`
					Tool   string          `json:"tool"`
					Error  string          `json:"error"`
					Result json.RawMessage `json:"result"`
				} `json:"failure"`
				Total      int `json:"total"`
				Unexecuted int `json:"unexecuted"`
			}
			if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
				t.Fatal(err)
			}
			if report.Status != "partial" || report.Total != 3 || report.Unexecuted != 1 || len(report.Results) != 1 ||
				report.Failure.Index != 1 || report.Failure.Module != "r2" || report.Failure.Tool != test.tool || report.Failure.Error == "" {
				t.Fatalf("partial report is incomplete: %s", stdout.Bytes())
			}
			if test.want != "" && report.Failure.Error != test.want {
				t.Fatalf("failure message=%q want=%q", report.Failure.Error, test.want)
			}
			first := report.Results[0]
			if first.Index != 0 || first.Module != "r2" || first.Tool != "show_info" || !reflect.DeepEqual(first.Result, prefixBefore) {
				t.Fatalf("successful prefix changed: %s", stdout.Bytes())
			}
			if test.reply.result == nil {
				if len(report.Failure.Result) != 0 {
					t.Fatalf("invented failure result: %s", report.Failure.Result)
				}
			} else {
				var raw any
				if err := json.Unmarshal(report.Failure.Result, &raw); err != nil || !reflect.DeepEqual(raw, failedBefore) {
					t.Fatalf("failed raw MCP result changed: %s err=%v", report.Failure.Result, err)
				}
			}
			if !reflect.DeepEqual(moduleJSONValue(t, prefix), prefixBefore) || !reflect.DeepEqual(moduleJSONValue(t, test.reply.result), failedBefore) {
				t.Fatal("batch changed an original provider result")
			}
		})
	}
}

func TestModuleBatchFailureBeforeSuccess(t *testing.T) {
	caller := &moduleScriptCaller{replies: []moduleScriptReply{{result: moduleTextResult(moduleTimeoutText)}}}
	var stdout, stderr bytes.Buffer
	err := runModuleBatchCLI(context.Background(), caller, []string{"--json", `[{"module":"r2","tool":"analyze"},{"module":"r2","tool":"xrefs_to"}]`}, &stdout, &stderr)
	if err == nil || len(caller.calls) != 1 {
		t.Fatalf("first-step failure err=%v calls=%d", err, len(caller.calls))
	}
	var report struct {
		Status     string `json:"status"`
		Results    []any  `json:"results"`
		Total      int    `json:"total"`
		Unexecuted int    `json:"unexecuted"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Status != "partial" || report.Results == nil || len(report.Results) != 0 || report.Total != 2 || report.Unexecuted != 1 {
		t.Fatalf("first-step failure report=%s", stdout.Bytes())
	}
}

type moduleErrorWriter struct{ err error }

func (w moduleErrorWriter) Write([]byte) (int, error) { return 0, w.err }

func TestModuleBatchReturnsStepAndOutputErrors(t *testing.T) {
	stepErr, outputErr := errors.New("script transport error"), errors.New("output failed")
	caller := &moduleScriptCaller{replies: []moduleScriptReply{
		{result: moduleTextResult("opened")}, {err: stepErr},
	}}
	err := runModuleBatchCLI(context.Background(), caller,
		[]string{"--json", `[{"module":"r2","tool":"open_file"},{"module":"r2","tool":"show_info"},{"module":"r2","tool":"close_file"}]`},
		moduleErrorWriter{outputErr}, io.Discard)
	if !errors.Is(err, stepErr) || !errors.Is(err, outputErr) || len(caller.calls) != 2 {
		t.Fatalf("combined failure err=%v calls=%d", err, len(caller.calls))
	}
}

func TestModuleBatchSuccessRetainsLegacyArray(t *testing.T) {
	withMeta := moduleFunctionMissingResult()
	before := moduleJSONValue(t, withMeta)
	caller := &moduleScriptCaller{replies: []moduleScriptReply{
		{result: moduleTextResult("opened")}, {result: withMeta}, {result: &mcp.CallToolResult{StructuredContent: []string{"closed"}}},
	}}
	var stdout, stderr bytes.Buffer
	err := runModuleBatchCLI(context.Background(), caller,
		[]string{"--json", `[{"module":"r2","tool":"open_file"},{"module":"r2","tool":"show_info"},{"module":"r2","tool":"close_file"}]`}, &stdout, &stderr)
	if err != nil || len(caller.calls) != 3 {
		t.Fatalf("successful batch err=%v calls=%d", err, len(caller.calls))
	}
	var rows []map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("successful array=%s", stdout.Bytes())
	}
	want := []any{map[string]any{"text": "opened"}, before, []any{"closed"}}
	for index, row := range rows {
		if len(row) != 4 || row["index"] != float64(index) || row["module"] != "r2" || row["tool"] != caller.calls[index].tool || !reflect.DeepEqual(row["result"], want[index]) {
			t.Fatalf("successful row shape changed: %s", stdout.Bytes())
		}
	}
}
