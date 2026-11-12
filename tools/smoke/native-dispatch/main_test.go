package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"reverseresearch/internal/targetidentity"
)

func TestQueriesRejectWritesAndScopeOverrides(t *testing.T) {
	for _, input := range []string{
		`[{"tool":"execute_script","arguments":{"script":"anything"}}]`,
		`[{"tool":"rename_function","arguments":{"address":"0x1000","new_name":"changed"}}]`,
		`[{"tool":"open_database","arguments":{"file_path":"other.bin"}}]`,
		`[{"tool":"close_database","arguments":{"save":true}}]`,
		`[{"tool":"get_function","arguments":{"address":"0x1000","database":"other"}}]`,
		`[{"tool":"get_function","arguments":{"address":"0x1000","save":true}}]`,
		`[{"tool":"get_xrefs_to","arguments":{"address":"0x1000","address offset":0}}]`,
		`[{"tool":"get_function","tool":"rename_function","arguments":{"address":"0x1000"}}]`,
		`[{"tool":"get_function","arguments":{"address":"0x1000","address":"0x2000"}}]`,
		`[{"tool":"get_function","t\u006fol":"get_switch_info","arguments":{"address":"0x1000"}}]`,
		`[{"tool":"get_function","arguments":{"address":"0x1000","add\u0072ess":"0x2000"}}]`,
		`[{"tool":"get_function","arguments":{"address":"0x1000"},"extra":true}]`,
		`[{"tool":"get_function","arguments":null}]`,
		`[{"tool":"get_function","arguments":{"address":{"value":"0x1000"}}}]`,
		`[{"tool":"get_function","arguments":{"address":["0x1000"]}}]`,
		`[{"tool":"list_switches","arguments":{"offset":true}}]`,
		`[{"tool":"list_switches"}] {"trailing":true}`,
	} {
		if _, err := parseQueries([]byte(input)); err == nil {
			t.Fatalf("accepted forbidden query: %s", input)
		}
	}
}

func TestQueriesExactReadOnlyNamesAndDatabase(t *testing.T) {
	for _, tool := range []string{"get_function", "disassemble_function", "decompile_function", "get_switch_info", "get_basic_blocks", "get_cfg_edges", "get_xrefs_to", "get_xrefs_from", "get_call_graph", "read_bytes"} {
		input := `[{"tool":"` + tool + `","arguments":{"address":"0x401000"}}]`
		queries, err := parseQueries([]byte(input))
		if err != nil {
			t.Fatalf("%s: %v", tool, err)
		}
		if _, present := queries[0].Arguments["database"]; present {
			t.Fatal("inner arguments must not select the database")
		}
		if queryCallArgs(queries[0])["database"] != databaseID {
			t.Fatal("gateway database was not fixed by the harness")
		}
	}
	for _, tool := range []string{"list_functions", "list_switches"} {
		if _, err := parseQueries([]byte(`[{"tool":"` + tool + `"}]`)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestQueryGatewayWireShapeAndSoleDatabaseOwner(t *testing.T) {
	q := query{Tool: "get_switch_info", Arguments: map[string]json.RawMessage{
		"address":  json.RawMessage(`"0x6c141040"`),
		"database": json.RawMessage(`"must-not-select-this"`),
	}}
	body, err := json.Marshal(queryCallArgs(q))
	if err != nil {
		t.Fatal(err)
	}
	expected := `{"arguments":{"address":"0x6c141040"},"database":"wf17_dispatch","tool":"get_switch_info"}`
	if string(body) != expected {
		t.Fatalf("gateway arguments=%s want=%s", body, expected)
	}
	if string(q.Arguments["database"]) != `"must-not-select-this"` || len(q.Arguments) != 2 {
		t.Fatal("gateway construction changed the parsed query")
	}
}

func TestQueryBudgetsAndTypedArguments(t *testing.T) {
	for _, input := range []string{
		`[]`, `null`, `{}`, `[{"tool":"get_function"}]`,
		`[{"tool":"get_function","arguments":{"address":4096}}]`,
		`[{"tool":"get_function","arguments":{"address":""}}]`,
		`[{"tool":"get_function","arguments":{"address":"bad\u0000name"}}]`,
		`[{"tool":"list_switches","arguments":{"offset":null}}]`,
		`[{"tool":"list_switches","arguments":{"offset":-1}}]`,
		`[{"tool":"list_switches","arguments":{"limit":201}}]`,
		`[{"tool":"get_call_graph","arguments":{"address":"0x1000","depth":4}}]`,
		`[{"tool":"read_bytes","arguments":{"address":"0x1000","size":4097}}]`,
		`[{"tool":"read_bytes","arguments":{"address":"0x1000","size":1.5}}]`,
		`[{"tool":"read_bytes","arguments":{"address":"0x1000","size":"16"}}]`,
	} {
		if _, err := parseQueries([]byte(input)); err == nil {
			t.Fatalf("accepted invalid boundary: %s", input)
		}
	}
	item := `{"tool":"list_switches","arguments":{"offset":0,"limit":200}}`
	if _, err := parseQueries([]byte("[" + strings.TrimSuffix(strings.Repeat(item+",", 16), ",") + "]")); err != nil {
		t.Fatal(err)
	}
	if _, err := parseQueries([]byte("[" + strings.TrimSuffix(strings.Repeat(item+",", 17), ",") + "]")); err == nil {
		t.Fatal("accepted 17 queries")
	}
	if _, err := parseQueries(bytes.Repeat([]byte(" "), maxQueryBytes+1)); err == nil {
		t.Fatal("accepted oversized query file")
	}
}

func TestExistingOperationDirectoryIsNotReplayedOrOverwritten(t *testing.T) {
	work := filepath.Join(t.TempDir(), "owned-operation")
	if err := os.Mkdir(work, 0o700); err != nil {
		t.Fatal(err)
	}
	previous := []byte(`{"status":"RUNNING","previous_identity":"retain"}`)
	path := filepath.Join(work, "receipt.json")
	if err := os.WriteFile(path, previous, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := run(options{work: work})
	if err == nil || out.ResultPath != path {
		t.Fatal("existing operation was not refused with its receipt path")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(previous, after) {
		t.Fatal("existing operation receipt was changed")
	}
}

func TestForbiddenQueriesLeaveFailedReceiptWithoutBackend(t *testing.T) {
	parent := t.TempDir()
	queries := filepath.Join(parent, "queries.json")
	if err := os.WriteFile(queries, []byte(`[{"tool":"rename_function","arguments":{}}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := run(options{work: filepath.Join(parent, "new-operation"), root: parent,
		target: filepath.Join(parent, "must-not-be-opened.bin"), queries: queries,
		expectedSHA: strings.Repeat("0", 64), port: 19197})
	if err == nil {
		t.Fatal("forbidden query was accepted")
	}
	body, readErr := os.ReadFile(out.ResultPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	var got receipt
	if decodeErr := json.Unmarshal(body, &got); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if got.Status != "FAILED" || len(got.Calls) != 0 || got.BackendClosed || got.ShutdownVerified {
		t.Fatalf("failure was misreported: %+v", got)
	}
	if _, statErr := os.Stat(filepath.Join(filepath.Dir(out.ResultPath), "state")); !os.IsNotExist(statErr) {
		t.Fatal("forbidden queries created backend state")
	}
}

func TestResultObjectRequiresActualSuccessAndOneObject(t *testing.T) {
	for _, result := range []*mcp.CallToolResult{nil,
		{IsError: true, StructuredContent: map[string]any{"status": "ready"}},
		{Content: []mcp.Content{&mcp.TextContent{Text: "null"}}},
		{Content: []mcp.Content{&mcp.TextContent{Text: "{}"}, &mcp.TextContent{Text: "{}"}}},
	} {
		if _, err := resultObject(result); err == nil {
			t.Fatal("accepted missing, failed or ambiguous object")
		}
	}
	value, err := resultObject(&mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: `{"status":"ready"}`}}})
	if err != nil || value["status"] != "ready" {
		t.Fatal(value, err)
	}
}

func TestDotPrefixedPathElements(t *testing.T) {
	if !hasDotElement(`D:\work\.hidden\trial`) || !hasDotElement(`/work/.hidden/trial`) || hasDotElement(`D:\work\trial.v1`) {
		t.Fatal("dot-prefixed path element admission changed")
	}
}

func TestReadQueryFileBoundedBytesAndCanceledRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queries.json")
	body := append([]byte("[]"), bytes.Repeat([]byte(" "), maxQueryBytes-2)...)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	got, hash, err := readQueryFile(context.Background(), path)
	if err != nil || !bytes.Equal(got, body) || hash != digest(body) {
		t.Fatalf("exact byte-bound read failed: hash=%s err=%v", hash, err)
	}
	if err := os.WriteFile(path, append(body, ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readQueryFile(context.Background(), path); err == nil {
		t.Fatal("read accepted 64 KiB + 1")
	}
	if _, _, err := readQueryFile(context.Background(), filepath.Dir(path)); err == nil {
		t.Fatal("read accepted directory")
	}
	if err := os.WriteFile(path, []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := readQueryFile(ctx, path); !errors.Is(err, context.Canceled) {
		t.Fatal("read ignored canceled context")
	}
}

func TestQueryParserRejectsMalformedUTF8AndTruncation(t *testing.T) {
	for _, body := range [][]byte{
		append([]byte(`[{"tool":"get_function","arguments":{"address":"`), append([]byte{0xff}, []byte(`"}}]`)...)...),
		[]byte(`[{"tool":"get_function","arguments":{"address":"0x1000"}`),
		[]byte(`[{"tool":"list_switches"},]`),
		[]byte(`[{"tool":"list_switches"}] null`),
	} {
		if _, err := parseQueries(body); err == nil {
			t.Fatalf("accepted malformed config: %q", body)
		}
	}
}

func TestPrepareFixtureCopiesWithoutReplacingExistingDestination(t *testing.T) {
	parent := t.TempDir()
	sourcePath, frozenPath := filepath.Join(parent, "source.bin"), filepath.Join(parent, "frozen.bin")
	body := []byte("inert fixture bytes, never executed")
	if err := os.WriteFile(sourcePath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := targetidentity.InspectBoundedContext(context.Background(), sourcePath, maxTargetBytes)
	if err != nil {
		t.Fatal(err)
	}
	frozen, err := prepareFixture(context.Background(), source, frozenPath)
	defer os.Chmod(frozenPath, 0o600)
	if err != nil || frozen == nil || frozen.SHA256 != digest(body) || frozen.Size != int64(len(body)) {
		t.Fatalf("copy identity failed: frozen=%+v err=%v", frozen, err)
	}
	if _, err := prepareFixture(context.Background(), source, frozenPath); !errors.Is(err, os.ErrExist) {
		t.Fatalf("existing destination was not refused: %v", err)
	}
	for _, path := range []string{sourcePath, frozenPath} {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, body) {
			t.Fatalf("copy changed %s: %v", path, err)
		}
	}
}

func TestPrepareFixtureRejectsSourceDriftAndCanceledWork(t *testing.T) {
	parent := t.TempDir()
	sourcePath, frozenPath := filepath.Join(parent, "source.bin"), filepath.Join(parent, "frozen.bin")
	if err := os.WriteFile(sourcePath, []byte("before"), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := targetidentity.InspectBoundedContext(context.Background(), sourcePath, maxTargetBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourcePath, []byte("after!"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareFixture(context.Background(), source, frozenPath); err == nil {
		t.Fatal("source drift was accepted")
	}
	defer os.Chmod(frozenPath, 0o600)
	if _, err := os.Stat(frozenPath); err != nil {
		t.Fatal("failed preparation did not preserve its evidence", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	untouched := filepath.Join(parent, "must-not-be-created.bin")
	if _, err := prepareFixture(ctx, source, untouched); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := os.Stat(untouched); !os.IsNotExist(err) {
		t.Fatal("canceled preparation created output")
	}
}

func TestLifecycleRejectsDuplicateDecisionFieldsAndTrailingJSON(t *testing.T) {
	for _, text := range []string{
		`{"status":"ready","status":"closed"}`,
		`{"status":null,"sta\u0074us":"ready"}`,
		`{"database":"other","database":"wf17_dispatch"}`,
		`{"saved":true,"saved":false}`,
		`{"file_path":"other","file_path":"expected"}`,
		`{"status":"ready"} {"status":"closed"}`,
		`{"status":"ready"} null`,
		`{"status":"ready"`,
		"{\"status\":\"" + string([]byte{0xff}) + "\"}",
	} {
		if _, err := resultObject(&mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}); err == nil {
			t.Fatalf("accepted ambiguous lifecycle object: %q", text)
		}
	}
	value, err := resultObject(&mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: `{"status":"ready","database":"wf17_dispatch","capabilities":{"decompiler":true}}`}}})
	if err != nil || value["status"] != "ready" || value["capabilities"] == nil {
		t.Fatal("ordinary nested producer facet was lost", value, err)
	}
}
