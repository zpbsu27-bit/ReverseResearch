package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"reverseresearch/internal/bindiff"
	"reverseresearch/internal/knowledge"
	"reverseresearch/internal/migration"
)

func workflowTestSession(t *testing.T) (*Runtime, *mcp.ClientSession, string, string) {
	t.Helper()
	root, source := isolatedServerRoot(t)
	r, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	s, c := mcp.NewInMemoryTransports()
	go func() { _ = r.Run(ctx, s) }()
	client := mcp.NewClient(&mcp.Implementation{Name: "research-workflow-contract", Version: "test"}, nil)
	session, err := client.Connect(ctx, c, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return r, session, root, source
}

func workflowCall(t *testing.T, session *mcp.ClientSession, name string, args map[string]any, dst any) *mcp.CallToolResult {
	t.Helper()
	r, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil || r == nil || r.IsError {
		t.Fatalf("%s failed: result=%#v err=%v", name, r, err)
	}
	if dst != nil {
		decodeStructured(t, r.StructuredContent, dst)
	}
	body, err := json.Marshal(r.StructuredContent)
	if err != nil || len(body) > maxResearchResultBytes {
		t.Fatalf("unbounded %s: bytes=%d err=%v", name, len(body), err)
	}
	return r
}

func TestJournalMCPContractAndImmutableReplay(t *testing.T) {
	r, session, root, _ := workflowTestSession(t)
	listed, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, tool := range listed.Tools {
		names[tool.Name] = true
		if tool.Name == "journal_add" && (tool.Annotations == nil || !tool.Annotations.IdempotentHint) {
			t.Fatal("journal_add lost idempotent annotation")
		}
	}
	for _, name := range []string{"journal_add", "journal_search", "journal_get", "journal_read", "binary_diff_quick", "binary_diff_functions", "function_migration_plan"} {
		if !names[name] {
			t.Fatalf("missing %s", name)
		}
	}
	args := map[string]any{"operation_id": "mcp-note-1", "title": "version evidence", "body": "one\ntwo\nthree", "route": "binary-diff", "architectures": []string{"amd64"}}
	var note, replay journalMetadata
	workflowCall(t, session, "journal_add", args, &note)
	workflowCall(t, session, "journal_add", args, &replay)
	if note.ID != replay.ID || note.Revision != replay.Revision || note.Source.EvidenceStatus != "unverified" {
		t.Fatalf("replay/provenance changed: %+v %+v", note, replay)
	}
	var metadata map[string]any
	workflowCall(t, session, "journal_get", map[string]any{"id": note.ID}, &metadata)
	if _, exposed := metadata["body"]; exposed {
		t.Fatal("get exposed full body")
	}
	var searched struct {
		Matches []journalMetadata `json:"matches"`
	}
	workflowCall(t, session, "journal_search", map[string]any{"route": "binary-diff", "origin": "journal", "architectures": []string{"x64"}}, &searched)
	if len(searched.Matches) != 1 || searched.Matches[0].ID != note.ID || searched.Matches[0].Revision != note.Revision {
		t.Fatalf("search=%+v", searched)
	}
	var excerpt knowledge.Excerpt
	workflowCall(t, session, "journal_read", map[string]any{"id": note.ID, "revision": note.Revision, "start_line": 2, "max_lines": 1}, &excerpt)
	if excerpt.Text != "two" || excerpt.NextLine != 3 {
		t.Fatalf("excerpt=%+v", excerpt)
	}
	workflowCall(t, session, "journal_search", map[string]any{"origin": "builtin", "query": "process guard"}, nil)
	for _, negative := range []struct {
		name string
		args map[string]any
	}{
		{"journal_add", map[string]any{"title": "missing op", "body": "text"}},
		{"journal_add", map[string]any{"operation_id": "mcp-note-1", "title": "version evidence", "body": "changed"}},
		{"journal_add", map[string]any{"operation_id": "too-large", "title": "UTF8 byte budget", "body": strings.Repeat("汉", 22000)}},
		{"journal_get", map[string]any{"id": "../../escape"}},
		{"journal_read", map[string]any{"id": note.ID, "revision": strings.Repeat("0", 64)}},
		{"journal_search", map[string]any{"query": "evidence", "unexpected": true}},
		{"binary_diff_quick", map[string]any{"left_path": "missing", "right_path": "missing", "offset": 1}},
		{"function_migration_plan", map[string]any{"left_path": "missing", "right_path": "missing", "anchors": []any{}}},
	} {
		result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: negative.name, Arguments: negative.args})
		if err == nil && result != nil && !result.IsError {
			t.Fatalf("negative accepted: %s %#v", negative.name, negative.args)
		}
	}
	files, _ := filepath.Glob(filepath.Join(root, "state", "knowledge", "notes", "*.json"))
	if len(files) != 1 {
		t.Fatalf("failed requests wrote extra notes: %v", files)
	}
	for _, status := range r.statuses() {
		if status.State != "idle" {
			t.Fatalf("journal started backend %+v", status)
		}
	}
}

func TestResearchPageBudgetAndRevisionFence(t *testing.T) {
	values := []string{strings.Repeat("a", 20<<10), strings.Repeat("b", 20<<10), strings.Repeat("c", 20<<10)}
	first, err := pagedResearchResult(values, len(values), researchPageOptions{Limit: 3}, func(start, end int) []string { return values[start:end] })
	if err != nil {
		t.Fatal(err)
	}
	var page researchPage[[]string]
	decodeStructured(t, first.StructuredContent, &page)
	if len(page.Result) != 2 || !page.Truncated || page.NextOffset != 2 || page.Total != 3 {
		t.Fatalf("page=%+v", page)
	}
	_, err = pagedResearchResult(values, len(values), researchPageOptions{Offset: 2, ExpectedResultSHA256: page.ResultSHA256}, func(start, end int) []string { return values[start:end] })
	if err != nil {
		t.Fatal(err)
	}
	values[0] = "changed"
	_, err = pagedResearchResult(values, len(values), researchPageOptions{Offset: 2, ExpectedResultSHA256: page.ResultSHA256}, func(start, end int) []string { return values[start:end] })
	if err == nil {
		t.Fatal("accepted result drift between pages")
	}
	_, err = pagedResearchResult(values, len(values), researchPageOptions{Offset: 2}, func(start, end int) []string { return values[start:end] })
	if err == nil {
		t.Fatal("accepted subsequent page without a revision")
	}
}

func TestDiffMCPWithInstalledProducerPreservesCandidates(t *testing.T) {
	r, session, root, source := workflowTestSession(t)
	index, err := r.core.ScanTools()
	if err != nil {
		t.Fatal(err)
	}
	tool, ok := index.ByName("radiff2")
	if !ok || !tool.Available {
		t.Skip("real radiff2 required for native producer acceptance")
	}
	body, err := os.ReadFile(filepath.Join(source, "testdata", "mcp-smoke.exe"))
	if err != nil {
		t.Fatal(err)
	}
	left, right := filepath.Join(root, "old.exe"), filepath.Join(root, "new.exe")
	if err := os.WriteFile(left, body, 0o600); err != nil {
		t.Fatal(err)
	}
	changed := append([]byte(nil), body...)
	changed[len(changed)-1] ^= 1
	changed[len(changed)-3] ^= 1
	if err := os.WriteFile(right, changed, 0o600); err != nil {
		t.Fatal(err)
	}
	args := map[string]any{"left_path": left, "right_path": right, "limit": 1}
	var quick researchPage[bindiff.QuickResult]
	workflowCall(t, session, "binary_diff_quick", args, &quick)
	if quick.Result.Comparison.SameContent || quick.Total < 1 {
		t.Fatalf("quick=%+v", quick)
	}
	var functions researchPage[bindiff.FunctionResult]
	workflowCall(t, session, "binary_diff_functions", map[string]any{"left_path": left, "right_path": right}, &functions)
	if functions.Total == 0 {
		t.Fatal("real fixture produced no function candidates")
	}
	rva := functions.Result.Matches[0].OldRVA
	var planned researchPage[migration.Result]
	workflowCall(t, session, "function_migration_plan", map[string]any{"left_path": left, "right_path": right, "anchors": []migration.Anchor{{Label: "fixture-function", OldRVA: &rva}}}, &planned)
	if planned.Result.Validation != "candidate-only" || planned.Result.RuntimeVerified || len(planned.Result.Entries) != 1 {
		t.Fatalf("plan lost candidate semantics: %+v", planned)
	}
	bad, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "binary_diff_quick", Arguments: map[string]any{"left_path": left, "right_path": right, "expected_left_sha256": strings.Repeat("0", 64)}})
	if err == nil && bad != nil && !bad.IsError {
		t.Fatal("accepted stale selected target")
	}
	after, err := os.ReadFile(right)
	if err != nil || string(after) != string(changed) {
		t.Fatal("static comparison changed target bytes")
	}
	for _, status := range r.statuses() {
		if status.State != "idle" {
			t.Fatalf("direct static producer started persistent backend %+v", status)
		}
	}
}
