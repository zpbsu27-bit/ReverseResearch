package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"reverseresearch/internal/capability"
	"reverseresearch/internal/playbook"
	"reverseresearch/internal/sandbox"
)

func TestResearchCatalogAndStableSandboxPlanMCP(t *testing.T) {
	r, session, _, _ := workflowTestSession(t)
	var bookPage researchPage[[]playbook.Playbook]
	workflowCall(t, session, "playbook_list", map[string]any{"limit": 1}, &bookPage)
	if len(bookPage.Result) != 1 || bookPage.Total < 2 || !bookPage.Truncated || bookPage.NextOffset != 1 {
		t.Fatalf("playbook page=%+v", bookPage)
	}
	workflowCall(t, session, "playbook_list", map[string]any{"offset": bookPage.NextOffset, "expected_result_sha256": bookPage.ResultSHA256}, nil)
	var status researchPage[[]capability.Status]
	workflowCall(t, session, "capability_status", map[string]any{"route_id": "binary-diff"}, &status)
	if status.Total != 1 || status.Result[0].RouteID != "binary-diff" {
		t.Fatalf("capability=%+v", status)
	}
	workflowCall(t, session, "capability_status", map[string]any{"limit": 1}, nil)
	plan, err := r.core.PlanSandbox(sandbox.PlanRequest{Name: "MCP owned directory", Kind: sandbox.KindFilesystem})
	if err != nil {
		t.Fatal(err)
	}
	var created, replay struct {
		Plan                     sandbox.Plan `json:"plan"`
		IsolationStarted         bool         `json:"isolation_started"`
		TargetExecutionPerformed bool         `json:"target_execution_performed"`
	}
	args := map[string]any{"plan": plan}
	workflowCall(t, session, "sandbox_create", args, &created)
	keep := filepath.Join(plan.WorkDir, "keep.txt")
	if err := os.WriteFile(keep, []byte("owned work"), 0o600); err != nil {
		t.Fatal(err)
	}
	workflowCall(t, session, "sandbox_create", args, &replay)
	if created.IsolationStarted || created.TargetExecutionPerformed || replay.Plan.ID != plan.ID || replay.Plan.CreatedUTC != plan.CreatedUTC {
		t.Fatalf("sandbox replay=%+v %+v", created, replay)
	}
	storedBody, err := os.ReadFile(filepath.Join(plan.Root, "sandbox.json"))
	if err != nil {
		t.Fatal(err)
	}
	var stored sandbox.Plan
	if err := json.Unmarshal(storedBody, &stored); err != nil || stored.ID != plan.ID {
		t.Fatalf("canonical metadata=%+v %v", stored, err)
	}
	conflict := plan
	conflict.Name = "different request"
	unsafe := plan
	unsafe.Root = t.TempDir()
	for _, bad := range []struct {
		name string
		args map[string]any
	}{
		{"playbook_list", map[string]any{"offset": 1}},
		{"playbook_list", map[string]any{"offset": 1, "expected_result_sha256": strings.Repeat("0", 64)}},
		{"capability_status", map[string]any{"route_id": "missing-route"}},
		{"capability_status", map[string]any{"unknown": true}},
		{"sandbox_create", map[string]any{"plan": conflict}},
		{"sandbox_create", map[string]any{"plan": unsafe}},
	} {
		result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: bad.name, Arguments: bad.args})
		if err == nil && result != nil && !result.IsError {
			t.Fatalf("negative accepted: %s %#v", bad.name, bad.args)
		}
	}
	if body, err := os.ReadFile(keep); err != nil || string(body) != "owned work" {
		t.Fatalf("failed request changed work: %q %v", body, err)
	}
	for _, status := range r.statuses() {
		if status.State != "idle" {
			t.Fatalf("catalog/create launched a backend: %+v", status)
		}
	}
}
