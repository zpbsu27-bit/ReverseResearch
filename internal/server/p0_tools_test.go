package server

import (
	"context"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestP0ResearchOwnersWorkThroughMCP(t *testing.T) {
	root, _ := isolatedServerRoot(t)
	runtime, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	go func() { _ = runtime.Run(ctx, serverTransport) }()

	client := mcp.NewClient(&mcp.Implementation{Name: "p0-tools-test", Version: "1.0.0"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	call := func(name string, arguments map[string]any, destination any) *mcp.CallToolResult {
		t.Helper()
		result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: arguments})
		if err != nil || result == nil || result.IsError {
			t.Fatalf("%s failed: result=%#v err=%v", name, result, err)
		}
		if destination != nil {
			decodeStructured(t, result.StructuredContent, destination)
		}
		return result
	}

	var eng struct {
		ID string `json:"id"`
	}
	call("engagement_create", map[string]any{
		"organization": "Research Lab",
		"operator":     "analyst",
		"scope": map[string]any{
			"targets":         []string{"host-a"},
			"allowed_actions": []string{"observe", "patch"},
			"authorization":   map[string]any{"status": "granted", "basis": "lab_only", "evidence_refs": []string{"test-fixture"}},
			"network_profile": map[string]any{"mode": "authorized_target_only"},
			"starts_utc":      time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
			"ends_utc":        time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		},
	}, &eng)
	if eng.ID == "" {
		t.Fatal("missing engagement id")
	}

	var decision struct {
		Allowed bool `json:"allowed"`
	}
	call("engagement_authorize", map[string]any{
		"engagement_id": eng.ID, "target": "host-a", "action": "patch",
	}, &decision)
	if !decision.Allowed {
		t.Fatal("expected scoped action to be allowed")
	}

	var planned struct {
		ID          string `json:"job_id"`
		OperationID string `json:"operation_id"`
		State       string `json:"state"`
	}
	call("job_plan", map[string]any{
		"operation_id": "mcp-p0-op-1", "engagement_id": eng.ID,
		"target": "host-a", "action": "patch", "effect_class": "local mutation",
		"input_revision": "sha256:before",
	}, &planned)
	if planned.ID == "" || planned.State != "planned" {
		t.Fatalf("planned=%+v", planned)
	}
	var prepared struct {
		State string `json:"state"`
	}
	call("job_prepare", map[string]any{
		"job_id": planned.ID, "operation_id": planned.OperationID,
	}, &prepared)
	if prepared.State != "prepared" {
		t.Fatalf("prepared=%+v", prepared)
	}
	var running struct {
		State string `json:"state"`
	}
	call("job_transition", map[string]any{
		"job_id": planned.ID, "operation_id": planned.OperationID, "to": "running",
	}, &running)
	if running.State != "running" {
		t.Fatalf("running=%+v", running)
	}
	var uncertain struct {
		State string `json:"state"`
	}
	call("job_transition", map[string]any{
		"job_id": planned.ID, "operation_id": planned.OperationID, "to": "uncertain",
		"failure": "fixture transport interruption",
	}, &uncertain)
	if uncertain.State != "uncertain" {
		t.Fatalf("uncertain=%+v", uncertain)
	}
	replayed, replayErr := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "job_transition", Arguments: map[string]any{
			"job_id": planned.ID, "operation_id": planned.OperationID, "to": "running",
		},
	})
	if replayErr == nil && replayed != nil && !replayed.IsError {
		t.Fatalf("uncertain job replay was accepted: %#v", replayed)
	}

	var pack struct {
		ID string `json:"id"`
	}
	call("domain_pack_get", map[string]any{"route_id": "blue-detection"}, &pack)
	if pack.ID != "blue-detection" {
		t.Fatalf("domain pack=%+v", pack)
	}
	var knowledgePack struct {
		ID string `json:"id"`
	}
	call("knowledge_pack_get", map[string]any{"pack_id": "detection-engineering"}, &knowledgePack)
	if knowledgePack.ID != "detection-engineering" {
		t.Fatalf("knowledge pack=%+v", knowledgePack)
	}

	var researchCase struct {
		ID            string `json:"id"`
		SchemaVersion int    `json:"schema_version"`
	}
	call("case_create", map[string]any{
		"title": "P0 detection validation", "route": "blue-detection", "engagement_id": eng.ID,
		"targets": []map[string]any{{"id": "target_a", "kind": "host", "identity": "host-a"}},
	}, &researchCase)
	if researchCase.ID == "" || researchCase.SchemaVersion != 2 {
		t.Fatalf("case=%+v", researchCase)
	}

	var role struct {
		ID string `json:"id"`
	}
	call("case_role_assign", map[string]any{
		"case_id": researchCase.ID, "role": "lead", "specialist_skill": "seep-blueteam", "handoff_when": "detection validated",
	}, &role)
	if role.ID == "" {
		t.Fatal("missing role id")
	}

	var work struct {
		ID string `json:"id"`
	}
	call("case_workitem_add", map[string]any{
		"case_id": researchCase.ID, "title": "validate scheduled-task detection", "owner_role": "lead", "coverage": "T1053",
	}, &work)
	if work.ID == "" {
		t.Fatal("missing workitem id")
	}

	var evidence struct {
		ID string `json:"id"`
	}
	call("case_evidence_add", map[string]any{
		"case_id": researchCase.ID, "summary": "positive telemetry fixture", "kind": "runtime",
		"repro_command": "fixture replay", "linked_workitem_id": work.ID,
	}, &evidence)
	if evidence.ID == "" {
		t.Fatal("missing evidence id")
	}

	var firstHypothesis struct {
		ID string `json:"id"`
	}
	call("case_hypothesis_add", map[string]any{
		"case_id": researchCase.ID, "hypothesis": "service persistence exists",
		"supporting_evidence_ids": []string{evidence.ID}, "required_experiment": "check service control manager state",
	}, &firstHypothesis)
	var replacement struct {
		ID string `json:"id"`
	}
	call("case_hypothesis_add", map[string]any{
		"case_id": researchCase.ID, "hypothesis": "scheduled-task persistence exists instead",
	}, &replacement)
	var retracted struct {
		Status string `json:"status"`
	}
	call("case_hypothesis_update", map[string]any{
		"case_id": researchCase.ID, "hypothesis_id": firstHypothesis.ID, "status": "retracted",
		"conflicting_evidence_ids":  []string{evidence.ID},
		"rejected_reason":           "service state absent in fixture",
		"replacement_hypothesis_id": replacement.ID,
	}, &retracted)
	if retracted.Status != "retracted" {
		t.Fatalf("retracted=%+v", retracted)
	}

	var detection struct {
		ID        string `json:"id"`
		Validated bool   `json:"validated"`
	}
	call("case_detection_add", map[string]any{
		"case_id": researchCase.ID, "name": "scheduled task persistence", "kind": "sigma",
		"technique": "T1053", "telemetry_requirement": []string{"Sysmon", "Windows Event Log"},
		"rule": "title: scheduled task persistence", "revision": "rev-1",
		"positive_fixture": "positive.evtx", "negative_fixture": "negative.evtx", "expected_hit": "1",
		"false_positive_notes": "administrative scheduled tasks", "coverage": "task creation telemetry",
		"evidence_ids": []string{evidence.ID}, "syntax_valid": true, "schema_valid": true,
		"positive_passed": true, "negative_passed": true, "telemetry_available": true, "validated": true,
	}, &detection)
	if detection.ID == "" || !detection.Validated {
		t.Fatalf("detection=%+v", detection)
	}

	call("case_retest_add", map[string]any{
		"case_id": researchCase.ID, "subject_type": "detection", "subject_id": detection.ID,
		"status": "passed", "summary": "positive fixture hits and negative fixture stays clean",
		"evidence_ids": []string{evidence.ID},
	}, nil)

	call("case_workitem_update", map[string]any{
		"case_id": researchCase.ID, "workitem_id": work.ID, "status": "done",
		"coverage": "T1053", "evidence_ids": []string{evidence.ID},
	}, nil)
	call("case_timeline_add", map[string]any{
		"case_id": researchCase.ID, "kind": "validation", "summary": "detection validation completed",
		"role": "lead", "workitem_id": work.ID, "evidence_ids": []string{evidence.ID},
	}, nil)

	var artifact struct {
		ID string `json:"id"`
	}
	call("case_artifact_add", map[string]any{
		"case_id": researchCase.ID, "kind": "telemetry", "identity": "fixture:scheduled-task",
	}, &artifact)
	call("case_observation_add", map[string]any{
		"case_id": researchCase.ID, "summary": "scheduled-task telemetry observed", "evidence_ids": []string{evidence.ID},
	}, nil)

	var audit struct {
		HighRisk        int    `json:"high_risk"`
		AggregateSHA256 string `json:"aggregate_sha256"`
	}
	call("domain_pack_audit", map[string]any{"pack_id": "blue-detection"}, &audit)
	if audit.HighRisk != 0 || audit.AggregateSHA256 == "" {
		t.Fatalf("audit=%+v", audit)
	}

	var verification struct {
		Valid bool `json:"valid"`
	}
	call("case_verify", map[string]any{"case_id": researchCase.ID}, &verification)
	if !verification.Valid {
		t.Fatalf("verification=%+v", verification)
	}
	var review struct {
		Ready bool `json:"ready"`
	}
	call("case_review", map[string]any{"case_id": researchCase.ID}, &review)
	if !review.Ready {
		t.Fatalf("review=%+v", review)
	}
	var finalReport struct {
		Status     string `json:"status"`
		CaseSHA256 string `json:"case_sha256"`
	}
	call("case_report_add", map[string]any{
		"case_id": researchCase.ID, "kind": "blue", "format": "json", "revision": "rev-final",
		"profile": "blue-detection", "classification": "internal", "status": "final",
		"summary": "validated scheduled-task detection", "evidence_ids": []string{evidence.ID},
		"sections": []string{"executive-summary", "evidence", "detection", "retest"},
	}, &finalReport)
	if finalReport.Status != "final" || len(finalReport.CaseSHA256) != 64 {
		t.Fatalf("final report=%+v", finalReport)
	}
}
