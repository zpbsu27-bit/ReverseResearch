package main

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"reverseresearch/internal/casebook"
	"reverseresearch/internal/domainpack"
	"reverseresearch/internal/engagement"
	"reverseresearch/internal/job"
	"reverseresearch/internal/knowledgepack"
)

func p0CLI(t *testing.T, root string, args ...string) []byte {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if err := runCLI(context.Background(), root, args, &stdout, &stderr); err != nil {
		t.Fatalf("%v: %v; stdout=%s stderr=%s", args, err, stdout.String(), stderr.String())
	}
	return stdout.Bytes()
}

func TestP0CLIEndToEnd(t *testing.T) {
	root, _ := isolatedCLIRoot(t)

	var eng engagement.Engagement
	if err := json.Unmarshal(p0CLI(t, root,
		"engagement", "create",
		"--organization", "Lab", "--operator", "analyst",
		"--targets", "host-a", "--actions", "observe,patch",
		"--auth-status", "granted", "--auth-basis", "lab_only",
		"--network-profile", "authorized_target_only",
		"--data-handling", "keep-local", "--deliverables", "detection,report",
	), &eng); err != nil {
		t.Fatal(err)
	}
	if eng.ID == "" || eng.Scope.Authorization.Status != "granted" || eng.Scope.NetworkProfile.Mode != "authorized_target_only" {
		t.Fatalf("engagement=%+v", eng)
	}

	var decision engagement.Decision
	if err := json.Unmarshal(p0CLI(t, root,
		"engagement", "authorize", eng.ID,
		"--target", "host-a", "--action", "patch", "--effect-class", "local mutation",
	), &decision); err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed {
		t.Fatalf("decision=%+v", decision)
	}

	var planned job.Job
	if err := json.Unmarshal(p0CLI(t, root,
		"job", "plan",
		"--operation-id", "cli-p0-op", "--engagement", eng.ID,
		"--target", "host-a", "--action", "patch", "--effect-class", "local mutation",
	), &planned); err != nil {
		t.Fatal(err)
	}
	var prepared job.Job
	if err := json.Unmarshal(p0CLI(t, root,
		"job", "prepare", planned.ID, "--operation-id", planned.OperationID,
	), &prepared); err != nil {
		t.Fatal(err)
	}
	if prepared.State != job.StatePrepared {
		t.Fatalf("prepared=%+v", prepared)
	}

	var audit domainpack.Audit
	if err := json.Unmarshal(p0CLI(t, root, "domain-pack", "audit", "blue-detection"), &audit); err != nil {
		t.Fatal(err)
	}
	if audit.HighRisk != 0 || audit.AggregateSHA256 == "" {
		t.Fatalf("audit=%+v", audit)
	}

	var knowledgePacks []knowledgepack.Pack
	if err := json.Unmarshal(p0CLI(t, root, "knowledge-pack", "route", "blue-detection"), &knowledgePacks); err != nil {
		t.Fatal(err)
	}
	if len(knowledgePacks) != 4 {
		t.Fatalf("knowledge packs=%+v", knowledgePacks)
	}

	var c casebook.Case
	if err := json.Unmarshal(p0CLI(t, root,
		"case", "create", "--title", "CLI P0 case", "--route", "blue-detection",
		"--engagement", eng.ID, "--targets", "host-a",
	), &c); err != nil {
		t.Fatal(err)
	}
	var role casebook.RoleAssignment
	if err := json.Unmarshal(p0CLI(t, root,
		"case", "role", c.ID, "--role", "lead", "--skill", "seep-blueteam",
	), &role); err != nil {
		t.Fatal(err)
	}
	var work casebook.WorkItem
	if err := json.Unmarshal(p0CLI(t, root,
		"case", "workitem", c.ID, "--title", "validate detection", "--owner-role", "lead", "--coverage", "T1053",
	), &work); err != nil {
		t.Fatal(err)
	}
	var evidence casebook.Evidence
	if err := json.Unmarshal(p0CLI(t, root,
		"case", "evidence", c.ID, "--summary", "fixture telemetry", "--kind", "runtime",
		"--repro-command", "fixture replay", "--workitem", work.ID,
	), &evidence); err != nil {
		t.Fatal(err)
	}
	var finding casebook.Finding
	if err := json.Unmarshal(p0CLI(t, root,
		"case", "finding", c.ID,
		"--title", "task creation observed", "--conclusion", "scheduled task creation is observable",
		"--strength", "observed", "--confidence", "high", "--status", "validated",
		"--category", "detection", "--location", "Windows Event Log",
		"--impact", "persistence visibility", "--repro-steps", "replay fixture",
		"--remediation", "monitor task creation", "--attack", "T1053", "--evidence", evidence.ID,
	), &finding); err != nil {
		t.Fatal(err)
	}
	if finding.Status != "validated" || len(finding.EvidenceIDs) != 1 {
		t.Fatalf("finding=%+v", finding)
	}

	var detection casebook.Detection
	if err := json.Unmarshal(p0CLI(t, root,
		"case", "detection", c.ID,
		"--name", "task creation", "--kind", "sigma", "--technique", "T1053",
		"--telemetry", "Windows Event Log", "--rule", "title: task creation", "--revision", "rev-1",
		"--positive-fixture", "positive.evtx", "--negative-fixture", "negative.evtx", "--expected-hit", "1",
		"--false-positive-notes", "known admin tasks", "--coverage", "task creation", "--evidence", evidence.ID,
		"--syntax-valid", "--schema-valid", "--positive-passed", "--negative-passed", "--telemetry-available", "--validated",
	), &detection); err != nil {
		t.Fatal(err)
	}
	if !detection.Validated {
		t.Fatalf("detection=%+v", detection)
	}
	p0CLI(t, root,
		"case", "retest", c.ID, "--subject-type", "detection", "--subject-id", detection.ID,
		"--status", "passed", "--summary", "positive hit; negative clean", "--evidence", evidence.ID,
	)
	p0CLI(t, root,
		"case", "workitem-update", c.ID, work.ID, "--status", "done", "--coverage", "T1053", "--evidence", evidence.ID,
	)
	p0CLI(t, root,
		"case", "timeline", c.ID, "--kind", "validation", "--summary", "detection validation completed",
		"--role", "lead", "--workitem", work.ID, "--evidence", evidence.ID,
	)
	p0CLI(t, root, "case", "artifact", c.ID, "--kind", "telemetry", "--identity", "fixture:task")

	var review casebook.Review
	if err := json.Unmarshal(p0CLI(t, root, "case", "review", c.ID), &review); err != nil {
		t.Fatal(err)
	}
	if !review.Ready {
		t.Fatalf("review=%+v", review)
	}
	var finalReport casebook.Report
	if err := json.Unmarshal(p0CLI(t, root,
		"case", "report", c.ID,
		"--kind", "blue", "--format", "json", "--revision", "rev-final",
		"--profile", "blue-detection", "--classification", "internal", "--status", "final",
		"--summary", "validated scheduled-task detection", "--findings", finding.ID, "--evidence", evidence.ID,
		"--sections", "executive-summary,evidence,findings,detection,retest",
	), &finalReport); err != nil {
		t.Fatal(err)
	}
	if finalReport.Status != "final" || len(finalReport.CaseSHA256) != 64 {
		t.Fatalf("final report=%+v", finalReport)
	}
}

func TestP0CLIRejectsImplicitAuthorization(t *testing.T) {
	root, _ := isolatedCLIRoot(t)
	var stdout, stderr bytes.Buffer
	err := runCLI(context.Background(), root, []string{
		"engagement", "create",
		"--organization", "Lab", "--operator", "analyst",
		"--targets", "host-a", "--actions", "observe",
	}, &stdout, &stderr)
	if err == nil {
		t.Fatalf("implicit authorization was accepted: stdout=%s", stdout.String())
	}
}
