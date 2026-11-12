package main

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"reverseresearch/internal/casebook"
	researchcore "reverseresearch/internal/core"
)

func TestP1SecurityCLIFlowsIntoCanonicalCases(t *testing.T) {
	root, _ := isolatedCLIRoot(t)

	var malwareCase casebook.Case
	if err := json.Unmarshal(p0CLI(t, root,
		"case", "create", "--title", "malware triage", "--route", "malware-analysis",
	), &malwareCase); err != nil {
		t.Fatal(err)
	}
	var triage researchcore.MalwareTriageResult
	if err := json.Unmarshal(p0CLI(t, root,
		"malware", "triage", filepath.Join(root, "testdata", "mcp-smoke.exe"),
		"--case", malwareCase.ID, "--die=false", "--max-strings", "32",
	), &triage); err != nil {
		t.Fatal(err)
	}
	if triage.Artifact == nil || triage.Evidence == nil || triage.Observation == nil ||
		!triage.Report.StaticOnly || triage.Report.SampleExecutionPerformed || triage.Report.NetworkInteraction {
		t.Fatalf("triage=%+v", triage)
	}

	var blueCase casebook.Case
	if err := json.Unmarshal(p0CLI(t, root,
		"case", "create", "--title", "sigma fixture", "--route", "blue-detection",
	), &blueCase); err != nil {
		t.Fatal(err)
	}
	var validation researchcore.SigmaValidationResult
	if err := json.Unmarshal(p0CLI(t, root,
		"detection", "sigma",
		"--rule", filepath.Join(root, "testdata", "detection", "sigma_scheduled_task.yml"),
		"--positive", filepath.Join(root, "testdata", "detection", "sigma_scheduled_task_positive.json"),
		"--negative", filepath.Join(root, "testdata", "detection", "sigma_scheduled_task_negative.json"),
		"--case", blueCase.ID, "--technique", "T1053",
		"--telemetry", "Windows Event Log", "--telemetry-available",
		"--false-positive-notes", "known administrative tasks",
		"--coverage", "scheduled task creation",
	), &validation); err != nil {
		t.Fatal(err)
	}
	if !validation.Validation.Validated || validation.Detection == nil || !validation.Detection.Validated || len(validation.Evidence) != 3 {
		t.Fatalf("validation=%+v", validation)
	}
}
