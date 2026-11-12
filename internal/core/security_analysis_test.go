package core

import (
	"context"
	"path/filepath"
	"testing"

	"reverseresearch/internal/casebook"
	"reverseresearch/internal/malware"
)

func TestMalwareTriagePersistsArtifactEvidenceAndObservationWithoutFinding(t *testing.T) {
	root, sourceRoot := isolatedCoreRoot(t)
	service, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	c, err := service.CreateCase(casebook.CreateRequest{Title: "malware", Route: "malware-analysis"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.TriageMalware(context.Background(), MalwareTriageRequest{
		Path: filepath.Join(sourceRoot, "testdata", "mcp-smoke.exe"), CaseID: c.ID,
		Options: malware.Options{UseDIE: false, MaxStrings: 32},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Artifact == nil || result.Evidence == nil || result.Observation == nil {
		t.Fatalf("result=%+v", result)
	}
	stored, err := service.GetCase(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.Artifacts) != 1 || len(stored.Evidence) != 1 || len(stored.Observations) != 1 || len(stored.Findings) != 0 {
		t.Fatalf("stored=%+v", stored)
	}
	if !result.Report.StaticOnly || result.Report.SampleExecutionPerformed || result.Report.NetworkInteraction {
		t.Fatalf("report=%+v", result.Report)
	}
}

func TestSigmaValidationPersistsEvidenceBackedDetection(t *testing.T) {
	root, sourceRoot := isolatedCoreRoot(t)
	service, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	c, err := service.CreateCase(casebook.CreateRequest{Title: "blue", Route: "blue-detection"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.ValidateSigma(SigmaValidationRequest{
		RulePath:         filepath.Join(sourceRoot, "testdata", "detection", "sigma_scheduled_task.yml"),
		PositiveFixtures: []string{filepath.Join(sourceRoot, "testdata", "detection", "sigma_scheduled_task_positive.json")},
		NegativeFixtures: []string{filepath.Join(sourceRoot, "testdata", "detection", "sigma_scheduled_task_negative.json")},
		CaseID:           c.ID, Technique: "T1053", Telemetry: []string{"Windows Event Log"},
		TelemetryAvailable: true, FalsePositiveNotes: "known administrative tasks", Coverage: "scheduled task creation",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Validation.Validated || result.Detection == nil || !result.Detection.Validated || len(result.Evidence) != 3 {
		t.Fatalf("result=%+v", result)
	}
	stored, err := service.GetCase(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.Detections) != 1 || len(stored.Evidence) != 3 {
		t.Fatalf("stored=%+v", stored)
	}
}

func TestSigmaCaseBindingRequiresOperationalMetadata(t *testing.T) {
	root, sourceRoot := isolatedCoreRoot(t)
	service, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	c, err := service.CreateCase(casebook.CreateRequest{Title: "blue", Route: "blue-detection"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.ValidateSigma(SigmaValidationRequest{
		RulePath:         filepath.Join(sourceRoot, "testdata", "detection", "sigma_scheduled_task.yml"),
		PositiveFixtures: []string{filepath.Join(sourceRoot, "testdata", "detection", "sigma_scheduled_task_positive.json")},
		NegativeFixtures: []string{filepath.Join(sourceRoot, "testdata", "detection", "sigma_scheduled_task_negative.json")},
		CaseID:           c.ID,
	})
	if err == nil {
		t.Fatal("case-bound validation accepted missing operational metadata")
	}
}
