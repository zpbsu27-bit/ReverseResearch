package casebook

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCaseV2HypothesisRetractionAndDetectionEvidence(t *testing.T) {
	root := t.TempDir()
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	c, err := store.Create(CreateRequest{
		Title: "malware behavior case", Route: "malware-analysis", EngagementID: "eng_abc",
		Targets: []Target{{ID: "sample", Kind: "file", Identity: "sha256:sample"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.SchemaVersion != 2 || c.EngagementID != "eng_abc" || len(c.Targets) != 1 {
		t.Fatalf("case=%+v", c)
	}
	source := filepath.Join(root, "event.json")
	if err := os.WriteFile(source, []byte("telemetry"), 0o600); err != nil {
		t.Fatal(err)
	}
	evidence, err := store.AddEvidence(c.ID, EvidenceRequest{Summary: "runtime telemetry", Kind: "runtime", SourcePath: source})
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.AddHypothesis(c.ID, HypothesisRequest{
		Hypothesis:            "sample persists through service creation",
		SupportingEvidenceIDs: []string{evidence.ID},
		RequiredExperiment:    "check service registry and reboot fixture",
	})
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := store.AddHypothesis(c.ID, HypothesisRequest{Hypothesis: "sample only creates a scheduled task"})
	if err != nil {
		t.Fatal(err)
	}
	retracted, err := store.UpdateHypothesis(c.ID, first.ID, HypothesisUpdateRequest{
		Status: HypothesisRetracted, ConflictingEvidenceIDs: []string{evidence.ID},
		RejectedReason: "service key is absent in captured runtime state", ReplacementHypothesisID: replacement.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if retracted.Status != HypothesisRetracted || retracted.RejectedReason == "" || retracted.ReplacementHypothesisID != replacement.ID {
		t.Fatalf("retracted=%+v", retracted)
	}
	detection, err := store.AddDetection(c.ID, DetectionRequest{
		Name: "scheduled task behavior", Kind: "sigma", Technique: "T1053",
		Rule: "title: scheduled task", Revision: "rev-1", PositiveFixture: "positive.evtx",
		NegativeFixture: "negative.evtx", ExpectedHit: "1", FalsePositiveNotes: "administrative scheduled tasks",
		TelemetryRequirement: []string{"Sysmon", "Windows Event Log"}, EvidenceIDs: []string{evidence.ID},
		SyntaxValid: true, SchemaValid: true, PositivePassed: true, NegativePassed: true, TelemetryAvailable: true, Validated: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !detection.Validated || len(detection.EvidenceIDs) != 1 {
		t.Fatalf("detection=%+v", detection)
	}
	retest, err := store.AddRetest(c.ID, RetestRequest{
		SubjectType: "detection", SubjectID: detection.ID, Status: "passed",
		Summary: "positive hit and negative fixture stayed clean", EvidenceIDs: []string{evidence.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	if retest.ID == "" {
		t.Fatal("missing retest id")
	}
}

func TestValidatedDetectionCannotSkipFixturesOrEvidence(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c, err := store.Create(CreateRequest{Title: "detection validation"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddDetection(c.ID, DetectionRequest{
		Name: "bad", Kind: "sigma", Rule: "title: bad", Revision: "1", Validated: true,
	}); err == nil {
		t.Fatal("validated detection without fixtures/evidence was accepted")
	}
}

func TestRetractedHypothesisRequiresReason(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c, err := store.Create(CreateRequest{Title: "hypothesis matrix"})
	if err != nil {
		t.Fatal(err)
	}
	h, err := store.AddHypothesis(c.ID, HypothesisRequest{Hypothesis: "candidate"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdateHypothesis(c.ID, h.ID, HypothesisUpdateRequest{Status: HypothesisRetracted}); err == nil {
		t.Fatal("retraction without reason was accepted")
	}
}

func TestCaseV2OperationalObjectsAndStrictReview(t *testing.T) {
	root := t.TempDir()
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	c, err := store.Create(CreateRequest{
		Title: "purple validation case", Route: "purple-validation", EngagementID: "eng_test",
		Targets: []Target{{ID: "target_a", Kind: "host", Identity: "host-a"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	lead, err := store.AssignRole(c.ID, RoleAssignmentRequest{Role: "lead", SpecialistSkill: "seep-purple-team", HandoffWhen: "detection gap classified"})
	if err != nil {
		t.Fatal(err)
	}
	if lead.Role != "lead" {
		t.Fatalf("lead=%+v", lead)
	}
	work, err := store.AddWorkItem(c.ID, WorkItemRequest{Title: "validate telemetry path", OwnerRole: "lead", Coverage: "T1053"})
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "telemetry.json")
	if err := os.WriteFile(source, []byte("event"), 0o600); err != nil {
		t.Fatal(err)
	}
	evidence, err := store.AddEvidence(c.ID, EvidenceRequest{
		Summary: "task creation telemetry", Kind: "runtime", SourcePath: source,
		ReproCommand: "replay fixture", LinkedWorkItemID: work.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	obs, err := store.AddObservation(c.ID, ObservationRequest{Summary: "task creation event observed", EvidenceIDs: []string{evidence.ID}})
	if err != nil || obs.ID == "" {
		t.Fatalf("obs=%+v err=%v", obs, err)
	}
	finding, err := store.AddFinding(c.ID, FindingRequest{
		Title: "scheduled task persistence", Conclusion: "fixture records scheduled-task creation",
		Strength: "observed", Confidence: "high", Severity: "medium", Category: "design", Status: "validated",
		Location: "Windows Event Log", Impact: "persistence visibility", ReproSteps: []string{"replay fixture"},
		Remediation: "monitor task creation", ATTACK: []string{"T1053"}, EvidenceIDs: []string{evidence.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	path, err := store.AddPath(c.ID, PathRequest{
		Title: "T1053 validation path", Details: "emulation to telemetry to detection", PathType: "attack",
		Start: "scoped emulation", Goal: "validated detection",
		Steps:      []PathStep{{Action: "observe task creation", EvidenceIDs: []string{evidence.ID}, FindingIDs: []string{finding.ID}}},
		FindingIDs: []string{finding.ID},
	})
	if err != nil || len(path.Steps) != 1 {
		t.Fatalf("path=%+v err=%v", path, err)
	}
	artifact, err := store.AddArtifact(c.ID, ArtifactRequest{Kind: "telemetry", Identity: "sha256:event"})
	if err != nil {
		t.Fatal(err)
	}
	vuln, err := store.AddVulnerability(c.ID, VulnerabilityRequest{Title: "persistence control gap", FindingIDs: []string{finding.ID}, EvidenceIDs: []string{evidence.ID}})
	if err != nil || vuln.ID == "" {
		t.Fatalf("vuln=%+v err=%v", vuln, err)
	}
	ttp, err := store.AddTTP(c.ID, TTPRequest{Technique: "T1053", Tactic: "Persistence", FindingIDs: []string{finding.ID}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddIOC(c.ID, IOCRequest{Type: "task", Value: "fixture-task", SourceID: evidence.ID}); err != nil {
		t.Fatal(err)
	}
	mitigation, err := store.AddMitigation(c.ID, MitigationRequest{
		Summary: "monitor task creation telemetry", Technique: ttp.Technique, FindingIDs: []string{finding.ID}, EvidenceIDs: []string{evidence.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	detection, err := store.AddDetection(c.ID, DetectionRequest{
		Name: "task creation", Kind: "sigma", Technique: "T1053", TelemetryRequirement: []string{"Windows Event Log"},
		Rule: "title: task creation", Revision: "rev-1", PositiveFixture: "positive.evtx", NegativeFixture: "negative.evtx",
		ExpectedHit: "1", FalsePositiveNotes: "known administrative tasks", Coverage: "task creation",
		EvidenceIDs: []string{evidence.ID}, SyntaxValid: true, SchemaValid: true,
		PositivePassed: true, NegativePassed: true, TelemetryAvailable: true, Validated: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddRetest(c.ID, RetestRequest{
		SubjectType: "detection", SubjectID: detection.ID, Status: "passed",
		Summary: "positive hit and negative stayed clean", EvidenceIDs: []string{evidence.ID},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddRetest(c.ID, RetestRequest{
		SubjectType: "mitigation", SubjectID: mitigation.ID, Status: "passed",
		Summary: "control path exercised", EvidenceIDs: []string{evidence.ID},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddReport(c.ID, ReportRequest{Kind: "purple", Format: "json", Revision: "rev-1", ArtifactID: artifact.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdateWorkItem(c.ID, work.ID, WorkItemUpdateRequest{Status: "done", Coverage: "T1053", EvidenceIDs: []string{evidence.ID}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddTimeline(c.ID, TimelineRequest{
		Kind: "validation", Summary: "T1053 validation completed", Role: "lead", WorkItemID: work.ID, EvidenceIDs: []string{evidence.ID},
	}); err != nil {
		t.Fatal(err)
	}
	review, err := store.Review(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !review.Ready {
		t.Fatalf("review not ready: %+v", review)
	}
	finalReport, err := store.AddReport(c.ID, ReportRequest{
		Kind: "purple", Format: "json", Revision: "rev-2", Profile: "purple-validation",
		Classification: "internal", Status: "final", Summary: "validated T1053 coverage",
		ArtifactID: artifact.ID, FindingIDs: []string{finding.ID}, EvidenceIDs: []string{evidence.ID},
		Sections: []string{"executive-summary", "evidence", "findings", "detections", "retest"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if finalReport.SchemaVersion != 1 || finalReport.Status != "final" || len(finalReport.CaseSHA256) != 64 {
		t.Fatalf("final report=%+v", finalReport)
	}
}

func TestStrictReviewRejectsIncompleteCase(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c, err := store.Create(CreateRequest{Title: "incomplete"})
	if err != nil {
		t.Fatal(err)
	}
	review, err := store.Review(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if review.Ready || len(review.Issues) == 0 {
		t.Fatalf("review=%+v", review)
	}
}

func TestFinalReportFailsClosedBeforeCaseReviewIsReady(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c, err := store.Create(CreateRequest{Title: "not ready", EngagementID: "eng_test", Targets: []Target{{ID: "target_a", Identity: "host-a"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddReport(c.ID, ReportRequest{
		Kind: "security", Format: "json", Revision: "1", Profile: "default", Classification: "internal",
		Status: "final", Sections: []string{"summary"}, EvidenceIDs: []string{"e_missing"},
	}); err == nil {
		t.Fatal("final report bypassed strict case review")
	}
}
