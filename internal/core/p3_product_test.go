package core

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"reverseresearch/internal/casebook"
	"reverseresearch/internal/collaboration"
	"reverseresearch/internal/packregistry"
	"reverseresearch/internal/remoteagent"
)

func TestP3ReportCurrentnessAndCollaborationRBAC(t *testing.T) {
	root, _ := isolatedCoreRoot(t)
	service, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	c, err := service.CreateCase(casebook.CreateRequest{Title: "p3", Route: "vuln-research"})
	if err != nil {
		t.Fatal(err)
	}
	e, err := service.cases.AddEvidence(c.ID, casebook.EvidenceRequest{Summary: "proof", ReproCommand: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	f, err := service.cases.AddFinding(c.ID, casebook.FindingRequest{Title: "issue", Conclusion: "observed", Strength: "observed", EvidenceIDs: []string{e.ID}})
	if err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(root, "report.json")
	report, err := service.RenderCaseReport(ReportRenderRequest{CaseID: c.ID, Profile: "vulnerability", Format: "json", OutputPath: out})
	if err != nil {
		t.Fatal(err)
	}
	if report.Output == nil || report.Output.SHA256 != report.ContentSHA256 {
		t.Fatalf("report=%+v", report)
	}
	if _, err := service.RenderCaseReport(ReportRenderRequest{CaseID: c.ID, Profile: "vulnerability", Format: "json", OutputPath: out}); err == nil {
		t.Fatal("report overwrite without current SHA accepted")
	}
	next, err := service.RenderCaseReport(ReportRenderRequest{CaseID: c.ID, Profile: "vulnerability", Format: "json", OutputPath: out, ExpectedOutputSHA256: report.Output.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	if next.Output == nil {
		t.Fatal("expected output identity")
	}

	w, err := service.InitCaseCollaboration(CollaborationInitRequest{CaseID: c.ID, Owner: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	w, err = service.AddCaseParticipant(CollaborationParticipantRequest{CaseID: c.ID, ExpectedRevision: w.Revision, Actor: "alice", Subject: "bob", Role: "reviewer"})
	if err != nil {
		t.Fatal(err)
	}
	w, err = service.AssignCaseFindingOwner(FindingOwnerRequest{CaseID: c.ID, ExpectedRevision: w.Revision, Actor: "alice", FindingID: f.ID, Owner: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	w, err = service.LockCaseEvidence(EvidenceLockRequest{CaseID: c.ID, ExpectedRevision: w.Revision, Actor: "bob", EvidenceID: e.ID, Reason: "final review"})
	if err != nil {
		t.Fatal(err)
	}
	if len(w.EvidenceLocks) != 1 {
		t.Fatalf("locks=%+v", w.EvidenceLocks)
	}
	if _, _, err := service.AddCaseCollaborationTask(CollaborationTaskRequest{CaseID: c.ID, ExpectedRevision: w.Revision, Actor: "bob", Title: "should fail"}); err == nil {
		t.Fatal("reviewer task mutation allowed")
	}
	w, task, err := service.AddCaseCollaborationTask(CollaborationTaskRequest{CaseID: c.ID, ExpectedRevision: w.Revision, Actor: "alice", Title: "retest", Owner: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if task.Status != "planned" {
		t.Fatalf("task=%+v", task)
	}
	w, approval, err := service.AddCaseCollaborationApproval(CollaborationApprovalRequest{CaseID: c.ID, ExpectedRevision: w.Revision, Actor: "bob", Kind: "finding", SubjectID: f.ID, Decision: "approved"})
	if err != nil {
		t.Fatal(err)
	}
	if approval.SourceRevision == "" || approval.Decision != "approved" {
		t.Fatalf("approval=%+v", approval)
	}
}

func TestP3RemoteAgentAndSignedPackRemainVerificationOnly(t *testing.T) {
	root, _ := isolatedCoreRoot(t)
	service, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(nil)
	manifest, err := remoteagent.SignManifest(remoteagent.Manifest{AgentID: "agent-1", Platform: "windows", Architecture: "x86-64", Capabilities: []string{"artifact.inspect"}, TargetAllowlist: []string{"lab-host"}, MutualTLSRequired: true, NoRemoteShell: true, PublicKey: base64.StdEncoding.EncodeToString(pub), ExpiresUTC: time.Now().UTC().Add(time.Hour).Format(time.RFC3339)}, priv)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "agent.json")
	writeJSONFixture(t, manifestPath, manifest)
	reg, err := service.RegisterRemoteAgent(RemoteAgentRegisterRequest{ManifestPath: manifestPath, AuthorityRole: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	if reg.Registration.Manifest.AgentID != "agent-1" {
		t.Fatalf("reg=%+v", reg)
	}
	jobPath := filepath.Join(root, "job.json")
	writeJSONFixture(t, jobPath, remoteagent.JobRequest{Version: 1, JobID: "job-1", OperationID: "op-1", Capability: "artifact.inspect", Target: "lab-host"})
	validated, err := service.ValidateRemoteAgentJob(RemoteJobValidationRequest{AgentID: "agent-1", JobPath: jobPath})
	if err != nil {
		t.Fatal(err)
	}
	if !validated.Valid || validated.ExecutionPerformed {
		t.Fatalf("validated=%+v", validated)
	}
	result, err := remoteagent.SignResult(remoteagent.ResultEnvelope{AgentID: "agent-1", JobID: "job-1", OperationID: "op-1", State: "applied", ResultSHA256: remoteagent.ResultIdentity([]byte("ok")), CompletedUTC: time.Now().UTC().Format(time.RFC3339)}, priv)
	if err != nil {
		t.Fatal(err)
	}
	resultPath := filepath.Join(root, "result.json")
	writeJSONFixture(t, resultPath, result)
	verified, err := service.VerifyRemoteAgentResult(RemoteResultVerificationRequest{AgentID: "agent-1", ResultPath: resultPath})
	if err != nil {
		t.Fatal(err)
	}
	if !verified.Verified {
		t.Fatalf("verified=%+v", verified)
	}

	packRoot := filepath.Join(root, "pack")
	if err := os.MkdirAll(packRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packRoot, "data.txt"), []byte("pack"), 0o600); err != nil {
		t.Fatal(err)
	}
	packManifest, err := packregistry.Build(packRoot, packregistry.Manifest{ID: "demo", PackVersion: "1", Kind: "plugin", Publisher: "lab", PublicKeyID: "lab"})
	if err != nil {
		t.Fatal(err)
	}
	packManifest, err = packregistry.Sign(packManifest, priv)
	if err != nil {
		t.Fatal(err)
	}
	packManifestPath := filepath.Join(root, "manifest.json")
	writeJSONFixture(t, packManifestPath, packManifest)
	trustPath := filepath.Join(root, "trust.json")
	writeJSONFixture(t, trustPath, packregistry.TrustStore{Keys: map[string]string{"lab": base64.StdEncoding.EncodeToString(pub)}})
	packResult, err := service.VerifySignedPack(PackVerificationRequest{Root: packRoot, ManifestPath: packManifestPath, TrustPath: trustPath})
	if err != nil {
		t.Fatal(err)
	}
	if !packResult.Verification.Verified {
		t.Fatalf("pack=%+v", packResult)
	}
}

func writeJSONFixture(t *testing.T, path string, value any) {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestP3CollaborationWorkspaceDoesNotStoreSecretsByRoleClaim(t *testing.T) {
	root, _ := isolatedCoreRoot(t)
	service, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	c, err := service.CreateCase(casebook.CreateRequest{Title: "roles"})
	if err != nil {
		t.Fatal(err)
	}
	w, err := service.InitCaseCollaboration(CollaborationInitRequest{CaseID: c.ID, Owner: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	w, err = service.AddCaseParticipant(CollaborationParticipantRequest{CaseID: c.ID, ExpectedRevision: w.Revision, Actor: "alice", Subject: "eve", Role: "viewer"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.AddCaseCollaborationComment(CollaborationCommentRequest{CaseID: c.ID, ExpectedRevision: w.Revision, Actor: "eve", Body: "comment"}); err == nil {
		// viewer intentionally has read-only access, so comments are denied.
		t.Fatal("viewer comment mutation allowed")
	}
	got, err := service.GetCaseCollaboration(c.ID, "eve")
	if err != nil {
		t.Fatal(err)
	}
	if got.CaseID != c.ID || !strings.EqualFold(got.Participants[1].Role, "viewer") {
		t.Fatalf("workspace=%+v", got)
	}
	_ = collaboration.SchemaVersion
}
