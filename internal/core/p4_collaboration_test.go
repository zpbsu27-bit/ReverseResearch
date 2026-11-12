package core

import (
	"testing"

	"reverseresearch/internal/casebook"
)

func TestP4ReviewQueueBecomesStaleWhenCaseRevisionChanges(t *testing.T) {
	root, _ := isolatedCoreRoot(t)
	service, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	c, err := service.CreateCase(casebook.CreateRequest{Title: "review lifecycle", Route: "vuln-research"})
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
	w, err := service.InitCaseCollaboration(CollaborationInitRequest{CaseID: c.ID, Owner: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	w, err = service.AddCaseParticipant(CollaborationParticipantRequest{CaseID: c.ID, ExpectedRevision: w.Revision, Actor: "alice", Subject: "bob", Role: "reviewer"})
	if err != nil {
		t.Fatal(err)
	}
	w, review, err := service.RequestCaseCollaborationReview(CollaborationReviewRequest{
		CaseID: c.ID, ExpectedRevision: w.Revision, Actor: "alice", Kind: "finding", SubjectID: f.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if review.Status != "pending" {
		t.Fatalf("review=%+v", review)
	}
	queue, err := service.GetCaseCollaborationReviewQueue(CollaborationReviewQueueRequest{CaseID: c.ID, Actor: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	if len(queue) != 1 || queue[0].State != "pending" {
		t.Fatalf("queue=%+v", queue)
	}
	w, approval, err := service.AddCaseCollaborationApproval(CollaborationApprovalRequest{
		CaseID: c.ID, ExpectedRevision: w.Revision, Actor: "bob", Kind: "finding", SubjectID: f.ID, Decision: "approved",
	})
	if err != nil {
		t.Fatal(err)
	}
	if approval.ID == "" {
		t.Fatal("missing approval id")
	}
	queue, err = service.GetCaseCollaborationReviewQueue(CollaborationReviewQueueRequest{CaseID: c.ID, Actor: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if len(queue) != 0 {
		t.Fatalf("approved current review remained queued: %+v", queue)
	}
	if _, err := service.cases.AddEvidence(c.ID, casebook.EvidenceRequest{Summary: "new case revision", ReproCommand: "fixture2"}); err != nil {
		t.Fatal(err)
	}
	queue, err = service.GetCaseCollaborationReviewQueue(CollaborationReviewQueueRequest{CaseID: c.ID, Actor: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if len(queue) != 1 || queue[0].State != "stale" {
		t.Fatalf("old approval was not invalidated by new case revision: %+v", queue)
	}
	history, err := service.GetCaseCollaborationHistory(CollaborationHistoryRequest{CaseID: c.ID, Actor: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if len(history) < 4 {
		t.Fatalf("history=%+v", history)
	}
}
