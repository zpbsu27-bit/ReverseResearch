package collaboration

import (
	"path/filepath"
	"testing"
)

func TestWorkspaceCurrentnessApprovalAndEvidenceLock(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "collab"))
	if err != nil {
		t.Fatal(err)
	}
	w, err := store.Init("case_1", "alice")
	if err != nil {
		t.Fatal(err)
	}
	first := w.Revision
	w, err = store.AddParticipant("case_1", w.Revision, "bob", "reviewer")
	if err != nil {
		t.Fatal(err)
	}
	if w.Revision == first {
		t.Fatal("revision did not change")
	}
	if _, err := store.AddParticipant("case_1", first, "mallory", "viewer"); err == nil {
		t.Fatal("stale revision accepted")
	}
	w, err = store.AssignFinding("case_1", w.Revision, "f_1", "alice")
	if err != nil {
		t.Fatal(err)
	}
	w, err = store.LockEvidence("case_1", w.Revision, "e_1", "bob", "freeze for final review")
	if err != nil {
		t.Fatal(err)
	}
	if len(w.EvidenceLocks) != 1 {
		t.Fatalf("locks=%+v", w.EvidenceLocks)
	}
	w, approval, err := store.AddApproval("case_1", w.Revision, Approval{Kind: "report", SubjectID: "report_1", Reviewer: "bob", Decision: "approved", SourceRevision: "abc123"})
	if err != nil {
		t.Fatal(err)
	}
	if approval.Decision != "approved" || len(w.Approvals) != 1 {
		t.Fatalf("approval=%+v workspace=%+v", approval, w)
	}
	loaded, err := store.Get("case_1")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Revision != w.Revision {
		t.Fatal("persisted revision mismatch")
	}
}
func TestWorkspaceRejectsNonParticipantOwnership(t *testing.T) {
	store, _ := New(filepath.Join(t.TempDir(), "collab"))
	w, _ := store.Init("case_1", "alice")
	if _, err := store.AssignFinding("case_1", w.Revision, "f_1", "ghost"); err == nil {
		t.Fatal("unknown participant accepted")
	}
}

func TestReviewQueueTracksSourceRevisionAndDecision(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "collab"))
	if err != nil {
		t.Fatal(err)
	}
	w, err := store.Init("case_review", "alice")
	if err != nil {
		t.Fatal(err)
	}
	w, err = store.AddParticipant("case_review", w.Revision, "bob", "reviewer")
	if err != nil {
		t.Fatal(err)
	}
	w, review, err := store.RequestReview("case_review", w.Revision, "alice", "finding", "f_1", "case-rev-1")
	if err != nil {
		t.Fatal(err)
	}
	if review.Status != "pending" || len(w.Reviews) != 1 {
		t.Fatalf("review=%+v workspace=%+v", review, w)
	}
	queue, err := store.ReviewQueue("case_review", "case-rev-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(queue) != 1 || queue[0].State != "pending" {
		t.Fatalf("queue=%+v", queue)
	}
	stale, err := store.ReviewQueue("case_review", "case-rev-2")
	if err != nil {
		t.Fatal(err)
	}
	if len(stale) != 1 || stale[0].State != "stale" {
		t.Fatalf("stale=%+v", stale)
	}
	w, approval, err := store.AddApproval("case_review", w.Revision, Approval{Kind: "finding", SubjectID: "f_1", Reviewer: "bob", Decision: "approved", SourceRevision: "case-rev-1"})
	if err != nil {
		t.Fatal(err)
	}
	if approval.ID == "" || w.Reviews[0].Status != "approved" || w.Reviews[0].LatestApprovalID != approval.ID {
		t.Fatalf("approval=%+v reviews=%+v", approval, w.Reviews)
	}
	queue, err = store.ReviewQueue("case_review", "case-rev-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(queue) != 0 {
		t.Fatalf("approved current review remained queued: %+v", queue)
	}
	stale, err = store.ReviewQueue("case_review", "case-rev-2")
	if err != nil {
		t.Fatal(err)
	}
	if len(stale) != 1 || stale[0].State != "stale" {
		t.Fatalf("approved old revision should become stale: %+v", stale)
	}
	history, err := store.History("case_review")
	if err != nil {
		t.Fatal(err)
	}
	if len(history) < 4 {
		t.Fatalf("history=%+v", history)
	}
	if history[len(history)-2].Action != "review.request" || history[len(history)-1].Action != "review.decision" {
		t.Fatalf("review history tail=%+v", history[len(history)-2:])
	}
}
