package casebook

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResearchViewIsCanonicalAndDoesNotAcceptCompletion(t *testing.T) {
	root := t.TempDir()
	s, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.Create(CreateRequest{Title: "feature", Targets: []Target{{ID: "target_a", Identity: "build-a"}, {ID: "target_b", Identity: "build-b"}}})
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "evidence")
	os.WriteFile(p, []byte("before"), 0o600)
	e, err := s.AddEvidence(c.ID, EvidenceRequest{Summary: "declared feature", SourcePath: p})
	if err != nil {
		t.Fatal(err)
	}
	f, err := s.AddFinding(c.ID, FindingRequest{Title: "same-name", Conclusion: "candidate", Strength: "inferred", EvidenceIDs: []string{e.ID}})
	if err != nil {
		t.Fatal(err)
	}
	_, before, err := s.Snapshot(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.ResearchView(c.ID, ResearchViewOptions{FindingID: f.ID, Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	_, after, _ := s.Snapshot(c.ID)
	if before != after || v.CaseSHA256 != before || v.CompletionAccepted || v.CoverageComplete || len(v.Targets) != 2 || !v.Verification.Valid {
		t.Fatalf("view %+v", v)
	}
	if _, err := s.ResearchView(c.ID, ResearchViewOptions{FindingID: "same-name"}); err == nil {
		t.Fatal("text matched a function identity")
	}
	if _, err := s.ResearchView(c.ID, ResearchViewOptions{ExpectedSHA256: strings.Repeat("0", 64)}); err == nil {
		t.Fatal("accepted old Case snapshot")
	}
	os.WriteFile(p, []byte("changed"), 0o600)
	v, err = s.ResearchView(c.ID, ResearchViewOptions{})
	if err != nil || v.Verification.Valid {
		t.Fatalf("stale evidence accepted %+v %v", v, err)
	}
	_, after, _ = s.Snapshot(c.ID)
	if after != before {
		t.Fatal("view rewrote canonical Case")
	}
}
