package casebook

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyChecksSourceDriftWithoutRewritingTheCase(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.Create(CreateRequest{Title: "source verification"})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "source.bin")
	if err := os.WriteFile(path, []byte{1, 2, 3}, 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := s.AddEvidence(c.ID, EvidenceRequest{Summary: "bound source", SourcePath: path})
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(s.casePath(c.ID))
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.Verify(c.ID)
	if err != nil || !r.Valid || r.EvidenceChecked != 1 {
		t.Fatalf("valid case rejected: %+v %v", r, err)
	}
	if err := os.WriteFile(path, []byte{9, 2, 3}, 0o600); err != nil {
		t.Fatal(err)
	}
	r, err = s.Verify(c.ID)
	if err != nil || r.Valid || len(r.Issues) != 1 || r.Issues[0].Code != "source_changed" || r.Issues[0].ObjectID != e.ID {
		t.Fatalf("drift not detected: %+v %v", r, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	r, err = s.Verify(c.ID)
	if err != nil || r.Valid || r.Issues[0].Code != "source_unavailable" {
		t.Fatalf("missing source not detected: %+v %v", r, err)
	}
	after, err := os.ReadFile(s.casePath(c.ID))
	if err != nil || string(before) != string(after) {
		t.Fatalf("verification changed the case: %v", err)
	}
}

func TestVerifyDetectsDanglingLinksAndReportsUnboundNotes(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.Create(CreateRequest{Title: "link verification"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.AddEvidence(c.ID, EvidenceRequest{Summary: "an observation without a source file"})
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.Verify(c.ID)
	if err != nil || !r.Valid || r.UnboundEvidence != 1 {
		t.Fatalf("unbound observation lost: %+v %v", r, err)
	}
	c, err = s.Get(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	c.Findings = append(c.Findings, Finding{ID: "f_bad", EvidenceIDs: []string{"e_missing"}})
	c.Paths = append(c.Paths, ResearchPath{ID: "p_bad", FindingIDs: []string{"f_missing"}})
	if err := s.save(c); err != nil {
		t.Fatal(err)
	}
	r, err = s.Verify(c.ID)
	if err != nil || r.Valid || len(r.Issues) < 2 {
		t.Fatalf("dangling links accepted: %+v %v", r, err)
	}
}

func TestVerifyReportsLegacyUngradedFindingWithoutRewritingIt(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.Create(CreateRequest{Title: "legacy strength"})
	if err != nil {
		t.Fatal(err)
	}
	c, err = s.Get(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	c.Findings = append(c.Findings, Finding{ID: "f_legacy", Title: "old conclusion", Conclusion: "predates explicit grading"})
	if err := s.save(c); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(s.casePath(c.ID))
	if err != nil {
		t.Fatal(err)
	}
	result, err := s.Verify(c.ID)
	if err != nil || !result.Valid || result.UngradedFindings != 1 {
		t.Fatalf("legacy grade audit=%+v err=%v", result, err)
	}
	after, err := os.ReadFile(s.casePath(c.ID))
	if err != nil || string(before) != string(after) {
		t.Fatalf("verification rewrote legacy record: %v", err)
	}
}

func TestListRecoversCreatedCaseIDs(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, name := range []string{"first", "second"} {
		c, err := s.Create(CreateRequest{Title: name})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, c.ID)
	}
	all, err := s.List(20)
	if err != nil || len(all) != 2 {
		t.Fatalf("list=%+v err=%v", all, err)
	}
	seen := map[string]bool{}
	for _, c := range all {
		seen[c.ID] = true
	}
	for _, id := range ids {
		if !seen[id] {
			t.Fatalf("missing %s", id)
		}
	}
	one, err := s.List(1)
	if err != nil || len(one) != 1 {
		t.Fatalf("limit ignored: %+v %v", one, err)
	}
}
