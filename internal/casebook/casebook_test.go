package casebook

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCaseEvidenceFindingLifecycle(t *testing.T) {
	root := t.TempDir()
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}

	c, err := store.Create(CreateRequest{
		Title: "Heroes3 split-army migration",
		Route: "binary-diff",
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.ID == "" || c.Title == "" || c.Status != StatusOpen {
		t.Fatalf("case=%+v", c)
	}

	source := filepath.Join(root, "sample.bin")
	if err := os.WriteFile(source, []byte{1, 2, 3, 4}, 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := store.AddEvidence(c.ID, EvidenceRequest{
		Summary:    "candidate function bytes",
		SourcePath: source,
		Kind:       "file",
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.ID == "" || len(e.SourceSHA256) != 64 {
		t.Fatalf("evidence=%+v", e)
	}

	f, err := store.AddFinding(c.ID, FindingRequest{
		Title:       "candidate split-army function",
		Conclusion:  "Old and new builds share the same call-site role.",
		Strength:    "observed",
		Confidence:  "high",
		EvidenceIDs: []string{e.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	if f.ID == "" || len(f.EvidenceIDs) != 1 || f.Strength != "observed" {
		t.Fatalf("finding=%+v", f)
	}

	p, err := store.AddPath(c.ID, PathRequest{
		Title:      "validated split-army path",
		Details:    "UI event -> handler -> army-slot write",
		FindingIDs: []string{f.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.ID == "" || len(p.FindingIDs) != 1 {
		t.Fatalf("path=%+v", p)
	}

	got, err := store.Get(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Evidence) != 1 || len(got.Findings) != 1 || len(got.Paths) != 1 {
		t.Fatalf("loaded=%+v", got)
	}
}

func TestFindingStrengthDefaultsAndRejectsInvalidValue(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c, err := store.Create(CreateRequest{Title: "strength grading", Route: "android"})
	if err != nil {
		t.Fatal(err)
	}
	finding, err := store.AddFinding(c.ID, FindingRequest{Title: "hypothesis", Conclusion: "not independently reproduced"})
	if err != nil {
		t.Fatal(err)
	}
	if finding.Strength != "unverified" {
		t.Fatalf("strength=%q want unverified", finding.Strength)
	}
	if _, err := store.AddFinding(c.ID, FindingRequest{Title: "bad grade", Conclusion: "invalid", Strength: "high"}); err == nil {
		t.Fatal("invalid finding strength accepted")
	}
}

func TestFindingRejectsUnknownEvidence(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c, err := store.Create(CreateRequest{Title: "test", Route: "native-static"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddFinding(c.ID, FindingRequest{
		Title:       "bad",
		Conclusion:  "unsupported",
		EvidenceIDs: []string{"e_missing"},
	}); err == nil {
		t.Fatal("expected unknown evidence failure")
	}
}

func TestPathRejectsUnknownFinding(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c, err := store.Create(CreateRequest{Title: "test", Route: "native-static"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddPath(c.ID, PathRequest{
		Title: "bad path", Details: "unsupported", FindingIDs: []string{"f_missing"},
	}); err == nil {
		t.Fatal("expected unknown finding failure")
	}
}

func TestCaseIDsArePathSafe(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c, err := store.Create(CreateRequest{Title: "中文 / case .. \\ test", Route: "native-static"})
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(c.ID) != c.ID {
		t.Fatalf("unsafe case id %q", c.ID)
	}
}
