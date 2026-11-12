package casebook

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestVerificationRevisionMatchesExactRecordBytes(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.Create(CreateRequest{Title: "snapshot"})
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(s.casePath(c.ID))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	result, err := s.Verify(c.ID)
	if err != nil || result.CaseSHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("unbound snapshot: %+v %v", result, err)
	}
}

func TestVerificationRejectsCaseChangedDuringSourceRead(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.Create(CreateRequest{Title: "moving case"})
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "sample.bin")
	if err := os.WriteFile(source, []byte("source"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddEvidence(c.ID, EvidenceRequest{Summary: "source", SourcePath: source}); err != nil {
		t.Fatal(err)
	}
	result, err := s.verify(c.ID, func(path string) (string, int64, error) {
		if _, err := s.AddEvidence(c.ID, EvidenceRequest{Summary: "concurrent observation"}); err != nil {
			t.Fatal(err)
		}
		return fingerprintSource(path)
	})
	if err != nil || result.Valid || len(result.Issues) != 1 || result.Issues[0].Code != "case_changed" {
		t.Fatalf("stale case accepted: %+v %v", result, err)
	}
}

func TestVerificationRejectsDuplicateAndIncompleteBindings(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.Create(CreateRequest{Title: "corrupted record"})
	if err != nil {
		t.Fatal(err)
	}
	c.Evidence = []Evidence{{ID: "e_same", Summary: "first"}, {ID: "e_same", Summary: "second", SourceSHA256: "bad"}}
	if err := s.save(c); err != nil {
		t.Fatal(err)
	}
	result, err := s.Verify(c.ID)
	if err != nil || result.Valid {
		t.Fatalf("corruption accepted: %+v %v", result, err)
	}
	codes := map[string]bool{}
	for _, issue := range result.Issues {
		codes[issue.Code] = true
	}
	if !codes["duplicate_object_id"] || !codes["invalid_source_binding"] {
		t.Fatalf("missing diagnostics: %+v", result.Issues)
	}
}
