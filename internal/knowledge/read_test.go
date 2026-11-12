package knowledge

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRevisionPinnedReadAndSource(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	note, err := s.Add(AddRequest{Title: "PE notes", Body: "first\nsecond\nthird", Source: &Source{
		Reference: "local:test-research", License: "unspecified", UpstreamRevision: "fixture-v1", Engine: "ghidra", Version: "test-only",
	}})
	if err != nil || len(note.Revision) != 64 {
		t.Fatalf("add=%+v err=%v", note, err)
	}
	results, err := s.Search("PE", 10)
	if err != nil || len(results) != 1 || results[0].Revision != note.Revision || results[0].Source.Reference != "local:test-research" {
		t.Fatalf("search provenance=%+v err=%v", results, err)
	}
	part, err := s.Read(ReadRequest{ID: note.ID, Revision: note.Revision, StartLine: 2, MaxLines: 1})
	if err != nil || part.Text != "second" || part.NextLine != 3 || part.TotalLines != 3 || part.EndLine != 2 {
		t.Fatalf("excerpt=%+v err=%v", part, err)
	}
	if _, err := s.Read(ReadRequest{ID: note.ID}); err == nil {
		t.Fatal("unpinned read accepted")
	}
	if _, err := s.Read(ReadRequest{ID: "../outside", Revision: note.Revision}); err == nil {
		t.Fatal("path traversal accepted")
	}
	for _, request := range []ReadRequest{
		{ID: note.ID, Revision: note.Revision, StartLine: -1},
		{ID: note.ID, Revision: note.Revision, StartLine: 4},
		{ID: note.ID, Revision: note.Revision, MaxLines: 201},
	} {
		if _, err := s.Read(request); err == nil {
			t.Errorf("out-of-range request accepted: %+v", request)
		}
	}
	// Simulate an external edit; a search result must not authorize a later revision.
	note.Body = "changed"
	note.Revision = ""
	body, err := json.Marshal(note)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.root, "notes", note.ID+".json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Read(ReadRequest{ID: note.ID, Revision: results[0].Revision}); !errors.Is(err, ErrRevisionChanged) {
		t.Fatalf("stale revision accepted: %v", err)
	}
}

func TestKnowledgeSourceValidationAndReadBounds(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add(AddRequest{Title: "external", Body: "body", Source: &Source{Reference: "external:article"}}); err == nil {
		t.Fatal("source without license/revision accepted")
	}
	note, err := s.Add(AddRequest{Title: "local note", Body: strings.Repeat("x", 33000)})
	if err != nil {
		t.Fatal(err)
	}
	if note.Source == nil || note.Source.EvidenceStatus != "unverified" {
		t.Fatalf("local note silently promoted to evidence: %+v", note.Source)
	}
	if _, err := s.Read(ReadRequest{ID: note.ID, Revision: note.Revision}); err == nil {
		t.Fatal("oversized excerpt accepted")
	}
}
