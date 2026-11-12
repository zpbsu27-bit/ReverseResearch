package knowledge

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetNoteAndRejectChangedIdentity(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	n, err := s.Add(AddRequest{Title: "note identity", Body: "an observation, not an instruction"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(n.ID)
	if err != nil || got.Body != n.Body {
		t.Fatalf("get note: %+v %v", got, err)
	}
	if _, err := s.Get("../outside"); err == nil {
		t.Fatal("unsafe ID accepted")
	}
	if err := os.WriteFile(filepath.Join(s.root, "notes", n.ID+".json"), []byte(`{"id":"note_wrong","title":"wrong","body":"wrong"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(n.ID); err == nil {
		t.Fatal("mismatching on-disk note ID accepted")
	}
	if _, err := s.Search("wrong", 10); err == nil {
		t.Fatal("search accepted a forged note identity")
	}
}
