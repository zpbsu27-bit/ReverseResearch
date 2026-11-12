package knowledge

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestOperationReplayRefusesChangedContentWithRetainedRequestDigest(t *testing.T) {
	for _, explicitSource := range []bool{false, true} {
		t.Run(map[bool]string{false: "default-source", true: "explicit-source"}[explicitSource], func(t *testing.T) {
			s, err := New(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			request := AddRequest{OperationID: "immutable-request", Title: "candidate", Body: "original research"}
			if explicitSource {
				request.Source = &Source{Reference: "local:fixture", License: "owned", UpstreamRevision: "v1"}
			}
			note, err := s.Add(request)
			if err != nil {
				t.Fatal(err)
			}
			note.Body = "externally replaced research"
			note.Revision = ""
			payload, err := json.Marshal(note)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(s.root, "notes", note.ID+".json")
			if err := os.WriteFile(path, payload, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Add(request); !errors.Is(err, ErrOperationConflict) {
				t.Fatalf("changed content reused the historical request digest: %v", err)
			}
			after, err := os.ReadFile(path)
			if err != nil || string(after) != string(payload) {
				t.Fatalf("refused replay wrote to the note: %v", err)
			}
		})
	}
}

func TestOperationRetryAndConcurrentStoresKeepOneImmutableNote(t *testing.T) {
	root := t.TempDir()
	request := AddRequest{OperationID: "case-01-note", Title: "version candidate", Body: "candidate only\nnot runtime verified", Tools: []string{"RADIFF2"}, Architectures: []string{"amd64"}}
	const writers = 20
	var wg sync.WaitGroup
	notes := make(chan Note, writers)
	errorsFound := make(chan error, writers)
	for range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := New(root)
			if err != nil {
				errorsFound <- err
				return
			}
			note, err := s.Add(request)
			if err != nil {
				errorsFound <- err
				return
			}
			notes <- note
		}()
	}
	wg.Wait()
	close(notes)
	close(errorsFound)
	for err := range errorsFound {
		t.Error(err)
	}
	var first Note
	count := 0
	for note := range notes {
		if first.ID == "" {
			first = note
		}
		if note.ID != first.ID || note.Revision != first.Revision || note.CreatedUTC != first.CreatedUTC {
			t.Fatalf("retry changed immutable note: %s/%s vs %s/%s", note.ID, note.Revision, first.ID, first.Revision)
		}
		count++
	}
	if count != writers {
		t.Fatalf("successful writers=%d want=%d", count, writers)
	}
	files, err := filepath.Glob(filepath.Join(root, "notes", "*.json"))
	if err != nil || len(files) != 1 {
		t.Fatalf("notes=%v err=%v", files, err)
	}
	s, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	request.Architectures = []string{"x64"} // the existing scope owner canonicalizes aliases
	request.Tools = []string{"radiff2"}
	replayed, err := s.Add(request)
	if err != nil || replayed.Revision != first.Revision {
		t.Fatalf("normalized replay=%+v err=%v", replayed, err)
	}
	request.Body = "different request"
	if _, err := s.Add(request); !errors.Is(err, ErrOperationConflict) {
		t.Fatalf("conflicting operation reuse err=%v", err)
	}
	after, err := os.ReadFile(files[0])
	if err != nil || contentRevision(after) != first.Revision {
		t.Fatalf("conflict overwrote note: %v", err)
	}
}

func TestOperationIdentityValidationAndLegacyAddRemainSeparate(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{"../escape", "with space", ""} {
		r := AddRequest{OperationID: op, Title: "note", Body: "body"}
		if op == "" {
			a, err := s.Add(r)
			if err != nil {
				t.Fatal(err)
			}
			b, err := s.Add(r)
			if err != nil {
				t.Fatal(err)
			}
			if a.ID == b.ID || a.OperationID != "" {
				t.Fatal("legacy adds lost their independent random identities")
			}
		} else if _, err := s.Add(r); err == nil {
			t.Fatalf("invalid operation accepted: %q", op)
		}
	}
}
