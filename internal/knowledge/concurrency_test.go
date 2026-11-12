package knowledge

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestConcurrentNotesPersistAcrossIndependentStores(t *testing.T) {
	root := t.TempDir()
	const count = 48
	start := make(chan struct{})
	errs := make(chan error, count)
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			s, err := New(root)
			if err == nil {
				var note Note
				note, err = s.Add(AddRequest{Title: fmt.Sprintf("parallel-%d", i), Body: "persisted parallel note"})
				if err == nil {
					var got Note
					got, err = s.Get(note.ID)
					if err == nil && (got.ID != note.ID || got.Body != note.Body) {
						err = fmt.Errorf("published note does not match: %+v", got)
					}
				}
			}
			errs <- err
		}(i)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	reopened, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	results, err := reopened.Search("parallel", 100)
	if err != nil || len(results) != count {
		t.Fatalf("persisted %d/%d notes: %v", len(results), count, err)
	}
	seen := map[string]bool{}
	for _, item := range results {
		if seen[item.ID] {
			t.Fatalf("duplicate ID: %s", item.ID)
		}
		seen[item.ID] = true
	}
}

func TestNoteCollisionPreservesPreviousRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "note_collision.json")
	if err := writeNote(path, []byte("previous")); err != nil {
		t.Fatal(err)
	}
	if err := writeNote(path, []byte("replacement")); err == nil {
		t.Fatal("note collision overwrote the original")
	}
	body, err := os.ReadFile(path)
	if err != nil || string(body) != "previous" {
		t.Fatalf("previous record lost: %q %v", body, err)
	}
}
