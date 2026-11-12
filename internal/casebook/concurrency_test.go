package casebook

import (
	"fmt"
	"sync"
	"testing"
)

// Independent stores model separate CLI invocations and a concurrently running MCP adapter.
func TestIndependentStoresDoNotLoseEvidence(t *testing.T) {
	root := t.TempDir()
	owner, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	c, err := owner.Create(CreateRequest{Title: "parallel evidence"})
	if err != nil {
		t.Fatal(err)
	}
	const count = 40
	stores := make([]*Store, count)
	for i := range stores {
		stores[i], err = New(root)
		if err != nil {
			t.Fatal(err)
		}
	}
	start := make(chan struct{})
	errs := make(chan error, count)
	var wg sync.WaitGroup
	for i, s := range stores {
		wg.Add(1)
		go func(i int, s *Store) {
			defer wg.Done()
			<-start
			_, err := s.AddEvidence(c.ID, EvidenceRequest{Summary: fmt.Sprintf("evidence-%02d", i)})
			errs <- err
		}(i, s)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent update failed: %v", err)
		}
	}
	got, err := owner.Get(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Evidence) != count {
		t.Fatalf("lost evidence: stored %d of %d successful update attempts", len(got.Evidence), count)
	}
}
