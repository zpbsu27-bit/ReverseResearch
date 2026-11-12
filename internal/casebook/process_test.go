package casebook

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"
)

func TestSeparateProcessesPreserveAllEvidence(t *testing.T) {
	root := t.TempDir()
	s, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.Create(CreateRequest{Title: "multiprocess case"})
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	const workers, perWorker = 6, 8
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cmd := exec.CommandContext(ctx, exe, "-test.run=^TestCaseProcessHelper$")
			cmd.Env = append(os.Environ(), "RR_CASE_WORKER=1", "RR_CASE_ROOT="+root, "RR_CASE_ID="+c.ID)
			out, err := cmd.CombinedOutput()
			if err != nil {
				errs <- fmt.Errorf("worker %d: %w %s", i, err, out)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	got, err := s.Get(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Evidence) != workers*perWorker {
		t.Fatalf("cross-process lost update: %d want %d", len(got.Evidence), workers*perWorker)
	}
}

func TestCaseProcessHelper(t *testing.T) {
	if os.Getenv("RR_CASE_WORKER") != "1" {
		return
	}
	s, err := New(os.Getenv("RR_CASE_ROOT"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if _, err := s.AddEvidence(os.Getenv("RR_CASE_ID"), EvidenceRequest{Summary: fmt.Sprintf("pid=%d item=%d", os.Getpid(), i)}); err != nil {
			t.Fatal(err)
		}
	}
}
