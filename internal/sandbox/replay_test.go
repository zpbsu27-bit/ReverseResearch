package sandbox

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"reverseresearch/internal/toolindex"
)

func TestIndependentManagersCreateOnePlanAndPreserveWorkOnReplay(t *testing.T) {
	root := t.TempDir()
	m, err := New(root, toolindex.Index{})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := m.Plan(PlanRequest{Name: "owned research", Kind: KindFilesystem})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			manager, err := New(root, toolindex.Index{})
			if err != nil {
				t.Error(err)
				return
			}
			created, err := manager.Create(plan)
			if err != nil || created.ID != plan.ID || created.CreatedUTC != plan.CreatedUTC {
				t.Errorf("concurrent create: %+v %v", created, err)
			}
		}()
	}
	wg.Wait()
	work := filepath.Join(plan.WorkDir, "research.txt")
	if err := os.WriteFile(work, []byte("preserve my work"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Create(plan); err != nil {
		t.Fatal(err)
	}
	changed := plan
	changed.Name = "different operation"
	if _, err := m.Create(changed); !errors.Is(err, ErrPlanConflict) {
		t.Fatalf("conflict accepted: %v", err)
	}
	if body, err := os.ReadFile(work); err != nil || string(body) != "preserve my work" {
		t.Fatalf("replay/conflict changed work: %q %v", body, err)
	}
	entries, err := os.ReadDir(filepath.Join(root, "sandboxes"))
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range entries {
		if entry.IsDir() {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("published or leaked directories=%d", count)
	}
}

func TestCreateRefusesUnsafeAndIncompleteDirectoriesWithoutDeletingThem(t *testing.T) {
	root := t.TempDir()
	m, _ := New(root, toolindex.Index{})
	plan, err := m.Plan(PlanRequest{Name: "research", Kind: KindFilesystem})
	if err != nil {
		t.Fatal(err)
	}
	unsafe := plan
	unsafe.Root = filepath.Join(t.TempDir(), plan.ID)
	if _, err := m.Create(unsafe); err == nil {
		t.Fatal("non-owner path accepted")
	}
	if err := os.MkdirAll(plan.WorkDir, 0o700); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(plan.WorkDir, "keep")
	if err := os.WriteFile(keep, []byte("existing data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Create(plan); err == nil {
		t.Fatal("incomplete existing root accepted")
	}
	if body, err := os.ReadFile(keep); err != nil || string(body) != "existing data" {
		t.Fatalf("failure removed another owner's data: %q %v", body, err)
	}
}

func TestCommittedPlanReplayNeedsNoNewIsolationBackend(t *testing.T) {
	root := t.TempDir()
	m, _ := New(root, toolindex.Index{Tools: []toolindex.Tool{{Name: "docker", Available: true}}})
	plan, err := m.Plan(PlanRequest{Name: "directory preparation", Kind: KindDocker})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Create(plan); err != nil {
		t.Fatal(err)
	}
	missing, _ := New(root, toolindex.Index{})
	if _, err := missing.Create(plan); err != nil {
		t.Fatalf("completed directory creation was replayed against a new environment: %v", err)
	}
}
