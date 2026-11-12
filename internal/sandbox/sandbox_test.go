package sandbox

import (
	"os"
	"path/filepath"
	"testing"

	"reverseresearch/internal/toolindex"
)

func TestFilesystemSandboxPlanAndCreate(t *testing.T) {
	root := t.TempDir()
	manager, err := New(root, toolindex.Index{})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := manager.Plan(PlanRequest{
		Name:  "pwn challenge 01",
		Route: "ctf-sandbox",
		Kind:  KindFilesystem,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Ready || len(plan.MissingTools) != 0 {
		t.Fatalf("plan=%+v", plan)
	}
	created, err := manager.Create(plan)
	if err != nil {
		t.Fatal(err)
	}
	if created.ID == "" || created.Root == "" {
		t.Fatalf("created=%+v", created)
	}
	for _, dir := range []string{created.InputDir, created.WorkDir, created.OutputDir} {
		if info, err := os.Stat(dir); err != nil || !info.IsDir() {
			t.Fatalf("sandbox dir %s missing: %v", dir, err)
		}
	}
	if _, err := os.Stat(filepath.Join(created.Root, "sandbox.json")); err != nil {
		t.Fatalf("sandbox metadata missing: %v", err)
	}
}

func TestDockerSandboxFailsClosedWhenDockerMissing(t *testing.T) {
	manager, err := New(t.TempDir(), toolindex.Index{
		Tools: []toolindex.Tool{{Name: "docker", Available: false, Source: "missing"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := manager.Plan(PlanRequest{Name: "docker lab", Kind: KindDocker})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Ready || len(plan.MissingTools) != 1 || plan.MissingTools[0] != "docker" {
		t.Fatalf("plan=%+v", plan)
	}
	if _, err := manager.Create(plan); err == nil {
		t.Fatal("create must fail when required isolation backend is missing")
	}
}

func TestWSLSandboxRequiresWSL(t *testing.T) {
	manager, err := New(t.TempDir(), toolindex.Index{
		Tools: []toolindex.Tool{{Name: "wsl", Available: true, Path: "C:/Windows/System32/wsl.exe", Source: "path"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := manager.Plan(PlanRequest{Name: "pwn", Kind: KindWSL})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Ready {
		t.Fatalf("plan=%+v", plan)
	}
}
