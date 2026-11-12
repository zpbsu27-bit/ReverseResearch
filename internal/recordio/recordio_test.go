package recordio

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestPublishFailureRetainsCommittedRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "record.json")
	if err := os.WriteFile(path, []byte("old-record"), 0o600); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("injected publication failure")
	err := writeFileWithPublisher(path, []byte("new-record"), 0o600, func(_, _ string) error { return failure })
	if !errors.Is(err, failure) {
		t.Fatalf("unexpected error: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "old-record" {
		t.Fatalf("old record lost: %q %v", got, err)
	}
	leftovers, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".rr-record-*"))
	if err != nil || len(leftovers) != 0 {
		t.Fatalf("leftover temp files: %v %v", leftovers, err)
	}
	if err := WriteFile(path, []byte("new-record"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = os.ReadFile(path)
	if err != nil || string(got) != "new-record" {
		t.Fatalf("replacement failed: %q %v", got, err)
	}
}

func TestIndependentHandlesAndBoundedWait(t *testing.T) {
	path := filepath.Join(t.TempDir(), "record.lock")
	release, err := Acquire(path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if other, err := Acquire(path, 25*time.Millisecond); !errors.Is(err, ErrBusy) {
		if other != nil {
			_ = other()
		}
		t.Fatalf("expected ErrBusy, got %v", err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	again, err := Acquire(path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := again(); err != nil {
		t.Fatal(err)
	}
}

func TestLockReleasedAfterProcessExit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exit.lock")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestAbandonedLockHelper$")
	cmd.Env = append(os.Environ(), "RR_ABANDON_LOCK="+path)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child failed: %v %s", err, out)
	}
	release, err := Acquire(path, time.Second)
	if err != nil {
		t.Fatalf("dead process retained lock: %v", err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
}

func TestAbandonedLockHelper(t *testing.T) {
	path := os.Getenv("RR_ABANDON_LOCK")
	if path == "" {
		return
	}
	_, err := Acquire(path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	os.Exit(0) // Deliberately omit release to verify OS process-exit recovery.
}
