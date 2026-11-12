package bindiff

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"reverseresearch/internal/targetidentity"
)

func TestBoundedDiffRefusesTruncatedProducerOutputAndHonorsCancellation(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(exe)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"stdout", "stderr", "wait"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("RR_DIFF_BOUNDED_HELPER", mode)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			if mode == "wait" {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
			}
			defer cancel()
			_, _, err := a.run(ctx)
			if mode == "wait" {
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("cancel err=%v", err)
				}
			} else if !errors.Is(err, ErrOutputLimit) {
				t.Fatalf("truncated producer accepted: %v", err)
			}
		})
	}
}

func TestSelectedDiffInputRevisionIsCheckedBeforeProducerStarts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "target.bin")
	if err := os.WriteFile(path, []byte("old!"), 0o600); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(exe)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("RR_DIFF_CURRENTNESS_HELPER", path)
	identity, err := targetidentity.Inspect(path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.Quick(context.Background(), path, path, Options{ExpectedLeftSHA256: "not-a-digest"})
	if err == nil {
		t.Fatal("invalid selected revision accepted")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != "old!" {
		t.Fatal("producer started before input revision validation")
	}
	_, err = a.Quick(context.Background(), path, path, Options{ExpectedLeftSHA256: identity.SHA256})
	if err == nil {
		t.Fatal("accepted producer-side target drift")
	}
}
