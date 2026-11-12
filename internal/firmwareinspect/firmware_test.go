package firmwareinspect

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestInspectSquashFS(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fw.bin")
	if err := os.WriteFile(p, []byte("hsqsfixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := Inspect(p)
	if err != nil {
		t.Fatal(err)
	}
	if r.Format != "squashfs" || !r.ReadOnly {
		t.Fatalf("report=%+v", r)
	}
}

func TestInspectContextHonorsCancellation(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fw.bin")
	if err := os.WriteFile(p, []byte("hsqsfixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := InspectContext(ctx, p); !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v want context.Canceled", err)
	}
}
