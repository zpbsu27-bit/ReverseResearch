package recordio

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileShardQuotaBoundsFilesAndBytes(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.json")
	b := filepath.Join(dir, "b.json")
	c := filepath.Join(dir, "c.json")

	if err := WriteFileShardQuota(a, bytes.Repeat([]byte{'a'}, 8), 0o600, 2, 16); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileShardQuota(b, bytes.Repeat([]byte{'b'}, 8), 0o600, 2, 16); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileShardQuota(c, []byte("c"), 0o600, 2, 16); !errors.Is(err, ErrShardQuota) {
		t.Fatalf("third file err=%v", err)
	}
	if err := WriteFileShardQuota(a, bytes.Repeat([]byte{'x'}, 9), 0o600, 2, 16); !errors.Is(err, ErrShardQuota) {
		t.Fatalf("oversized replacement err=%v", err)
	}
	if err := WriteFileShardQuota(a, bytes.Repeat([]byte{'x'}, 7), 0o600, 2, 16); err != nil {
		t.Fatal(err)
	}
}

func TestShardQuotaContextHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	path := filepath.Join(t.TempDir(), "cancelled.json")
	if err := CheckShardQuotaContext(ctx, path, 1, 2, 16); !errors.Is(err, context.Canceled) {
		t.Fatalf("check cancellation err=%v", err)
	}
	if err := WriteFileShardQuotaContext(ctx, path, []byte("x"), 0o600, 2, 16); !errors.Is(err, context.Canceled) {
		t.Fatalf("write cancellation err=%v", err)
	}
}

func TestCheckShardQuotaReservesWorstCase(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "receipt.json")
	if err := CheckShardQuota(target, 12, 2, 16); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "other.json"), bytes.Repeat([]byte{'z'}, 8), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckShardQuota(target, 12, 2, 16); !errors.Is(err, ErrShardQuota) {
		t.Fatalf("reserve err=%v", err)
	}
}
