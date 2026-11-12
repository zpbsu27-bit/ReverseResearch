package memscan

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestDeleteRequiresCurrentVersionAndReleasesScanState(t *testing.T) {
	manager := fakeManager(t, t.TempDir(), fakeU32Memory(10, 20, 30, 40))
	scan := startU32(t, manager, ModeExact, "20", 100)

	if _, err := manager.Delete(context.Background(), DeleteRequest{
		ScanID: scan.ID, ExpectedVersion: scan.Version + 1,
	}); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("stale delete err=%v want ErrVersionConflict", err)
	}
	if _, err := manager.Get(scan.ID, 1); err != nil {
		t.Fatalf("stale delete removed scan: %v", err)
	}

	deleted, err := manager.Delete(context.Background(), DeleteRequest{
		ScanID: scan.ID, ExpectedVersion: scan.Version,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !deleted.Deleted || deleted.ScanID != scan.ID || deleted.Version != scan.Version {
		t.Fatalf("delete result=%+v", deleted)
	}
	if _, err := manager.Get(scan.ID, 1); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("deleted scan Get err=%v want not-exist", err)
	}
}
