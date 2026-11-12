package statecompat

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"reverseresearch/internal/recordio"
)

func TestInspectConservativelyTreatsNonEmptyUnversionedStateAsCurrent(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "state", "auth"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "state", "auth", "token"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	status, err := Inspect(root)
	if err != nil {
		t.Fatal(err)
	}
	if status.MarkerPresent || !status.Conservative || status.LayoutVersion != CurrentLayoutVersion {
		t.Fatalf("status=%+v", status)
	}
}

func TestEnsurePublishesStableCurrentMarker(t *testing.T) {
	root := t.TempDir()
	first, err := Ensure(root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Ensure(root)
	if err != nil {
		t.Fatal(err)
	}
	if first.LayoutVersion != CurrentLayoutVersion || second.LayoutVersion != CurrentLayoutVersion ||
		first.CreatedUTC == "" || second.CreatedUTC != first.CreatedUTC {
		t.Fatalf("first=%+v second=%+v", first, second)
	}
	status, err := Inspect(root)
	if err != nil {
		t.Fatal(err)
	}
	if !status.MarkerPresent || status.Conservative || status.LayoutVersion != CurrentLayoutVersion {
		t.Fatalf("status=%+v", status)
	}
}

func TestEnsureUpgradesExplicitLegacyMarker(t *testing.T) {
	root := t.TempDir()
	path, err := MarkerPath(root)
	if err != nil {
		t.Fatal(err)
	}
	legacy := Marker{SchemaVersion: MarkerSchema, LayoutVersion: LegacyUnversionedLayout, CreatedUTC: "2026-10-03T00:00:00Z"}
	body, _ := json.Marshal(legacy)
	if err := recordio.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	marker, err := Ensure(root)
	if err != nil {
		t.Fatal(err)
	}
	if marker.LayoutVersion != CurrentLayoutVersion || marker.MigratedFrom != LegacyUnversionedLayout || marker.UpdatedUTC == "" {
		t.Fatalf("marker=%+v", marker)
	}
}

func TestEnsureRejectsNewerLayout(t *testing.T) {
	root := t.TempDir()
	path, err := MarkerPath(root)
	if err != nil {
		t.Fatal(err)
	}
	newer := Marker{SchemaVersion: MarkerSchema, LayoutVersion: CurrentLayoutVersion + 1, CreatedUTC: "2026-10-03T00:00:00Z"}
	body, _ := json.Marshal(newer)
	if err := recordio.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Ensure(root); !errors.Is(err, ErrStateLayoutTooNew) {
		t.Fatalf("err=%v want ErrStateLayoutTooNew", err)
	}
}

func TestConcurrentEnsurePublishesOneStableMarker(t *testing.T) {
	root := t.TempDir()
	const workers = 16
	markers := make([]Marker, workers)
	errs := make([]error, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		i := i
		go func() {
			defer wg.Done()
			markers[i], errs[i] = Ensure(root)
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("worker %d: %v", i, err)
		}
	}
	for i := 1; i < len(markers); i++ {
		if markers[i].CreatedUTC != markers[0].CreatedUTC || markers[i].LayoutVersion != CurrentLayoutVersion {
			t.Fatalf("marker %d=%+v first=%+v", i, markers[i], markers[0])
		}
	}
	status, err := Inspect(root)
	if err != nil {
		t.Fatal(err)
	}
	if !status.MarkerPresent || status.LayoutVersion != CurrentLayoutVersion || status.CreatedUTC != markers[0].CreatedUTC {
		t.Fatalf("status=%+v first=%+v", status, markers[0])
	}
}
