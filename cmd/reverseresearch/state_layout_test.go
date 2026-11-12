package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"reverseresearch/internal/statecompat"
)

func TestStateLayoutCLIAndNormalCommandPublishMarker(t *testing.T) {
	root := t.TempDir()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if err := runCLI(context.Background(), root, []string{"state-layout", "capabilities"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	var capabilities statecompat.Capabilities
	if err := json.Unmarshal(stdout.Bytes(), &capabilities); err != nil {
		t.Fatal(err)
	}
	if capabilities.MaxSupportedLayout != statecompat.CurrentLayoutVersion || capabilities.WritesLayout != statecompat.CurrentLayoutVersion {
		t.Fatalf("capabilities=%+v", capabilities)
	}
	markerPath, err := statecompat.MarkerPath(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(markerPath); !os.IsNotExist(err) {
		t.Fatalf("capabilities unexpectedly mutated state: %v", err)
	}

	if err := os.MkdirAll(filepath.Join(root, "state", "auth"), 0o700); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	if err := runCLI(context.Background(), root, []string{"state-layout", "status"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	var status statecompat.Status
	if err := json.Unmarshal(stdout.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.MarkerPresent || !status.Conservative || status.LayoutVersion != statecompat.CurrentLayoutVersion {
		t.Fatalf("status=%+v", status)
	}

	target := filepath.Join(root, "fixture.bin")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	if err := runCLI(context.Background(), root, []string{"target", "identify", target}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	status, err = statecompat.Inspect(root)
	if err != nil {
		t.Fatal(err)
	}
	if !status.MarkerPresent || status.LayoutVersion != statecompat.CurrentLayoutVersion {
		t.Fatalf("published status=%+v", status)
	}
}
