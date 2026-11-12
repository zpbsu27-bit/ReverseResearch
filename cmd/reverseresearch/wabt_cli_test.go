package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"reverseresearch/internal/toolindex"
	"reverseresearch/internal/webinspect"
)

func TestExistingWASMCLIWABTProfile(t *testing.T) {
	root, sourceRoot := isolatedCLIRoot(t)
	tools, err := toolindex.DiscoverWABT(sourceRoot)
	if err != nil {
		t.Fatal(err)
	}
	var bin string
	for _, tool := range tools {
		if tool.Name == "wasm-validate" && tool.Available {
			bin = filepath.Dir(tool.Path)
		}
	}
	if bin == "" {
		t.Skip("WABT is not supplied")
	}
	t.Setenv("REVERSERESEARCH_TOOLS", bin)
	path := filepath.Join(t.TempDir(), "module.wasm")
	if err := os.WriteFile(path, []byte{0, 97, 115, 109, 1, 0, 0, 0}, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := runMain(context.Background(), root, []string{"web", "wasm", path, "--wabt", "--view", "wat"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	var report webinspect.WASMReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if !report.WABT.Validated || report.WABT.Output != "(module)\n" || !report.WABT.TemporaryCopyDisposed {
		t.Fatalf("CLI=%+v", report.WABT)
	}
	stdout.Reset()
	if err := runMain(context.Background(), root, []string{"web", "wasm", path, "--view", "wat"}, &stdout, &stderr); err == nil || stdout.Len() != 0 {
		t.Fatal("CLI allowed implied WABT execution")
	}
	bad := []byte{0, 97, 115, 109, 1, 0, 0, 0, 1, 4, 1, 0x60, 0, 0, 3, 2, 1, 0, 10, 4, 1, 2, 0, 1}
	if err := os.WriteFile(path, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	if err := runMain(context.Background(), root, []string{"web", "wasm", path, "--wabt", "--view", "wat"}, &stdout, &stderr); err == nil {
		t.Fatal("CLI accepted invalid module")
	}
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.WABT.Validated || report.WABT.Status != "invalid-module" {
		t.Fatal("CLI lost structured validation diagnostic")
	}
}
