package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func isolatedCLIRoot(t *testing.T) (string, string) {
	t.Helper()
	sourceRoot := filepath.Clean(filepath.Join("..", ".."))
	base := filepath.Join(sourceRoot, ".tmp")
	if err := os.MkdirAll(base, 0o700); err != nil {
		t.Fatalf("create CLI test base: %v", err)
	}
	root, err := os.MkdirTemp(base, "cli-test-")
	if err != nil {
		t.Fatalf("create isolated CLI root: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(root)
		_ = os.Remove(base)
	})
	for _, name := range []string{"config", "skills", "testdata"} {
		if err := os.CopyFS(filepath.Join(root, name), os.DirFS(filepath.Join(sourceRoot, name))); err != nil {
			t.Fatalf("copy %s into isolated CLI root: %v", name, err)
		}
	}
	roots := []string{
		filepath.Join(sourceRoot, "runtime", "x32dbg", "release", "x32"),
		filepath.Join(sourceRoot, "runtime", "x32dbg", "release", "x64"),
		filepath.Join(sourceRoot, "runtime", "ghidra", "app"),
		filepath.Join(sourceRoot, "runtime", "radare2", "mcp"),
		filepath.Join(sourceRoot, "runtime", "die"),
	}
	if matches, _ := filepath.Glob(filepath.Join(sourceRoot, "runtime", "radare2", "engine", "radare2-*-w64", "bin")); len(matches) > 0 {
		roots = append(roots, matches[0])
	}
	if current := strings.TrimSpace(os.Getenv("REVERSERESEARCH_TOOLS")); current != "" {
		roots = append(roots, strings.Split(current, string(os.PathListSeparator))...)
	}
	t.Setenv("REVERSERESEARCH_TOOLS", strings.Join(roots, string(os.PathListSeparator)))
	return root, sourceRoot
}
