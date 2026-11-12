package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func isolatedServerRoot(t *testing.T) (string, string) {
	t.Helper()
	sourceRoot := filepath.Clean(filepath.Join("..", ".."))
	root := t.TempDir()
	copyServerTestTree(t, sourceRoot, root, "config")
	copyServerTestTree(t, sourceRoot, root, "skills")
	configureServerTestToolRoots(t, sourceRoot)
	return root, sourceRoot
}

func copyServerTestTree(t *testing.T, sourceRoot, targetRoot, name string) {
	t.Helper()
	source := filepath.Join(sourceRoot, name)
	target := filepath.Join(targetRoot, name)
	if err := os.CopyFS(target, os.DirFS(source)); err != nil {
		t.Fatalf("copy %s into isolated test root: %v", name, err)
	}
}

func configureServerTestToolRoots(t *testing.T, sourceRoot string) {
	t.Helper()
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
}
