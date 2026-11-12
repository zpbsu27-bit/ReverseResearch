package backend

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSyncGhidraRuntimeSourcesRepairsAndIsIdempotent(t *testing.T) {
	root := t.TempDir()
	sessionOverlay := filepath.Join(root, "patches", "ghidra", "re_mcp_ghidra", "session.py")
	poolOverlay := filepath.Join(root, "patches", "ghidra", "re_mcp", "worker_provider.py")
	switchOverlay := filepath.Join(root, "patches", "ghidra", "re_mcp_ghidra", "tools", "switches.py")
	win32Overlay := filepath.Join(root, "patches", "ghidra", "mcp", "os", "win32", "utilities.py")
	sessionTarget := filepath.Join(root, "runtime", "ghidra", "python-packages", "re_mcp_ghidra", "session.py")
	poolTarget := filepath.Join(root, "runtime", "ghidra", "python-packages", "re_mcp", "worker_provider.py")
	switchTarget := filepath.Join(root, "runtime", "ghidra", "python-packages", "re_mcp_ghidra", "tools", "switches.py")
	win32Target := filepath.Join(root, "runtime", "ghidra", "python-packages", "mcp", "os", "win32", "utilities.py")

	for path, body := range map[string]string{
		sessionOverlay: "patched session",
		poolOverlay:    "patched pool",
		switchOverlay:  "patched switches",
		win32Overlay:   "patched win32 utilities",
		sessionTarget:  "old session",
		poolTarget:     "old pool",
		switchTarget:   "old switches",
		win32Target:    "old win32 utilities",
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if err := syncGhidraRuntimeSources(root); err != nil {
		t.Fatal(err)
	}
	assertFileBody(t, sessionTarget, "patched session")
	assertFileBody(t, poolTarget, "patched pool")
	assertFileBody(t, switchTarget, "patched switches")
	win32Expected := "old win32 utilities"
	if runtime.GOOS == "windows" {
		win32Expected = "patched win32 utilities"
	}
	assertFileBody(t, win32Target, win32Expected)

	if err := syncGhidraRuntimeSources(root); err != nil {
		t.Fatal(err)
	}
	assertFileBody(t, sessionTarget, "patched session")
	assertFileBody(t, poolTarget, "patched pool")
	assertFileBody(t, switchTarget, "patched switches")
	assertFileBody(t, win32Target, win32Expected)

	if err := os.Remove(sessionTarget); err != nil {
		t.Fatal(err)
	}
	if err := syncGhidraRuntimeSources(root); err != nil {
		t.Fatal(err)
	}
	assertFileBody(t, sessionTarget, "patched session")
}

func assertFileBody(t *testing.T, path, want string) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != want {
		t.Fatalf("%s=%q want=%q", path, string(body), want)
	}
}
