package backend

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestGhidraSwitchOverlayMissingSourceIsExplicit(t *testing.T) {
	root := t.TempDir()
	for _, rel := range []string{
		"patches/ghidra/re_mcp_ghidra/session.py",
		"patches/ghidra/re_mcp/worker_provider.py",
	} {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("existing overlay"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	err := syncGhidraRuntimeSources(root)
	if err == nil || !strings.Contains(err.Error(), "switches.py") || !strings.Contains(err.Error(), "read Ghidra runtime overlay") {
		t.Fatalf("missing canonical switch overlay was not explicit: %v", err)
	}
	target := filepath.Join(root, "runtime", "ghidra", "python-packages", "re_mcp_ghidra", "tools", "switches.py")
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("missing canonical source must not publish a switch target: %v", err)
	}
}

func TestGhidraSwitchEvidenceSemantics(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("MSYS Python producer is the verified Windows profile; pure overlay copy tests are portable")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	python, err := resolveGhidraPython(root)
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(root, "patches", "ghidra", "tests", "test_switches.py")
	bundle := filepath.Join(root, "runtime", "ghidra", "python-packages")
	cmd := exec.CommandContext(t.Context(), python, "-I", script, bundle)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("switch semantics regression failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "OK") {
		t.Fatalf("switch regression did not finish: %s", output)
	}
}
