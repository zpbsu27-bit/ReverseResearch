//go:build linux

package backend

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func nativeGhidraTestProfile(t *testing.T) string {
	t.Helper()
	root := os.Getenv("RR_GHIDRA_LINUX_TEST_ROOT")
	if !filepath.IsAbs(root) {
		t.Fatal("native Ghidra tests require an exact absolute RR_GHIDRA_LINUX_TEST_ROOT")
	}
	return root
}

func TestLinuxGhidraNativePythonABIAndWorkerOrigins(t *testing.T) {
	root := nativeGhidraTestProfile(t)
	python, err := resolveGhidraPython(root)
	if err != nil {
		t.Fatal(err)
	}
	if python != filepath.Join(root, "runtime", "ghidra", "python-env", "bin", "python") {
		t.Fatalf("native interpreter differs: %s", python)
	}
	bundle := filepath.Join(root, "runtime", "ghidra", "python-packages")
	if err := validateGhidraPython(t.Context(), python, bundle); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), python, "-c", ghidraPythonPrelude(bundle)+"print('native worker origins verified')")
	cmd.Env = ghidraWorkerEnvironment(os.Environ(), python, bundle)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("native worker bundle resolution failed: %v: %s", err, output)
	}
	if err := validateGhidraPython(t.Context(), python, t.TempDir()); err == nil {
		t.Fatal("empty/unverified bundle was accepted")
	}
}
