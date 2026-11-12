package toolindex

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestJADXProfileDoesNotTreatMissingOrUnpinnedDataAsExecutable(t *testing.T) {
	root := t.TempDir()
	java := filepath.Join(root, "bin", "java")
	if runtime.GOOS == "windows" {
		java += ".exe"
	}
	if err := os.MkdirAll(filepath.Dir(java), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(java, []byte("inert identity fixture"), 0700); err != nil {
		t.Fatal(err)
	}
	tools := []Tool{{Name: "java21", Path: java, Available: true, HealthStatus: "identity-verified"}}
	missing := discoverJADX(root, tools)
	if missing.Available || missing.RuntimeKind != "java-source-bridge" || missing.ExecutableIdentity.SHA256 != "" || missing.IdentityError == "" {
		t.Fatalf("missing profile forged readiness: %+v", missing)
	}
	jar, _ := JADXPaths(root)
	if err := os.MkdirAll(filepath.Dir(jar), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(jar, []byte("wrong engine"), 0600); err != nil {
		t.Fatal(err)
	}
	wrong := discoverJADX(root, tools)
	if wrong.Available || wrong.HealthStatus != "unavailable" || len(wrong.RuntimeArtifacts) != 0 {
		t.Fatalf("unpinned profile forged identity: %+v", wrong)
	}
}
