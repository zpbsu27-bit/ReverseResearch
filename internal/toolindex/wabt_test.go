package toolindex

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWABTDiscoveryReusesConfiguredAndProjectSources(t *testing.T) {
	root, configured := t.TempDir(), t.TempDir()
	project := filepath.Join(root, "runtime", "wabt", "wabt-1.0.42", "bin")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"wasm-validate", "wasm-objdump", "wasm2wat", "wat2wasm"} {
		if err := os.WriteFile(filepath.Join(project, name+".exe"), []byte("project tool"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	selected := filepath.Join(configured, "wasm2wat.exe")
	if err := os.WriteFile(selected, []byte("configured tool"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REVERSERESEARCH_TOOLS", configured)
	tools, err := DiscoverWABT(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != 4 {
		t.Fatal("incomplete tool projection")
	}
	for _, tool := range tools {
		if !tool.Available || tool.ExecutableIdentity.SHA256 == "" {
			t.Fatalf("identity=%+v", tool)
		}
		if tool.Name == "wasm2wat" && (tool.Path != selected || tool.Source != "configured") {
			t.Fatalf("operator selection=%+v", tool)
		}
		if tool.Name != "wasm2wat" && tool.Source != "project" {
			t.Fatalf("project source=%+v", tool)
		}
	}
}
