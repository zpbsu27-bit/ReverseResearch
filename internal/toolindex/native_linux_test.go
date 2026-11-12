//go:build linux

package toolindex

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNativeLinuxDiscoveryRefusesWindowsPayloads(t *testing.T) {
	root := t.TempDir()
	for _, member := range []string{"python.exe", "python3", "not-executable", "ghidraRun.bat", "ghidraRun"} {
		mode := os.FileMode(0700)
		if member == "not-executable" {
			mode = 0600
		}
		if err := os.WriteFile(filepath.Join(root, member), []byte("discovery fixture only"), mode); err != nil {
			t.Fatal(err)
		}
	}
	for _, member := range []string{"python.exe", "ghidraRun.bat", "not-executable"} {
		if tool := projectTool("fixture", filepath.Join(root, member)); tool.Available {
			t.Fatalf("non-native/non-executable payload reported available: %+v", tool)
		}
	}
	t.Setenv("PATH", root)
	if tool := firstTool("python", []string{"python.exe", "python3"}); !tool.Available || tool.Path != filepath.Join(root, "python3") {
		t.Fatalf("native PATH choice differs: %+v", tool)
	}
	if tool := firstAvailableTool("ghidra", projectTool("ghidra", filepath.Join(root, "ghidraRun.bat")), projectTool("ghidra", filepath.Join(root, "ghidraRun"))); !tool.Available || tool.Path != filepath.Join(root, "ghidraRun") {
		t.Fatalf("native launcher choice differs: %+v", tool)
	}
}
