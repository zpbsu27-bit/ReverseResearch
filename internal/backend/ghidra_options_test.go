package backend

import (
	"path/filepath"
	"testing"
)

func TestResolveGhidraLaunchOptionsKeepsDefaultLayout(t *testing.T) {
	root := filepath.Clean(filepath.Join("C:", "rr"))
	got, err := resolveGhidraLaunchOptions(root, GhidraLaunchOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Port != defaultGhidraPort ||
		got.StateDir != filepath.Join(root, "state") ||
		got.EvidenceDir != filepath.Join(root, "evidence") {
		t.Fatalf("options=%+v", got)
	}
}

func TestResolveGhidraLaunchOptionsSupportsIsolatedStateAndPort(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "隔离状态")
	evidence := filepath.Join(root, "证据（隔离）")
	got, err := resolveGhidraLaunchOptions(root, GhidraLaunchOptions{
		Port: 19196, StateDir: state, EvidenceDir: evidence,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Port != 19196 || got.StateDir != state || got.EvidenceDir != evidence {
		t.Fatalf("options=%+v", got)
	}
}

func TestResolveGhidraLaunchOptionsRejectsDotPrefixedProjectPath(t *testing.T) {
	root := t.TempDir()
	_, err := resolveGhidraLaunchOptions(root, GhidraLaunchOptions{
		Port: 19196, StateDir: filepath.Join(root, ".tmp", "隔离状态"),
	})
	if err == nil {
		t.Fatal("dot-prefixed Ghidra project path was accepted")
	}
}

func TestResolveGhidraLaunchOptionsRejectsInvalidPort(t *testing.T) {
	if _, err := resolveGhidraLaunchOptions(t.TempDir(), GhidraLaunchOptions{Port: 80}); err == nil {
		t.Fatal("privileged/invalid isolated port was accepted")
	}
}
