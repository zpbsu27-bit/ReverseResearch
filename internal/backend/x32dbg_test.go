package backend

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestXDBGSpecSelectsArchitectureSpecificRuntime(t *testing.T) {
	root := t.TempDir()
	x32, err := xdbgSpec(root, 32)
	if err != nil {
		t.Fatal(err)
	}
	x64, err := xdbgSpec(root, 64)
	if err != nil {
		t.Fatal(err)
	}
	if x32.Name != "x32dbg" || filepath.Base(x32.Base) != "x32" ||
		filepath.Ext(x32.PluginPath) != ".dp32" || filepath.Base(x32.StateDir) != "x32dbg" {
		t.Fatalf("x32 spec=%+v", x32)
	}
	if x64.Name != "x64dbg" || filepath.Base(x64.Base) != "x64" ||
		filepath.Ext(x64.PluginPath) != ".dp64" || filepath.Base(x64.StateDir) != "x64dbg" {
		t.Fatalf("x64 spec=%+v", x64)
	}
	if _, err := xdbgSpec(root, 128); err == nil {
		t.Fatal("unsupported debugger architecture was accepted")
	}
}

func TestEnsureXDBGConfigDerivesIndependentX64Config(t *testing.T) {
	root := t.TempDir()
	x32, _ := xdbgSpec(root, 32)
	x64, _ := xdbgSpec(root, 64)
	if err := os.MkdirAll(x32.Base, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(x64.Base, 0o755); err != nil {
		t.Fatal(err)
	}
	source := xdbgConfig{
		IPAddress: "127.0.0.1", Port: 19095, AutoStart: true,
		AuthToken: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	body, _ := json.Marshal(source)
	if err := os.WriteFile(filepath.Join(x32.Base, "mcp_config.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}

	derived, err := ensureXDBGConfig(root, x64)
	if err != nil {
		t.Fatal(err)
	}
	if derived.Port != 19096 || derived.AuthToken == source.AuthToken || len(derived.AuthToken) != 64 || derived.IPAddress != "127.0.0.1" {
		t.Fatalf("derived=%+v", derived)
	}
	persisted, err := os.ReadFile(filepath.Join(x64.Base, "mcp_config.json"))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeXDBGConfig(persisted)
	if err != nil || decoded.Port != derived.Port {
		t.Fatalf("persisted=%+v err=%v", decoded, err)
	}
}

func TestEnsureXDBGConfigRejectsSharedArchitecturePort(t *testing.T) {
	root := t.TempDir()
	x32, _ := xdbgSpec(root, 32)
	x64, _ := xdbgSpec(root, 64)
	for _, dir := range []string{x32.Base, x64.Base} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cfg := xdbgConfig{
		IPAddress: "127.0.0.1", Port: 19095, AutoStart: true,
		AuthToken: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	body, _ := json.Marshal(cfg)
	if err := os.WriteFile(filepath.Join(x32.Base, "mcp_config.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(x64.Base, "mcp_config.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureXDBGConfig(root, x64); err == nil {
		t.Fatal("shared x32/x64 MCP port was accepted")
	}
}
