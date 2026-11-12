package packregistry

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestPackLifecycleActivateUpdateRollbackQuarantineAndCurrentness(t *testing.T) {
	root := t.TempDir()
	registry, err := NewRegistry(filepath.Join(root, "registry"))
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(nil)
	state, err := registry.TrustKey("", "lab", base64.StdEncoding.EncodeToString(pub), "Lab")
	if err != nil {
		t.Fatal(err)
	}

	v1Root := filepath.Join(root, "v1")
	if err := os.MkdirAll(v1Root, 0o700); err != nil {
		t.Fatal(err)
	}
	v1Body := []byte("rules-v1")
	if err := os.WriteFile(filepath.Join(v1Root, "rules.json"), v1Body, 0o600); err != nil {
		t.Fatal(err)
	}
	v1, err := Build(v1Root, Manifest{
		ID: "rules.demo", PackVersion: "1.0.0", Kind: "knowledge", Publisher: "Lab", PublicKeyID: "lab",
		Capabilities: []string{"rules.read"},
		Entrypoints:  []Entrypoint{{Name: "rules", Kind: "rules", Path: "rules.json"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	v1, err = Sign(v1, priv)
	if err != nil {
		t.Fatal(err)
	}
	state, receipt1, err := registry.VerifyAndRecord(v1Root, v1, manifestFixtureSHA(v1), state.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if record := state.Packs[receipt1.ID]; record.Status != "verified" || !record.Policy.Activatable || !record.Policy.DataOnly {
		t.Fatalf("verified record=%+v", record)
	}
	state, active1, err := registry.Activate(state.Revision, receipt1.ID)
	if err != nil {
		t.Fatal(err)
	}
	if active1.Status != "active" || state.Active["rules.demo"] != receipt1.ID {
		t.Fatalf("active=%+v state=%+v", active1, state.Active)
	}
	entry, err := registry.ReadActiveEntrypoint("rules.demo", "rules", 1024)
	if err != nil {
		t.Fatal(err)
	}
	if string(entry.Body) != string(v1Body) || entry.ReceiptID != receipt1.ID {
		t.Fatalf("entry=%+v", entry)
	}

	if err := os.WriteFile(filepath.Join(v1Root, "rules.json"), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.ReadActiveEntrypoint("rules.demo", "rules", 1024); err == nil {
		t.Fatal("tampered active pack remained readable")
	}
	if err := os.WriteFile(filepath.Join(v1Root, "rules.json"), v1Body, 0o600); err != nil {
		t.Fatal(err)
	}

	v2Root := filepath.Join(root, "v2")
	if err := os.MkdirAll(v2Root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(v2Root, "rules.json"), []byte("rules-v2"), 0o600); err != nil {
		t.Fatal(err)
	}
	v2, err := Build(v2Root, Manifest{
		ID: "rules.demo", PackVersion: "2.0.0", Kind: "knowledge", Publisher: "Lab", PublicKeyID: "lab",
		Capabilities: []string{"rules.read"},
		Entrypoints:  []Entrypoint{{Name: "rules", Kind: "rules", Path: "rules.json"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	v2, err = Sign(v2, priv)
	if err != nil {
		t.Fatal(err)
	}
	state, receipt2, err := registry.VerifyAndRecord(v2Root, v2, manifestFixtureSHA(v2), state.Revision)
	if err != nil {
		t.Fatal(err)
	}
	state, _, err = registry.Activate(state.Revision, receipt2.ID)
	if err != nil {
		t.Fatal(err)
	}
	if state.Active["rules.demo"] != receipt2.ID || state.Packs[receipt1.ID].Status != "verified" {
		t.Fatalf("update state=%+v packs=%+v", state.Active, state.Packs)
	}
	state, rolled, err := registry.Rollback(state.Revision, "rules.demo", receipt1.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rolled.ReceiptID != receipt1.ID || state.Active["rules.demo"] != receipt1.ID {
		t.Fatalf("rollback=%+v active=%+v", rolled, state.Active)
	}
	state, quarantined, err := registry.Quarantine(state.Revision, receipt2.ID, "regression")
	if err != nil {
		t.Fatal(err)
	}
	if quarantined.Status != "quarantined" || quarantined.QuarantineReason != "regression" {
		t.Fatalf("quarantined=%+v", quarantined)
	}
	if _, _, err := registry.Activate(state.Revision, receipt2.ID); err == nil {
		t.Fatal("quarantined version reactivated")
	}
	if len(state.Audit) < 6 {
		t.Fatalf("audit=%+v", state.Audit)
	}
}

func TestExecutablePluginVerifiesButCannotActivateDataOnlyLoader(t *testing.T) {
	root := t.TempDir()
	registry, err := NewRegistry(filepath.Join(root, "registry"))
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(nil)
	state, err := registry.TrustKey("", "lab", base64.StdEncoding.EncodeToString(pub), "Lab")
	if err != nil {
		t.Fatal(err)
	}
	packRoot := filepath.Join(root, "plugin")
	if err := os.MkdirAll(packRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packRoot, "adapter.py"), []byte("print('adapter')"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, err := Build(packRoot, Manifest{
		ID: "plugin.demo", PackVersion: "1.0.0", Kind: "plugin", Publisher: "Lab", PublicKeyID: "lab",
		Capabilities: []string{"analysis"},
		Entrypoints:  []Entrypoint{{Name: "adapter", Kind: "mcp-adapter", Path: "adapter.py"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	manifest, err = Sign(manifest, priv)
	if err != nil {
		t.Fatal(err)
	}
	state, receipt, err := registry.VerifyAndRecord(packRoot, manifest, manifestFixtureSHA(manifest), state.Revision)
	if err != nil {
		t.Fatal(err)
	}
	record := state.Packs[receipt.ID]
	if record.Policy.Activatable || !record.Policy.RequiresAdapter {
		t.Fatalf("plugin policy=%+v", record.Policy)
	}
	if _, _, err := registry.Activate(state.Revision, receipt.ID); err == nil {
		t.Fatal("executable plugin activated by data-only loader")
	}
}

func TestPackDependenciesRequireExactActiveVersion(t *testing.T) {
	root := t.TempDir()
	registry, _ := NewRegistry(filepath.Join(root, "registry"))
	pub, priv, _ := ed25519.GenerateKey(nil)
	state, err := registry.TrustKey("", "lab", base64.StdEncoding.EncodeToString(pub), "Lab")
	if err != nil {
		t.Fatal(err)
	}
	build := func(id, version, content string, deps []Dependency) (string, Manifest) {
		t.Helper()
		dir := filepath.Join(root, id+"-"+version)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "data.json"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		m, err := Build(dir, Manifest{
			ID: id, PackVersion: version, Kind: "domain", Publisher: "Lab", PublicKeyID: "lab",
			Dependencies: deps, Entrypoints: []Entrypoint{{Name: "data", Kind: "data", Path: "data.json"}},
		})
		if err != nil {
			t.Fatal(err)
		}
		m, err = Sign(m, priv)
		if err != nil {
			t.Fatal(err)
		}
		return dir, m
	}
	baseRoot, base := build("base", "1.0.0", "base", nil)
	state, baseReceipt, err := registry.VerifyAndRecord(baseRoot, base, manifestFixtureSHA(base), state.Revision)
	if err != nil {
		t.Fatal(err)
	}
	depRoot, dep := build("dependent", "1.0.0", "dep", []Dependency{{ID: "base", Version: "1.0.0"}})
	state, depReceipt, err := registry.VerifyAndRecord(depRoot, dep, manifestFixtureSHA(dep), state.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := registry.Activate(state.Revision, depReceipt.ID); err == nil {
		t.Fatal("dependent activated without dependency")
	}
	state, _, err = registry.Activate(state.Revision, baseReceipt.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := registry.Activate(state.Revision, depReceipt.ID); err != nil {
		t.Fatal(err)
	}
}

func manifestFixtureSHA(m Manifest) string {
	body, _ := canonical(m)
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
