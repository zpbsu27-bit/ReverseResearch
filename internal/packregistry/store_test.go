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

func TestRegistryTrustCurrentnessAndVerificationReceipt(t *testing.T) {
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
	if state.Revision == "" || len(state.TrustedKeys) != 1 {
		t.Fatalf("state=%+v", state)
	}
	if _, err := registry.TrustKey("", "other", base64.StdEncoding.EncodeToString(pub), "Other"); err == nil {
		t.Fatal("existing registry mutated without expected revision")
	}

	packRoot := filepath.Join(root, "pack")
	if err := os.MkdirAll(packRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packRoot, "data.txt"), []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := Build(packRoot, Manifest{ID: "demo", PackVersion: "1", Kind: "plugin", Publisher: "Lab", PublicKeyID: "lab"})
	if err != nil {
		t.Fatal(err)
	}
	m, err = Sign(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("manifest-fixture")
	sum := sha256.Sum256(body)
	manifestSHA := hex.EncodeToString(sum[:])
	state, receipt, err := registry.VerifyAndRecord(packRoot, m, manifestSHA, state.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.ID == "" || receipt.RegistryRevision == "" || len(state.Receipts) != 1 {
		t.Fatalf("receipt=%+v state=%+v", receipt, state)
	}
	loaded, err := registry.Get()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Revision != state.Revision || loaded.Receipts[0].RegistryRevision == "" {
		t.Fatalf("loaded=%+v", loaded)
	}
}

func TestRegistryRemoveRequiresCurrentRevision(t *testing.T) {
	root := t.TempDir()
	registry, err := NewRegistry(filepath.Join(root, "registry"))
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _ := ed25519.GenerateKey(nil)
	state, err := registry.TrustKey("", "lab", base64.StdEncoding.EncodeToString(pub), "Lab")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.RemoveKey("stale", "lab"); err == nil {
		t.Fatal("stale registry revision accepted")
	}
	next, err := registry.RemoveKey(state.Revision, "lab")
	if err != nil {
		t.Fatal(err)
	}
	if len(next.TrustedKeys) != 0 {
		t.Fatalf("trusted keys=%+v", next.TrustedKeys)
	}
}
