package packregistry

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestSignedPackVerificationAndTamperDetection(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "SKILL.md"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(nil)
	m, err := Build(root, Manifest{ID: "demo", PackVersion: "1.0.0", Kind: "skill", Publisher: "lab", PublicKeyID: "lab-key", Capabilities: []string{"analysis"}})
	if err != nil {
		t.Fatal(err)
	}
	m, err = Sign(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	trust := TrustStore{Keys: map[string]string{"lab-key": base64.StdEncoding.EncodeToString(pub)}}
	v, err := Verify(root, m, trust)
	if err != nil {
		t.Fatal(err)
	}
	if !v.Verified || v.Files != 1 {
		t.Fatalf("verification=%+v", v)
	}
	if err := os.WriteFile(filepath.Join(root, "SKILL.md"), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(root, m, trust); err == nil {
		t.Fatal("tampered pack verified")
	}
}
func TestUnsafeManifestPathRejected(t *testing.T) {
	root := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(nil)
	m := Manifest{Version: 1, ID: "x", PackVersion: "1", Kind: "plugin", Publisher: "p", PublicKeyID: "k", Files: []File{{Path: "../escape", SHA256: "00", Size: 0}}}
	m, _ = Sign(m, priv)
	if _, err := Verify(root, m, TrustStore{Keys: map[string]string{"k": base64.StdEncoding.EncodeToString(pub)}}); err == nil {
		t.Fatal("unsafe path accepted")
	}
}
