package core

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"reverseresearch/internal/packregistry"
)

func TestP3PersistentPackRegistrySeparatesTrustFromVerification(t *testing.T) {
	root, _ := isolatedCoreRoot(t)
	service, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(nil)
	state, err := service.TrustPackPublisher(PackRegistryTrustRequest{AuthorityRole: "owner", KeyID: "lab", PublicKey: base64.StdEncoding.EncodeToString(pub), Publisher: "Lab"})
	if err != nil {
		t.Fatal(err)
	}
	if state.Revision == "" {
		t.Fatal("registry revision missing")
	}
	if _, err := service.TrustPackPublisher(PackRegistryTrustRequest{AuthorityRole: "analyst", ExpectedRevision: state.Revision, KeyID: "other", PublicKey: base64.StdEncoding.EncodeToString(pub), Publisher: "Other"}); err == nil {
		t.Fatal("analyst modified trust root")
	}

	packRoot := filepath.Join(root, "pack")
	if err := os.MkdirAll(packRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packRoot, "data.txt"), []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := packregistry.Build(packRoot, packregistry.Manifest{ID: "demo", PackVersion: "1", Kind: "plugin", Publisher: "Lab", PublicKeyID: "lab"})
	if err != nil {
		t.Fatal(err)
	}
	m, err = packregistry.Sign(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "manifest.json")
	body, _ := json.Marshal(m)
	if err := os.WriteFile(manifestPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	verified, err := service.VerifyAndRecordPack(PackRegistryVerifyRequest{AuthorityRole: "analyst", ExpectedRevision: state.Revision, Root: packRoot, ManifestPath: manifestPath})
	if err != nil {
		t.Fatal(err)
	}
	if verified.Receipt.ID == "" || verified.Receipt.RegistryRevision == "" || len(verified.State.Receipts) != 1 {
		t.Fatalf("verified=%+v", verified)
	}
	read, err := service.GetPackRegistry(PackRegistryGetRequest{AuthorityRole: "viewer"})
	if err != nil {
		t.Fatal(err)
	}
	if len(read.TrustedKeys) != 1 || len(read.Receipts) != 1 {
		t.Fatalf("state=%+v", read)
	}

	removed, err := service.RemoveTrustedPackPublisher(PackRegistryRemoveRequest{AuthorityRole: "owner", ExpectedRevision: read.Revision, KeyID: "lab"})
	if err != nil {
		t.Fatal(err)
	}
	if len(removed.TrustedKeys) != 0 {
		t.Fatalf("trusted keys=%+v", removed.TrustedKeys)
	}
}
