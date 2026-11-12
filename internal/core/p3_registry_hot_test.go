package core

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"reverseresearch/internal/packregistry"
)

func TestPackRegistryGetDefaultsToHotAndArchivedIsExplicit(t *testing.T) {
	root := t.TempDir()
	service, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := service.packRegistryStore()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.GetHot(); err != nil {
		t.Fatal(err)
	}

	receipt := packregistry.Receipt{
		ID: "receipt_cold_test", PackID: "cold-demo", PackVersion: "1",
		VerifiedUTC: time.Now().UTC().Format(time.RFC3339Nano),
	}
	body, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	body = append(body, '\n')
	sum := sha256.Sum256([]byte(receipt.ID))
	shard := fmt.Sprintf("%02x", sum[0])
	path := filepath.Join(root, "state", "pack-registry", "archive", "receipts", shard, receipt.ID+".json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}

	hot, err := service.GetPackRegistry(PackRegistryGetRequest{AuthorityRole: "viewer"})
	if err != nil {
		t.Fatal(err)
	}
	if len(hot.Receipts) != 0 {
		t.Fatalf("default registry get hydrated cold receipts: %+v", hot.Receipts)
	}
	full, err := service.GetPackRegistry(PackRegistryGetRequest{AuthorityRole: "viewer", IncludeArchived: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(full.Receipts) != 1 || full.Receipts[0].ID != receipt.ID {
		t.Fatalf("explicit archived get receipts=%+v", full.Receipts)
	}
}
