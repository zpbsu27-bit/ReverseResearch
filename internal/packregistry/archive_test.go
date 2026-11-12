package packregistry

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"reverseresearch/internal/recordio"
)

func TestRegistryCompactionArchivesHistoryAndHydratesFullState(t *testing.T) {
	registry, err := NewRegistry(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	state := freshRegistry()
	base := time.Now().UTC().Add(-time.Hour)

	totalReceipts := registryHotReceiptLimit + 44
	totalAudit := registryHotAuditLimit + 77
	for i := 0; i < totalReceipts; i++ {
		id := fmt.Sprintf("receipt_%04d", i)
		packID := fmt.Sprintf("pack_%04d", i)
		at := base.Add(time.Duration(i) * time.Second).Format(time.RFC3339Nano)
		state.Receipts = append(state.Receipts, Receipt{
			ID: id, PackID: packID, PackVersion: "1", Kind: "data",
			Publisher: "test", ManifestSHA256: fmt.Sprintf("%064x", i+1),
			RegistryRevision: "rev", Files: 1, VerifiedUTC: at,
		})
		state.Packs[id] = PackRecord{
			ReceiptID:   id,
			Manifest:    Manifest{ID: packID, PackVersion: "1"},
			Status:      "verified",
			VerifiedUTC: at,
		}
	}
	state.Active["pack_0000"] = "receipt_0000"
	active := state.Packs["receipt_0000"]
	active.Status = "active"
	state.Packs["receipt_0000"] = active

	for i := 0; i < totalAudit; i++ {
		state.Audit = append(state.Audit, AuditEvent{
			ID: fmt.Sprintf("audit_%04d", i), Action: "verify",
			PackID:     fmt.Sprintf("pack_%04d", i%totalReceipts),
			CreatedUTC: base.Add(time.Duration(i) * time.Millisecond).Format(time.RFC3339Nano),
		})
	}

	if err := registry.compactState(&state); err != nil {
		t.Fatal(err)
	}
	if len(state.Receipts) != registryHotReceiptLimit {
		t.Fatalf("hot receipts=%d want=%d", len(state.Receipts), registryHotReceiptLimit)
	}
	if len(state.Audit) != registryHotAuditLimit {
		t.Fatalf("hot audit=%d want=%d", len(state.Audit), registryHotAuditLimit)
	}
	if _, ok := state.Packs["receipt_0000"]; !ok {
		t.Fatal("active old pack record was archived")
	}
	if len(state.Packs) > registryHotPackLimit+len(state.Active) {
		t.Fatalf("hot packs=%d exceeds bound", len(state.Packs))
	}

	state.Version = RegistryVersion
	state.UpdatedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	state.Revision = registryRevision(state)
	body, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	body = append(body, '\n')
	if err := recordio.WriteFile(registry.path(), body, 0o600); err != nil {
		t.Fatal(err)
	}

	full, err := registry.Get()
	if err != nil {
		t.Fatal(err)
	}
	if len(full.Receipts) != totalReceipts {
		t.Fatalf("hydrated receipts=%d want=%d", len(full.Receipts), totalReceipts)
	}
	if len(full.Audit) != totalAudit {
		t.Fatalf("hydrated audit=%d want=%d", len(full.Audit), totalAudit)
	}
	if len(full.Packs) != totalReceipts {
		t.Fatalf("hydrated packs=%d want=%d", len(full.Packs), totalReceipts)
	}

	if _, ok, err := registry.lookupPackRecord(state, "receipt_0001"); err != nil {
		t.Fatal(err)
	} else if !ok {
		t.Fatal("archived pack record was not lookup-able by receipt id")
	}
}

func TestReceiptArchiveAllowsOnlyRevisionFill(t *testing.T) {
	registry, err := NewRegistry(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	receipt := Receipt{
		ID: "receipt_fixed", PackID: "demo", PackVersion: "1",
		ManifestSHA256: fmt.Sprintf("%064x", 1),
		VerifiedUTC:    time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := registry.writeReceiptArchive(receipt); err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(registry.archiveReceiptPath(receipt.ID)) == registry.archiveRoot("receipts") {
		t.Fatal("receipt archive was not sharded")
	}

	withRevision := receipt
	withRevision.RegistryRevision = "revision-1"
	if err := registry.writeReceiptArchive(withRevision); err != nil {
		t.Fatalf("revision fill failed: %v", err)
	}
	got, ok, err := registry.lookupReceipt(freshRegistry(), receipt.ID)
	if err != nil || !ok || got.RegistryRevision != "revision-1" {
		t.Fatalf("receipt=%+v ok=%v err=%v", got, ok, err)
	}

	changed := withRevision
	changed.PackVersion = "2"
	if err := registry.writeReceiptArchive(changed); err == nil {
		t.Fatal("changed receipt replaced immutable archive")
	}
	changedRevision := withRevision
	changedRevision.RegistryRevision = "revision-2"
	if err := registry.writeReceiptArchive(changedRevision); err == nil {
		t.Fatal("second registry revision replaced archived receipt")
	}
}

func TestReceiptArchiveReadsAndMigratesLegacyFlatFile(t *testing.T) {
	registry, err := NewRegistry(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	receipt := Receipt{
		ID: "receipt_legacy", PackID: "legacy", PackVersion: "1",
		RegistryRevision: "rev", VerifiedUTC: time.Now().UTC().Format(time.RFC3339Nano),
	}
	body, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	body = append(body, '\n')
	legacy := registry.legacyArchivePath("receipts", receipt.ID)
	if err := recordio.WriteFile(legacy, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := registry.lookupReceipt(freshRegistry(), receipt.ID); err != nil || !ok {
		t.Fatalf("legacy lookup ok=%v err=%v", ok, err)
	}
	if err := registry.writeReceiptArchive(receipt); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(registry.archiveReceiptPath(receipt.ID)); err != nil {
		t.Fatalf("sharded receipt missing: %v", err)
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatalf("legacy receipt was not removed: %v", err)
	}
}

func TestQuarantineCanLoadArchivedPackRecord(t *testing.T) {
	registry, err := NewRegistry(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const receiptID = "receipt_archived"
	record := PackRecord{
		ReceiptID:   receiptID,
		Manifest:    Manifest{ID: "demo", PackVersion: "1"},
		Status:      "verified",
		VerifiedUTC: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := registry.writePackArchive(receiptID, record); err != nil {
		t.Fatal(err)
	}

	state := freshRegistry()
	state.UpdatedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	state.Revision = registryRevision(state)
	body, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	body = append(body, '\n')
	if err := recordio.WriteFile(registry.path(), body, 0o600); err != nil {
		t.Fatal(err)
	}

	updated, quarantined, err := registry.Quarantine(state.Revision, receiptID, "bad")
	if err != nil {
		t.Fatal(err)
	}
	if quarantined.Status != "quarantined" || quarantined.QuarantineReason != "bad" {
		t.Fatalf("quarantined=%+v", quarantined)
	}
	if got, ok := updated.Packs[receiptID]; !ok || got.Status != "quarantined" {
		t.Fatalf("updated pack=%+v ok=%v", got, ok)
	}
}
