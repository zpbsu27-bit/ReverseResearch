package remoteagent

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOperationLedgerStatsCacheAndDirtyRecovery(t *testing.T) {
	ledger, err := NewOperationLedger(filepath.Join(t.TempDir(), "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	first := JobRequest{Version: 1, JobID: "j1", OperationID: "op:1", Capability: "artifact.inspect", Target: "x"}
	second := JobRequest{Version: 1, JobID: "j2", OperationID: "op:2", Capability: "artifact.hash", Target: "y"}
	if _, err := ledger.Begin(first); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Begin(second); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Complete(first.OperationID, "applied"); err != nil {
		t.Fatal(err)
	}

	stats, err := ledger.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Total != 2 || stats.Running != 1 || stats.Applied != 1 {
		t.Fatalf("stats=%+v", stats)
	}
	if _, err := os.Stat(ledger.statsPath()); err != nil {
		t.Fatalf("stats cache missing: %v", err)
	}

	receipt, err := ledger.read(second.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	receipt.State = "failed"
	receipt.CompletedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	if err := ledger.write(receipt); err != nil {
		t.Fatal(err)
	}
	if err := ledger.markStatsDirtyUnlocked(); err != nil {
		t.Fatal(err)
	}

	stats, err = ledger.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Total != 2 || stats.Running != 0 || stats.Applied != 1 || stats.Failed != 1 {
		t.Fatalf("rebuilt stats=%+v", stats)
	}
	if _, err := os.Stat(ledger.statsDirtyPath()); !os.IsNotExist(err) {
		t.Fatalf("dirty marker was not cleared: %v", err)
	}
}

func TestOperationLedgerStatsRebuildsCorruptCache(t *testing.T) {
	ledger, err := NewOperationLedger(filepath.Join(t.TempDir(), "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	job := JobRequest{Version: 1, JobID: "j", OperationID: "op", Capability: "artifact.inspect", Target: "x"}
	if _, err := ledger.Begin(job); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ledger.statsPath(), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	stats, err := ledger.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Total != 1 || stats.Running != 1 {
		t.Fatalf("stats=%+v", stats)
	}
}
