package remoteagent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOperationLedgerCompletionReserveIsRestored(t *testing.T) {
	ledger, err := NewOperationLedger(filepath.Join(t.TempDir(), "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	assertReserve := func() {
		t.Helper()
		info, err := os.Stat(ledger.completionReservePath())
		if err != nil {
			t.Fatalf("completion reserve missing: %v", err)
		}
		if info.Size() < OperationCompletionReserveBytes {
			t.Fatalf("completion reserve size=%d want>=%d", info.Size(), OperationCompletionReserveBytes)
		}
	}
	assertReserve()

	job := JobRequest{Version: 1, JobID: "reserve", OperationID: "op:reserve", Capability: "artifact.hash", Target: "x"}
	if _, err := ledger.Begin(job); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Complete(job.OperationID, "applied"); err != nil {
		t.Fatal(err)
	}
	assertReserve()
}

// A receipt abandoned in "running" by a crash must not wedge the operation id
// forever, and must not keep stats.Running inflated.
func TestOperationLedgerSettlesAbandonedRunningReceipt(t *testing.T) {
	ledger, err := NewOperationLedger(filepath.Join(t.TempDir(), "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	job := JobRequest{Version: 1, JobID: "j1", OperationID: "op:abandoned", Capability: "artifact.hash", Target: "x"}
	if _, err := ledger.Begin(job); err != nil {
		t.Fatal(err)
	}

	receipt, err := ledger.read(job.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	receipt.CreatedUTC = time.Now().UTC().Add(-StaleRunningOperationAfter - time.Minute).Format(time.RFC3339Nano)
	if err := ledger.write(receipt); err != nil {
		t.Fatal(err)
	}

	settled, err := ledger.Begin(job)
	if !errors.Is(err, ErrOperationExists) {
		t.Fatalf("expected already-recorded error, got %v", err)
	}
	if settled.State != "uncertain" || settled.CompletedUTC == "" {
		t.Fatalf("abandoned receipt was not settled: %+v", settled)
	}

	stats, err := ledger.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Running != 0 || stats.Uncertain != 1 || stats.Total != 1 {
		t.Fatalf("stats did not account for the settlement: %+v", stats)
	}
}

// One damaged receipt must not make every remote operation fail.
func TestOperationLedgerStatsSkipsCorruptReceipt(t *testing.T) {
	ledger, err := NewOperationLedger(filepath.Join(t.TempDir(), "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Begin(JobRequest{Version: 1, JobID: "j1", OperationID: "op:good", Capability: "artifact.hash", Target: "x"}); err != nil {
		t.Fatal(err)
	}
	corrupt := filepath.Join(ledger.root, "receipts", "zz", "0000000000000000000000000000000000000000000000000000000000000000.json")
	if err := os.MkdirAll(filepath.Dir(corrupt), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(corrupt, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ledger.statsDirtyPath(), []byte("dirty\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	stats, err := ledger.Stats()
	if err != nil {
		t.Fatalf("one corrupt receipt must not fail stats: %v", err)
	}
	if stats.Total != 1 || stats.Unreadable != 1 {
		t.Fatalf("stats=%+v", stats)
	}
	if _, err := ledger.Begin(JobRequest{Version: 1, JobID: "j2", OperationID: "op:other", Capability: "artifact.hash", Target: "y"}); err != nil {
		t.Fatalf("new operations must survive a corrupt receipt: %v", err)
	}
}

// A live operation inside the stale window must never be settled.
func TestOperationLedgerKeepsFreshRunningReceipt(t *testing.T) {
	ledger, err := NewOperationLedger(filepath.Join(t.TempDir(), "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	job := JobRequest{Version: 1, JobID: "j1", OperationID: "op:live", Capability: "artifact.hash", Target: "x"}
	if _, err := ledger.Begin(job); err != nil {
		t.Fatal(err)
	}
	receipt, err := ledger.Begin(job)
	if !errors.Is(err, ErrOperationExists) {
		t.Fatalf("expected already-recorded, got %v", err)
	}
	if receipt.State != "running" {
		t.Fatalf("fresh running receipt was settled early: %+v", receipt)
	}
	if _, err := ledger.Complete(job.OperationID, "applied"); err != nil {
		t.Fatalf("a live operation must still be completable: %v", err)
	}
}

func TestOperationLedgerCompletionIsSameStateReplaySafe(t *testing.T) {
	ledger, err := NewOperationLedger(filepath.Join(t.TempDir(), "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	job := JobRequest{Version: 1, JobID: "j1", OperationID: "op:replay", Capability: "artifact.hash", Target: "x"}
	if _, err := ledger.Begin(job); err != nil {
		t.Fatal(err)
	}
	first, err := ledger.Complete(job.OperationID, "applied")
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := ledger.Complete(job.OperationID, "applied")
	if err != nil {
		t.Fatalf("same-state completion replay failed: %v", err)
	}
	if replayed.State != first.State || replayed.CompletedUTC != first.CompletedUTC {
		t.Fatalf("completion replay changed receipt: first=%+v replay=%+v", first, replayed)
	}
	if _, err := ledger.Complete(job.OperationID, "failed"); err == nil {
		t.Fatal("different terminal state replay was accepted")
	}
}

func TestOperationLedgerCompletionRecoverySurvivesCanceledRequest(t *testing.T) {
	ledger, err := NewOperationLedger(filepath.Join(t.TempDir(), "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	job := JobRequest{Version: 1, JobID: "j1", OperationID: "op:cancelled-request", Capability: "artifact.hash", Target: "x"}
	if _, err := ledger.Begin(job); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ledger.CompleteContext(ctx, job.OperationID, "applied"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled completion err=%v want context.Canceled", err)
	}
	recovered, err := ledger.CompleteWithRecovery(ctx, job.OperationID, "applied")
	if err != nil {
		t.Fatalf("detached completion recovery failed: %v", err)
	}
	if recovered.State != "applied" || recovered.CompletedUTC == "" {
		t.Fatalf("recovered receipt=%+v", recovered)
	}
	stats, err := ledger.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Running != 0 || stats.Applied != 1 || stats.Total != 1 {
		t.Fatalf("recovered stats=%+v", stats)
	}
}
