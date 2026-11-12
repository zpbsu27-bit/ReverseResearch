package modules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestX32CompletedReceiptMovesToShardedArchive(t *testing.T) {
	guard, _ := newTestX32Guard(t)
	receipt := x32MutationReceipt{
		OperationID:   "archive-op",
		RequestDigest: strings.Repeat("a", 64),
		Tool:          "Run", PID: 42,
		ProcessKey: strings.Repeat("b", 64),
		Owner:      "analysis-a", LeaseID: "lease-fixture",
		Status:     "prepared",
		CreatedUTC: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := guard.saveReceipt(receipt); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(guard.operationPath(receipt.OperationID)); err != nil {
		t.Fatalf("prepared hot receipt missing: %v", err)
	}

	receipt.Status = "completed"
	receipt.CompletedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	if err := guard.saveReceipt(receipt); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(guard.operationArchivePath(receipt.OperationID)); err != nil {
		t.Fatalf("completed archive missing: %v", err)
	}
	if _, err := os.Stat(guard.operationPath(receipt.OperationID)); !os.IsNotExist(err) {
		t.Fatalf("completed hot receipt was not removed: %v", err)
	}
	got, err := guard.loadReceipt(receipt.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "completed" || got.OperationID != receipt.OperationID {
		t.Fatalf("loaded receipt=%+v", got)
	}

	key := x32OperationKey(receipt.OperationID)
	wantShard := filepath.Join("locks", key[:2], key+".lock")
	if !strings.HasSuffix(guard.operationLockPath(receipt.OperationID), wantShard) {
		t.Fatalf("lock path=%s want suffix=%s", guard.operationLockPath(receipt.OperationID), wantShard)
	}
}

func TestX32CompletedReceiptArchiveIsImmutable(t *testing.T) {
	guard, _ := newTestX32Guard(t)
	receipt := x32MutationReceipt{
		OperationID: "immutable-op", Tool: "Run", Status: "completed",
		CreatedUTC: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := guard.saveReceipt(receipt); err != nil {
		t.Fatal(err)
	}
	changed := receipt
	changed.Tool = "StopDebug"
	if err := guard.saveReceipt(changed); err == nil {
		t.Fatal("changed completed receipt replaced immutable archive")
	}
}
