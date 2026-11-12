package remoteagent

import "testing"

func TestOperationLedgerQuotaRejectsNewReceiptsAtLimit(t *testing.T) {
	if err := ensureOperationLedgerQuota(OperationStats{Total: MaxOperationReceipts - 1}); err != nil {
		t.Fatal(err)
	}
	if err := ensureOperationLedgerQuota(OperationStats{Total: MaxOperationReceipts}); err == nil {
		t.Fatal("operation ledger quota accepted a new receipt at the hard limit")
	}
}
