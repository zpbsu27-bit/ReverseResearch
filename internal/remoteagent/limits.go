package remoteagent

import "time"

const (
	MaxRegistrationRecordBytes      = 1 << 20
	MaxStatusRecordBytes            = 2 << 20
	MaxOperationReceiptBytes        = 64 << 10
	MaxOperationStatsCacheBytes     = 64 << 10
	MaxOperationReceipts            = 65536
	OperationCompletionReserveBytes = 256 << 10
	MaxTLSPEMBytes                  = int64(4 << 20)

	// DefaultJobExecutionWindow bounds a job that carries no deadline, so an
	// omitted deadline can never mean "run until the agent is restarted".
	DefaultJobExecutionWindow = 30 * time.Minute

	// OperationCompletionRecoveryWindow is a single bounded detached retry used
	// only after a capability effect has finished and the terminal receipt could
	// not be persisted through the request context.
	OperationCompletionRecoveryWindow = 5 * time.Second

	// StaleRunningOperationAfter settles a receipt left in "running" by a crash
	// or a killed agent. It must stay well above DefaultJobExecutionWindow so a
	// live operation is never mistaken for an abandoned one.
	StaleRunningOperationAfter = 2 * time.Hour

	// MaxUnreadableReceiptsReported bounds how many broken receipts a stats
	// rebuild describes before collapsing into a count.
	MaxUnreadableReceiptsReported = 8
)
