package remoteagent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"reverseresearch/internal/recordio"
)

var safeOperationID = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)

var ErrOperationExists = errors.New("remote operation already recorded")

type OperationReceipt struct {
	Version       int    `json:"version"`
	OperationID   string `json:"operation_id"`
	JobID         string `json:"job_id"`
	Capability    string `json:"capability"`
	Target        string `json:"target"`
	RequestSHA256 string `json:"request_sha256"`
	State         string `json:"state"`
	CreatedUTC    string `json:"created_utc"`
	CompletedUTC  string `json:"completed_utc,omitempty"`
}

type OperationLedger struct{ root string }

func NewOperationLedger(root string) (*OperationLedger, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("operation ledger root is required")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, err
	}
	for _, dir := range []string{"receipts", "locks"} {
		if err := os.MkdirAll(filepath.Join(abs, dir), 0o700); err != nil {
			return nil, err
		}
	}
	ledger := &OperationLedger{root: abs}
	if err := ledger.ensureCompletionReserve(); err != nil {
		return nil, fmt.Errorf("reserve remote operation completion capacity: %w", err)
	}
	return ledger, nil
}

func (l *OperationLedger) Begin(j JobRequest) (receipt OperationReceipt, err error) {
	return l.BeginContext(context.Background(), j)
}

func (l *OperationLedger) BeginContext(ctx context.Context, j JobRequest) (receipt OperationReceipt, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !safeOperationID.MatchString(j.OperationID) {
		return OperationReceipt{}, errors.New("operation_id contains unsafe characters")
	}
	body, _ := json.Marshal(j)
	sum := sha256.Sum256(body)
	requestSHA := hex.EncodeToString(sum[:])

	lockPath := l.lockPath(j.OperationID)
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		return OperationReceipt{}, err
	}
	release, err := recordio.AcquireContext(ctx, lockPath, 2*time.Second)
	if err != nil {
		return OperationReceipt{}, err
	}
	defer func() { err = errors.Join(err, release()) }()

	if existing, readErr := l.read(j.OperationID); readErr == nil {
		if existing.State == "running" {
			settled, changed, settleErr := l.settleStaleRunningContext(ctx, existing)
			if settleErr != nil {
				return existing, errors.Join(ErrOperationExists, fmt.Errorf("settle abandoned operation %s: %w", j.OperationID, settleErr))
			}
			if changed {
				existing = settled
			}
		}
		if existing.RequestSHA256 != requestSHA {
			return existing, fmt.Errorf("%w with different request identity", ErrOperationExists)
		}
		return existing, ErrOperationExists
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return OperationReceipt{}, readErr
	}

	statsRelease, err := recordio.AcquireContext(ctx, l.statsLockPath(), 2*time.Second)
	if err != nil {
		return OperationReceipt{}, err
	}
	defer func() { err = errors.Join(err, statsRelease()) }()

	stats, err := l.currentStatsUnlocked()
	if err != nil {
		return OperationReceipt{}, err
	}
	if err := ensureOperationLedgerQuota(stats); err != nil {
		return OperationReceipt{}, err
	}
	if err := l.markStatsDirtyUnlocked(); err != nil {
		return OperationReceipt{}, err
	}

	receipt = OperationReceipt{
		Version: 1, OperationID: j.OperationID, JobID: j.JobID,
		Capability: j.Capability, Target: j.Target, RequestSHA256: requestSHA,
		State: "running", CreatedUTC: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := l.write(receipt); err != nil {
		return OperationReceipt{}, err
	}

	stats.Total++
	stats.Running++
	l.finishStatsCacheBestEffortUnlocked(stats)
	return receipt, nil
}

// settleStaleRunning turns a receipt that a crash or a killed agent abandoned
// in "running" into a terminal "uncertain" record. Without this the operation
// id is refused as already recorded forever and stats.Running never drains.
// Only receipts older than StaleRunningOperationAfter are touched, so a live
// operation is never mistaken for an abandoned one.
func (l *OperationLedger) settleStaleRunningContext(ctx context.Context, existing OperationReceipt) (receipt OperationReceipt, changed bool, err error) {
	created, parseErr := time.Parse(time.RFC3339Nano, existing.CreatedUTC)
	if parseErr == nil && time.Since(created) <= StaleRunningOperationAfter {
		return existing, false, nil
	}

	statsRelease, err := recordio.AcquireContext(ctx, l.statsLockPath(), 2*time.Second)
	if err != nil {
		return existing, false, err
	}
	defer func() { err = errors.Join(err, statsRelease()) }()

	stats, err := l.currentStatsUnlocked()
	if err != nil {
		return existing, false, err
	}
	if err := l.markStatsDirtyUnlocked(); err != nil {
		return existing, false, err
	}

	settled := existing
	settled.State = "uncertain"
	settled.CompletedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	if err := l.write(settled); err != nil {
		return existing, false, err
	}
	if stats.Running > 0 {
		stats.Running--
	}
	incrementOperationState(&stats, "uncertain")
	l.finishStatsCacheBestEffortUnlocked(stats)
	return settled, true, nil
}

func (l *OperationLedger) completionReservePath() string {
	return filepath.Join(l.root, ".completion-reserve")
}

func (l *OperationLedger) ensureCompletionReserve() error {
	path := l.completionReservePath()
	if info, err := os.Stat(path); err == nil {
		if info.Mode().IsRegular() && info.Size() >= OperationCompletionReserveBytes {
			return nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return recordio.WriteFile(path, make([]byte, OperationCompletionReserveBytes), 0o600)
}

func (l *OperationLedger) borrowCompletionReserve() error {
	if err := os.Remove(l.completionReservePath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (l *OperationLedger) Complete(operationID, state string) (receipt OperationReceipt, err error) {
	return l.CompleteContext(context.Background(), operationID, state)
}

// CompleteWithRecovery gives post-effect receipt persistence one bounded
// detached retry. The retry is intentionally finite: it protects exactly-once
// evidence from request cancellation without turning disk/lock failure into an
// unbounded background loop.
func (l *OperationLedger) CompleteWithRecovery(ctx context.Context, operationID, state string) (OperationReceipt, error) {
	receipt, err := l.CompleteContext(ctx, operationID, state)
	if err == nil {
		return receipt, nil
	}
	recoveryCtx, cancel := context.WithTimeout(context.Background(), OperationCompletionRecoveryWindow)
	defer cancel()
	recovered, recoveryErr := l.CompleteContext(recoveryCtx, operationID, state)
	if recoveryErr == nil {
		return recovered, nil
	}
	return OperationReceipt{}, errors.Join(err, fmt.Errorf("detached operation completion retry failed: %w", recoveryErr))
}

func (l *OperationLedger) CompleteContext(ctx context.Context, operationID, state string) (receipt OperationReceipt, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !safeOperationID.MatchString(operationID) {
		return OperationReceipt{}, errors.New("invalid operation_id")
	}
	switch state {
	case "applied", "failed", "uncertain", "rolled_back", "cancelled":
	default:
		return OperationReceipt{}, fmt.Errorf("invalid completion state %q", state)
	}

	lockPath := l.lockPath(operationID)
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		return OperationReceipt{}, err
	}
	release, err := recordio.AcquireContext(ctx, lockPath, 2*time.Second)
	if err != nil {
		return OperationReceipt{}, err
	}
	defer func() { err = errors.Join(err, release()) }()

	receipt, err = l.read(operationID)
	if err != nil {
		return OperationReceipt{}, err
	}
	if receipt.State == state {
		return receipt, nil
	}
	if receipt.State != "running" {
		return OperationReceipt{}, fmt.Errorf("operation %s already terminal in %s", operationID, receipt.State)
	}

	statsRelease, err := recordio.AcquireContext(ctx, l.statsLockPath(), 2*time.Second)
	if err != nil {
		return OperationReceipt{}, err
	}
	defer func() { err = errors.Join(err, statsRelease()) }()

	// Completion happens after the external effect. Borrow a preallocated disk
	// reserve while the global stats lock excludes Begin/Complete writers, so a
	// filesystem that became full during execution still has room to publish the
	// terminal receipt. Recreate the reserve before returning; failure is surfaced
	// after the terminal state itself has been made durable.
	if err := l.borrowCompletionReserve(); err != nil {
		return OperationReceipt{}, fmt.Errorf("borrow operation completion reserve: %w", err)
	}
	defer func() { err = errors.Join(err, l.ensureCompletionReserve()) }()

	stats, err := l.currentStatsUnlocked()
	if err != nil {
		return OperationReceipt{}, err
	}
	if err := l.markStatsDirtyUnlocked(); err != nil {
		return OperationReceipt{}, err
	}

	receipt.State = state
	receipt.CompletedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	if err := l.write(receipt); err != nil {
		return OperationReceipt{}, err
	}

	if stats.Running > 0 {
		stats.Running--
	}
	incrementOperationState(&stats, state)
	l.finishStatsCacheBestEffortUnlocked(stats)
	return receipt, nil
}

func (l *OperationLedger) Get(operationID string) (OperationReceipt, error) {
	if !safeOperationID.MatchString(operationID) {
		return OperationReceipt{}, errors.New("invalid operation_id")
	}
	return l.read(operationID)
}

func (l *OperationLedger) Stats() (stats OperationStats, err error) {
	release, err := recordio.Acquire(l.statsLockPath(), 2*time.Second)
	if err != nil {
		return OperationStats{}, err
	}
	defer func() { err = errors.Join(err, release()) }()
	return l.currentStatsUnlocked()
}

func (l *OperationLedger) read(id string) (OperationReceipt, error) {
	body, err := recordio.ReadFileLimit(l.path(id), MaxOperationReceiptBytes)
	if errors.Is(err, os.ErrNotExist) {
		body, err = recordio.ReadFileLimit(l.legacyPath(id), MaxOperationReceiptBytes)
	}
	if err != nil {
		return OperationReceipt{}, err
	}
	var r OperationReceipt
	if err := json.Unmarshal(body, &r); err != nil {
		return OperationReceipt{}, err
	}
	if r.OperationID != id {
		return OperationReceipt{}, errors.New("operation receipt identity mismatch")
	}
	return r, nil
}

func ensureOperationLedgerQuota(stats OperationStats) error {
	if stats.Total >= MaxOperationReceipts {
		return fmt.Errorf("remote operation ledger durable quota exceeded: receipts=%d max=%d", stats.Total, MaxOperationReceipts)
	}
	return nil
}

func (l *OperationLedger) write(r OperationReceipt) error {
	body, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if len(body) > MaxOperationReceiptBytes {
		return fmt.Errorf("operation receipt exceeds durable size limit: %d > %d", len(body), MaxOperationReceiptBytes)
	}
	path := l.path(r.OperationID)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return recordio.WriteFile(path, body, 0o600)
}

func operationFileKey(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
}

func (l *OperationLedger) path(id string) string {
	key := operationFileKey(id)
	return filepath.Join(l.root, "receipts", key[:2], key+".json")
}

func (l *OperationLedger) legacyPath(id string) string {
	return filepath.Join(l.root, operationFileKey(id)+".json")
}

func (l *OperationLedger) lockPath(id string) string {
	key := operationFileKey(id)
	return filepath.Join(l.root, "locks", key[:2], key+".lock")
}
