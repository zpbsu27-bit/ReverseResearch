package recordio

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var ErrShardQuota = errors.New("durable shard quota exceeded")

// WriteFileShardQuota atomically writes one durable file while enforcing a
// bounded file-count and byte budget for its direct parent shard. Hidden
// housekeeping files are excluded from the budget. The quota check and publish
// are serialized by a shard-local OS lock, so independent processes cannot
// race through the limit.
func WriteFileShardQuota(path string, body []byte, mode os.FileMode, maxFiles int, maxBytes int64) error {
	return WriteFileShardQuotaContext(context.Background(), path, body, mode, maxFiles, maxBytes)
}

// WriteFileShardQuotaContext is the request-driven variant. Cancellation only
// applies while waiting for the shard quota lock; once publishing starts the
// atomic record write is allowed to finish so cancellation cannot create a
// half-published durable record.
func WriteFileShardQuotaContext(ctx context.Context, path string, body []byte, mode os.FileMode, maxFiles int, maxBytes int64) (err error) {
	if err := validateShardQuota(maxFiles, maxBytes, int64(len(body))); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	release, err := AcquireContext(ctx, filepath.Join(dir, ".quota.lock"), 10*time.Second)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, release()) }()

	if err := checkShardQuotaUnlocked(path, int64(len(body)), maxFiles, maxBytes); err != nil {
		return err
	}
	return WriteFile(path, body, mode)
}

// CheckShardQuota verifies that target could be written at reservedBytes
// without exceeding the shard budget. It is useful before an irreversible
// effect when the eventual receipt must be guaranteed room. Callers that need
// the reservation to remain stable must also hold their own higher-level lock
// across this check and the eventual write.
func CheckShardQuota(path string, reservedBytes int64, maxFiles int, maxBytes int64) error {
	return CheckShardQuotaContext(context.Background(), path, reservedBytes, maxFiles, maxBytes)
}

// CheckShardQuotaContext lets request-driven preflight checks abandon a
// contended shard immediately when their caller is cancelled.
func CheckShardQuotaContext(ctx context.Context, path string, reservedBytes int64, maxFiles int, maxBytes int64) (err error) {
	if err := validateShardQuota(maxFiles, maxBytes, reservedBytes); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	release, err := AcquireContext(ctx, filepath.Join(dir, ".quota.lock"), 10*time.Second)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, release()) }()
	return checkShardQuotaUnlocked(path, reservedBytes, maxFiles, maxBytes)
}

func validateShardQuota(maxFiles int, maxBytes, bodyBytes int64) error {
	if maxFiles < 1 || maxBytes < 1 {
		return errors.New("durable shard quota must be positive")
	}
	if bodyBytes < 0 || bodyBytes > maxBytes {
		return fmt.Errorf("%w: record bytes=%d max_shard_bytes=%d", ErrShardQuota, bodyBytes, maxBytes)
	}
	return nil
}

func checkShardQuotaUnlocked(path string, newBytes int64, maxFiles int, maxBytes int64) error {
	dir := filepath.Dir(path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	targetName := filepath.Base(path)
	files := 0
	var bytesUsed int64
	var existingBytes int64
	exists := false
	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			continue
		}
		if info.Size() < 0 || bytesUsed > maxBytes-info.Size() {
			return fmt.Errorf("%w: shard already exceeds byte budget", ErrShardQuota)
		}
		files++
		bytesUsed += info.Size()
		if entry.Name() == targetName {
			exists = true
			existingBytes = info.Size()
		}
		if files > maxFiles || bytesUsed > maxBytes {
			return fmt.Errorf("%w: shard usage files=%d/%d bytes=%d/%d", ErrShardQuota, files, maxFiles, bytesUsed, maxBytes)
		}
	}
	nextFiles := files
	if !exists {
		nextFiles++
	}
	nextBytes := bytesUsed - existingBytes
	if newBytes > maxBytes-nextBytes {
		return fmt.Errorf("%w: shard bytes=%d+%d max=%d", ErrShardQuota, nextBytes, newBytes, maxBytes)
	}
	if nextFiles > maxFiles {
		return fmt.Errorf("%w: shard files=%d max=%d", ErrShardQuota, nextFiles, maxFiles)
	}
	return nil
}
