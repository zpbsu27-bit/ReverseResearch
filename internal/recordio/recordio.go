// Package recordio supplies cooperating-process locks and replacement-safe local records.
// It is independent of MCP. Locks are attached to stable sidecar files, not to
// replaceable JSON files; the sidecars must not be deleted while clients run.
package recordio

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"reverseresearch/internal/securefile"
)

var ErrBusy = errors.New("record is locked by another writer")

// Acquire serializes independent CLI processes and in-process clients. The OS
// releases the lock on process exit; an empty sidecar does not mean a stale lock.
func Acquire(path string, wait time.Duration) (func() error, error) {
	return AcquireContext(context.Background(), path, wait)
}

// AcquireContext is the cancellable lock primitive used by request-driven paths.
// Contended waiters exponentially back off instead of waking every 5ms forever.
func AcquireContext(ctx context.Context, path string, wait time.Duration) (func() error, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open record lock: %w", err)
	}
	if err := securefile.RestrictFile(path); err != nil {
		return nil, errors.Join(fmt.Errorf("restrict record lock: %w", err), file.Close())
	}

	deadline := time.Now().Add(wait)
	backoff := 5 * time.Millisecond
	const maxBackoff = 100 * time.Millisecond
	for {
		if err := ctx.Err(); err != nil {
			return nil, errors.Join(err, file.Close())
		}
		locked, err := tryLock(file)
		if err != nil {
			return nil, errors.Join(fmt.Errorf("lock record: %w", err), file.Close())
		}
		if locked {
			var once sync.Once
			var releaseErr error
			return func() error {
				once.Do(func() { releaseErr = errors.Join(unlock(file), file.Close()) })
				return releaseErr
			}, nil
		}
		if wait <= 0 || !time.Now().Before(deadline) {
			return nil, errors.Join(fmt.Errorf("%w: %s", ErrBusy, path), file.Close())
		}

		delay := backoff
		if remaining := time.Until(deadline); remaining < delay {
			delay = remaining
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil, errors.Join(ctx.Err(), file.Close())
		case <-timer.C:
		}
		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

// WriteStream atomically publishes a record without first materializing the
// complete encoded body in memory. The writer must finish successfully before
// fsync/rename makes the new record visible.
func WriteStream(path string, mode os.FileMode, write func(io.Writer) error) (err error) {
	if write == nil {
		return errors.New("record stream writer is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".rr-record-*")
	if err != nil {
		return err
	}
	name := temp.Name()
	closed := false
	defer func() {
		var cleanupErr error
		if !closed {
			cleanupErr = errors.Join(cleanupErr, temp.Close())
		}
		if removeErr := os.Remove(name); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			cleanupErr = errors.Join(cleanupErr, removeErr)
		}
		err = errors.Join(err, cleanupErr)
	}()

	if err := write(temp); err != nil {
		return err
	}
	if err := temp.Chmod(mode); err != nil {
		return err
	}
	if mode.Perm()&0o077 == 0 {
		if err := securefile.RestrictFile(name); err != nil {
			return err
		}
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	closed = true
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("publish streamed record (previous record retained): %w", err)
	}
	return nil
}

// WriteFile flushes a same-directory temporary file before replacing the record.
// A failed replacement never triggers deletion of the last committed record.
// Callers doing read-modify-write must hold a stable sidecar lock for the whole transaction.
func WriteFile(path string, body []byte, mode os.FileMode) error {
	return writeFileWithPublisher(path, body, mode, os.Rename)
}

func writeFileWithPublisher(path string, body []byte, mode os.FileMode, publish func(string, string) error) (err error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".rr-record-*")
	if err != nil {
		return err
	}
	name := temp.Name()
	closed := false
	defer func() {
		var cleanupErr error
		if !closed {
			cleanupErr = errors.Join(cleanupErr, temp.Close())
		}
		if removeErr := os.Remove(name); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			cleanupErr = errors.Join(cleanupErr, removeErr)
		}
		err = errors.Join(err, cleanupErr)
	}()
	if _, err := temp.Write(body); err != nil {
		return err
	}
	if err := temp.Chmod(mode); err != nil {
		return err
	}
	if mode.Perm()&0o077 == 0 {
		if err := securefile.RestrictFile(name); err != nil {
			return err
		}
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	closed = true
	if err := publish(name, path); err != nil {
		return fmt.Errorf("publish record (previous record retained): %w", err)
	}
	return nil
}
