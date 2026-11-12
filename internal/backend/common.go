package backend

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reverseresearch/internal/securefile"
	"strings"
	"sync"
	"time"
)

const (
	backendLogMaxBytes = int64(16 << 20)
	backendLogMaxFiles = 5
)

// The backend lifecycle owns tree cleanup; a stdio transport keeps sole Wait ownership.
type preparedBackendProcess interface {
	claim(log io.Closer, ownWait bool) (func() error, error)
	abort(log io.Closer, started bool) error
}

type rotatingLog struct {
	mu       sync.Mutex
	dir      string
	path     string
	maxBytes int64
	maxFiles int
	file     *os.File
	size     int64
}

func openLog(root, name string) (*rotatingLog, error) {
	return openLogAt(filepath.Join(root, "evidence"), name)
}

func openLogAt(dir, name string) (*rotatingLog, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	log := &rotatingLog{
		dir: dir, path: filepath.Join(dir, name),
		maxBytes: backendLogMaxBytes, maxFiles: backendLogMaxFiles,
	}
	if err := log.openLocked(); err != nil {
		return nil, err
	}
	if log.size >= log.maxBytes {
		if err := log.rotateLocked(); err != nil {
			return nil, errors.Join(err, log.Close())
		}
	}
	return log, nil
}

func (l *rotatingLog) openLocked() error {
	// Backend logs carry the same privacy as durable records: they contain target
	// paths, endpoints and crash output, and must not be world-readable merely
	// because they are not JSON state.
	file, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if restrictErr := securefile.RestrictFile(l.path); restrictErr != nil {
		return errors.Join(fmt.Errorf("restrict backend log: %w", restrictErr), file.Close())
	}
	info, err := file.Stat()
	if err != nil {
		return errors.Join(err, file.Close())
	}
	l.file = file
	l.size = info.Size()
	return nil
}

func (l *rotatingLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return 0, os.ErrClosed
	}

	written := 0
	for len(p) > 0 {
		if l.size >= l.maxBytes {
			if err := l.rotateLocked(); err != nil {
				return written, err
			}
		}
		remaining := l.maxBytes - l.size
		chunkSize := int64(len(p))
		if chunkSize > remaining {
			chunkSize = remaining
		}
		n, err := l.file.Write(p[:int(chunkSize)])
		written += n
		l.size += int64(n)
		p = p[n:]
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}

func (l *rotatingLog) rotateLocked() error {
	if l.file != nil {
		if err := l.file.Close(); err != nil {
			return err
		}
		l.file = nil
	}
	if l.maxFiles > 0 {
		oldest := fmt.Sprintf("%s.%d", l.path, l.maxFiles)
		_ = os.Remove(oldest)
		for index := l.maxFiles - 1; index >= 1; index-- {
			from := fmt.Sprintf("%s.%d", l.path, index)
			to := fmt.Sprintf("%s.%d", l.path, index+1)
			_ = os.Remove(to)
			if err := os.Rename(from, to); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("rotate backend log %s: %w", filepath.Base(from), err)
			}
		}
		first := l.path + ".1"
		_ = os.Remove(first)
		if err := os.Rename(l.path, first); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("rotate backend log %s: %w", filepath.Base(l.path), err)
		}
	} else {
		_ = os.Remove(l.path)
	}
	return l.openLocked()
}

func (l *rotatingLog) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	return err
}

func prependPath(env []string, dir string) []string {
	for i, item := range env {
		if strings.HasPrefix(strings.ToUpper(item), "PATH=") {
			env[i] = "PATH=" + dir + string(os.PathListSeparator) + item[5:]
			return env
		}
	}
	return append(env, "PATH="+dir)
}

func closeOptional(log io.Closer) error {
	if log == nil {
		return nil
	}
	if err := log.Close(); err != nil {
		return fmt.Errorf("close backend log: %w", err)
	}
	return nil
}

func waitTCP(ctx context.Context, address string, deadline time.Duration, cmd *exec.Cmd) (result error) {
	if ctx == nil {
		ctx = context.Background()
	}
	alive, closeWatcher, err := openProcessWatcher(cmd)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, closeWatcher()) }()
	until := time.Now().Add(deadline)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if time.Now().After(until) {
			return fmt.Errorf("backend startup deadline exceeded waiting for %s", address)
		}
		running, err := alive()
		if err != nil {
			return fmt.Errorf("wait for backend process readiness: %w", err)
		}
		if !running {
			return fmt.Errorf("backend process exited before %s became ready", address)
		}
		dialCtx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
		conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", address)
		cancel()
		if err == nil {
			return conn.Close()
		}
		timer := time.NewTimer(min(150*time.Millisecond, time.Until(until)))
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}
