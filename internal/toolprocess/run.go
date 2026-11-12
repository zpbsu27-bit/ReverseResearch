// Package toolprocess owns bounded direct-child execution for static tool
// adapters. It does not resolve tools, authorize targets or persist jobs.
package toolprocess

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"time"
)

type Result struct {
	Stdout, Stderr []byte
	ExitCode       int
	Err            error
	Truncated      bool
}

// Run retains a bounded prefix while draining the child's output. The caller
// owns the deadline and rejects Truncated; WaitDelay bounds inherited pipes.
// Cancellation kills this direct child, not an arbitrary process tree.
func Run(ctx context.Context, executable string, args []string, stdoutLimit, stderrLimit int, directory string) Result {
	if stdoutLimit < 1 || stderrLimit < 1 || stdoutLimit > 32<<20 || stderrLimit > 32<<20 {
		return Result{ExitCode: -1, Err: errors.New("invalid static tool output limits")}
	}
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Dir = directory
	cmd.WaitDelay = time.Second
	stdout, stderr := cappedBuffer{limit: stdoutLimit}, cappedBuffer{limit: stderrLimit}
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	exitCode := 0
	if err != nil {
		exitCode = -1
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		}
	}
	return Result{Stdout: stdout.buffer.Bytes(), Stderr: stderr.buffer.Bytes(), ExitCode: exitCode,
		Err: err, Truncated: stdout.truncated || stderr.truncated}
}

type cappedBuffer struct {
	buffer    bytes.Buffer
	limit     int
	truncated bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remaining := max(0, b.limit-b.buffer.Len())
	_, _ = b.buffer.Write(p[:min(n, remaining)])
	if n > remaining {
		b.truncated = true
	}
	return n, nil
}
