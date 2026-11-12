package consolelog

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

func TestTunnelLineClassification(t *testing.T) {
	tests := []struct {
		name string
		line string
		want Color
	}{
		{"error", "time=x level=ERROR msg=failed", ColorRed},
		{"warning", "time=x level=WARN msg=retrying", ColorYellow},
		{"reported warning with error cause", `time=2026-10-13T03:08:30.787+08:00 level=WARN msg="poll failed; backing off" component=controlplane error="controlplane client: poll transport failed (network_error)" retry_in_ms=268`, ColorYellow},
		{"reported timeout", `time=x level=WARN msg="poll timed out; backing off" error="controlplane client: poll transport failed (timeout)"`, ColorYellow},
		{"message cannot override level", `time=x level=INFO msg="diagnostic contains level=ERROR error=failed"`, ColorWhite},
		{"later attribute cannot override level", `time=x level=WARN msg=retrying cause="level=ERROR" error=failed`, ColorYellow},
		{"info with error attribute", `time=x level=INFO msg="request canceled" error=canceled`, ColorWhite},
		{"unstructured error", `producer error=failed`, ColorRed},
		{"recovery", `time=x level=INFO msg="poller recovered; polling operational" component=controlplane`, ColorGreen},
		{"metadata", "time=x level=INFO msg=\"tunnel metadata fetched\"", ColorGreen},
		{"route", "time=x level=INFO msg=\"control-plane route resolved\"", ColorStatus},
		{"poller", "time=x level=INFO msg=\"poller started\"", ColorStatus},
		{"tls", "time=x level=INFO msg=\"tls trust summary\"", ColorDim},
		{"ordinary", "time=x level=INFO msg=\"TunnelServiceClient created\"", ColorWhite},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyTunnelLine(tc.line); got != tc.want {
				t.Fatalf("classifyTunnelLine()=%d want=%d", got, tc.want)
			}
		})
	}
}

func testTunnelLog(output io.Writer) *TunnelLog {
	w := TunnelWriter()
	w.writer = output
	return w
}

func TestTunnelLogReplaysFailureRecoveryWithoutChangingProtocolResults(t *testing.T) {
	var output bytes.Buffer
	w := testTunnelLog(&output)
	if got := w.Snapshot(); got.LastEvent != "" || got.PollFailures != 0 || !strings.Contains(got.Summary(), "等待首次轮询结果") {
		t.Fatalf("new observer has fabricated a success: %+v", got)
	}
	w.ObserveReady()
	if got := w.Snapshot(); got.LastEvent != "first_poll_ok" || got.ObservedAt.IsZero() {
		t.Fatalf("first SDK poll was not observed: %+v", got)
	}
	logger := slog.New(slog.NewTextHandler(w, nil))
	logger.Warn("poll timed out; backing off", "error", "controlplane client: poll transport failed (timeout)", "retry_in_ms", 200)
	logger.Warn("poll failed; backing off", "error", "controlplane client: poll transport failed (network_error)", "retry_in_ms", 10000)
	logger.Warn("unrelated warning", "error", "other failure")
	failed := w.Snapshot()
	if failed.LastEvent != "poll_retry" || failed.PollFailures != 2 || failed.FailureKind != "network_error" || !strings.Contains(failed.Summary(), "网络错误") {
		t.Fatalf("SDK failures are missing from the independent observation: %+v", failed)
	}
	w.ObserveReady()
	if got := w.Snapshot(); got != failed {
		t.Fatalf("delayed one-time Ready erased a subsequent failure: %+v", got)
	}
	logger.Info("diagnostic says poller recovered; polling operational")
	if got := w.Snapshot(); got != failed {
		t.Fatalf("unrelated message fabricated recovery: %+v", got)
	}
	logger.Info("poller recovered; polling operational")
	recovered := w.Snapshot()
	if recovered.LastEvent != "poll_recovered" || recovered.PollFailures != 2 || recovered.FailureKind != "" || !strings.Contains(recovered.Summary(), "最近观测") {
		t.Fatalf("SDK recovery event did not retain cumulative failures: %+v", recovered)
	}
	logger.Info("poller stopped", "reason", "context canceled")
	if got := w.Snapshot(); got.LastEvent != "poll_stopped" || got.PollFailures != 2 {
		t.Fatalf("SDK stop event missing: %+v", got)
	}
	if got := output.String(); strings.Contains(got, "[错误]") || strings.Count(got, "[警告] [TUNNEL]") != 3 || !strings.Contains(got, "[完成] [TUNNEL]") {
		t.Fatalf("SDK levels were not preserved in the actual writer: %q", got)
	}
}

func TestTunnelLogOnlyObservesCompleteLines(t *testing.T) {
	w := testTunnelLog(io.Discard)
	line := `time=x level=WARN msg="poll failed; backing off" error="controlplane client: poll transport failed (network_error)"`
	for _, fragment := range []string{line[:20], line[20:]} {
		if _, err := io.WriteString(w, fragment); err != nil {
			t.Fatal(err)
		}
	}
	if got := w.Snapshot(); got.PollFailures != 0 {
		t.Fatalf("partial line was counted: %+v", got)
	}
	_, _ = io.WriteString(w, "\r\n")
	if got := w.Snapshot(); got.PollFailures != 1 || got.FailureKind != "network_error" {
		t.Fatalf("complete fragmented line was not counted once: %+v", got)
	}
}

func TestTunnelLogConcurrentSnapshotsAndWriters(t *testing.T) {
	w := testTunnelLog(io.Discard)
	const count = 32
	var workers sync.WaitGroup
	for i := range count {
		workers.Go(func() {
			_, _ = fmt.Fprintf(w, "time=x level=WARN msg=\"poll failed; backing off\" error=failed retry_in_ms=%d\n", i)
			w.ObserveReady()
			_ = w.Snapshot().Summary()
		})
	}
	workers.Wait()
	if got := w.Snapshot(); got.PollFailures != count || got.LastEvent != "poll_retry" {
		t.Fatalf("concurrent projection lost SDK events: %+v", got)
	}
}

func TestLineWriterBoundsUnterminatedLine(t *testing.T) {
	var output bytes.Buffer
	writer := &lineWriter{writer: &output, classify: func(string) Color { return ColorWhite }}
	payload := bytes.Repeat([]byte{'x'}, maxTunnelLineBytes*4)
	if n, err := writer.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("Write() = %d, %v; want %d, nil", n, err, len(payload))
	}
	if got := writer.buffer.Len(); got != maxTunnelLineBytes {
		t.Fatalf("buffer length = %d, want %d", got, maxTunnelLineBytes)
	}
	if !writer.truncated {
		t.Fatal("oversized unterminated line was not marked truncated")
	}
}

func TestLineWriterFlushesTruncatedLineAndRecovers(t *testing.T) {
	var output bytes.Buffer
	writer := &lineWriter{writer: &output, classify: func(string) Color { return ColorWhite }}
	payload := append(bytes.Repeat([]byte{'a'}, maxTunnelLineBytes+1024), '\n')
	payload = append(payload, []byte("next\n")...)
	if _, err := writer.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	if !strings.Contains(got, "line truncated at 65536 bytes") {
		t.Fatalf("missing truncation marker: %q", got)
	}
	if !strings.Contains(got, "next") {
		t.Fatalf("writer did not recover after oversized line: %q", got)
	}
	if writer.buffer.Len() != 0 || writer.truncated {
		t.Fatalf("writer retained state after complete lines: len=%d truncated=%t", writer.buffer.Len(), writer.truncated)
	}
}
