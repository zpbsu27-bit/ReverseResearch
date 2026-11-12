package die

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"reverseresearch/internal/targetidentity"
)

func TestNewFindsPinnedRuntimeFromAncestorWithoutChangingStateRoot(t *testing.T) {
	project := t.TempDir()
	runtimeDir := filepath.Join(project, "runtime", "die")
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(runtimeDir, "diec.exe")
	if err := os.WriteFile(exe, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	scratch := filepath.Join(project, ".tmp", "record-closeout", "smoke-fixture")
	if err := os.MkdirAll(scratch, 0o700); err != nil {
		t.Fatal(err)
	}
	adapter := New(scratch)
	if filepath.Clean(adapter.executable) != filepath.Clean(exe) {
		t.Fatalf("executable=%q want=%q", adapter.executable, exe)
	}
}

func TestScanReturnsStructuredPinnedResult(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "sample.exe")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(root, "diec.exe")
	if err := os.WriteFile(exe, []byte("tool"), 0o600); err != nil {
		t.Fatal(err)
	}
	toolIdentity, err := targetidentity.Inspect(exe)
	if err != nil {
		t.Fatal(err)
	}
	adapter := newAdapter(exe, "3.21", toolIdentity.SHA256, func(_ context.Context, _ string, args []string) runResult {
		if len(args) == 1 && args[0] == "-v" {
			return runResult{Stdout: []byte("die 3.21\r\n")}
		}
		return runResult{Stdout: []byte("{\"detects\":[{\"filetype\":\"PE64\",\"info\":\"\",\"offset\":\"0\",\"parentfilepart\":\"Header\",\"size\":\"7\",\"values\":[{\"info\":\"AMD64\",\"name\":\"Windows\",\"string\":\"Operation system: Windows\",\"type\":\"operation system\",\"version\":\"10\"}]}]}")}
	})
	report, err := adapter.Scan(context.Background(), target, ScanOptions{Verbose: true, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if report.Tool.Version != "3.21" || report.Tool.License != "MIT" || report.Tool.SHA256 != toolIdentity.SHA256 {
		t.Fatalf("tool=%+v", report.Tool)
	}
	if report.Target.SHA256 == "" || len(report.Detects) != 1 || report.Detects[0].FileType != "PE64" {
		t.Fatalf("report=%+v", report)
	}
	if len(report.Detects[0].Values) != 1 || report.Detects[0].Values[0].Type != "operation system" {
		t.Fatalf("values=%+v", report.Detects[0].Values)
	}
}

func TestScanRejectsMissingRuntime(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "sample.bin")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	adapter := New(root)
	_, err := adapter.Scan(context.Background(), target, ScanOptions{})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err=%v want ErrUnavailable", err)
	}
}

func TestScanRejectsRuntimeVersionMismatch(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "sample.bin")
	exe := filepath.Join(root, "diec.exe")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe, []byte("tool"), 0o600); err != nil {
		t.Fatal(err)
	}
	id, _ := targetidentity.Inspect(exe)
	adapter := newAdapter(exe, "3.21", id.SHA256, func(_ context.Context, _ string, _ []string) runResult {
		return runResult{Stdout: []byte("die 3.22\n")}
	})
	_, err := adapter.Scan(context.Background(), target, ScanOptions{})
	if !errors.Is(err, ErrVersionMismatch) {
		t.Fatalf("err=%v want ErrVersionMismatch", err)
	}
}

func TestScanTimesOut(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "sample.bin")
	exe := filepath.Join(root, "diec.exe")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe, []byte("tool"), 0o600); err != nil {
		t.Fatal(err)
	}
	id, _ := targetidentity.Inspect(exe)
	adapter := newAdapter(exe, "3.21", id.SHA256, func(ctx context.Context, _ string, args []string) runResult {
		if len(args) == 1 && args[0] == "-v" {
			return runResult{Stdout: []byte("die 3.21\n")}
		}
		<-ctx.Done()
		return runResult{Err: ctx.Err()}
	})
	_, err := adapter.Scan(context.Background(), target, ScanOptions{Timeout: 15 * time.Millisecond})
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("err=%v want ErrTimeout", err)
	}
}

func TestScanReportsAbnormalExit(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "sample.bin")
	exe := filepath.Join(root, "diec.exe")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe, []byte("tool"), 0o600); err != nil {
		t.Fatal(err)
	}
	id, _ := targetidentity.Inspect(exe)
	adapter := newAdapter(exe, "3.21", id.SHA256, func(_ context.Context, _ string, args []string) runResult {
		if len(args) == 1 && args[0] == "-v" {
			return runResult{Stdout: []byte("die 3.21\n")}
		}
		return runResult{ExitCode: 7, Stderr: []byte("fixture failure")}
	})
	_, err := adapter.Scan(context.Background(), target, ScanOptions{})
	if err == nil || !strings.Contains(err.Error(), "exit code 7") || !strings.Contains(err.Error(), "fixture failure") {
		t.Fatalf("unexpected err=%v", err)
	}
}

func TestScanRejectsTargetDriftDuringAnalysis(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "sample.bin")
	exe := filepath.Join(root, "diec.exe")
	if err := os.WriteFile(target, []byte("first-version"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe, []byte("tool"), 0o600); err != nil {
		t.Fatal(err)
	}
	id, _ := targetidentity.Inspect(exe)
	adapter := newAdapter(exe, "3.21", id.SHA256, func(_ context.Context, _ string, args []string) runResult {
		if len(args) == 1 && args[0] == "-v" {
			return runResult{Stdout: []byte("die 3.21\n")}
		}
		if err := os.WriteFile(target, []byte("other-version"), 0o600); err != nil {
			t.Fatal(err)
		}
		return runResult{Stdout: []byte("{\"detects\":[]}")}
	})
	_, err := adapter.Scan(context.Background(), target, ScanOptions{})
	if err == nil || !strings.Contains(err.Error(), "target changed during DiE scan") {
		t.Fatalf("unexpected err=%v", err)
	}
}

func TestBundledDie321Smoke(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	exe := filepath.Join(root, "runtime", "die", "diec.exe")
	if _, err := os.Stat(exe); err != nil {
		t.Skipf("bundled DiE runtime not present: %v", err)
	}
	adapter := New(root)
	target, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	report, err := adapter.Scan(context.Background(), target, ScanOptions{Verbose: true, Timeout: 15 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if report.Tool.Version != PinnedVersion || report.Tool.SHA256 != PinnedExecutableSHA256 {
		t.Fatalf("tool=%+v", report.Tool)
	}
	if len(report.Detects) == 0 {
		t.Fatal("bundled DiE returned no detections for Go test executable")
	}
}
