package modules

import (
	"context"
	"errors"
	"testing"
)

func TestRuntimeStartsIdleAndRejectsUnknownModule(t *testing.T) {
	runtime := New(t.TempDir())
	defer runtime.Close()

	statuses := runtime.Statuses()
	if len(statuses) != 3 {
		t.Fatalf("status count=%d want=3", len(statuses))
	}
	for _, status := range statuses {
		if status.State != "idle" {
			t.Fatalf("%s state=%q want idle", status.Name, status.State)
		}
	}
	if _, err := runtime.Call(context.Background(), "missing", "tool", map[string]any{}); err == nil {
		t.Fatal("unknown module must fail")
	}
	for _, status := range runtime.Statuses() {
		if status.State != "idle" {
			t.Fatalf("unknown call started %s: %s", status.Name, status.State)
		}
	}
}

func TestRuntimeReadOnlyXDBGRequiresBoundSessionBeforeBackendStartup(t *testing.T) {
	runtime := New(t.TempDir())
	defer runtime.Close()

	_, err := runtime.Call(context.Background(), "x32dbg", "ReadMemory", map[string]any{
		"address": "401000", "size": 4,
	})
	if !errors.Is(err, ErrX32SessionUnbound) {
		t.Fatalf("err=%v want unbound session", err)
	}
	for _, status := range runtime.Statuses() {
		if status.State != "idle" {
			t.Fatalf("read-only route probe started backend %s: %s", status.Name, status.State)
		}
	}
}

func TestRuntimeRejectsUnguardedX32MutationsBeforeBackendStartup(t *testing.T) {
	runtime := New(t.TempDir())
	defer runtime.Close()

	_, err := runtime.Call(context.Background(), "x32dbg", "WriteMemToAddress", map[string]any{
		"address": "401000", "byteString": "90",
	})
	if !errors.Is(err, ErrX32GuardRequired) {
		t.Fatalf("err=%v want guard required", err)
	}
	_, err = runtime.Call(context.Background(), "x32dbg", "ExecuteDebuggerCommand", map[string]any{
		"command": "attach 99",
	})
	if !errors.Is(err, ErrX32ToolBlocked) {
		t.Fatalf("err=%v want blocked generic command", err)
	}
	for _, status := range runtime.Statuses() {
		if status.State != "idle" {
			t.Fatalf("guard rejection started backend %s: %s", status.Name, status.State)
		}
	}
}
