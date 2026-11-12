package modules

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"reverseresearch/internal/backend"
	"reverseresearch/internal/processcontrol"
)

type fakeWatchBackend struct {
	mu              sync.Mutex
	watched         *uint64
	instruction     uint64
	conflictAddress uint64
	calls           []string
	commands        []string
	blockRun        bool
	onSet           func()
}

func (f *fakeWatchBackend) record(call string) {
	f.mu.Lock()
	f.calls = append(f.calls, call)
	f.mu.Unlock()
}

func (f *fakeWatchBackend) snapshot() ([]string, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...), append([]string(nil), f.commands...)
}

func (f *fakeWatchBackend) starter(ctx context.Context) (*mcp.ClientSession, func() error, error) {
	server := mcp.NewServer(&mcp.Implementation{Name: "fake-xdbg", Version: "1.0.0"}, nil)
	add := func(name string, handler func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error)) {
		server.AddTool(&mcp.Tool{
			Name:        name,
			InputSchema: map[string]any{"type": "object", "additionalProperties": true},
		}, handler)
	}
	result := func(value any) *mcp.CallToolResult {
		return &mcp.CallToolResult{StructuredContent: value}
	}
	add("AttachProcess", func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		f.record("AttachProcess")
		return result(map[string]any{"attached": true}), nil
	})
	add("ListBreakpoints", func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		f.record("ListBreakpoints")
		if f.conflictAddress != 0 {
			return result(map[string]any{"breakpoints": []any{map[string]any{"address": fmt.Sprintf("0x%X", f.conflictAddress)}}}), nil
		}
		return result(map[string]any{"breakpoints": []any{}}), nil
	})
	add("SetHardwareBreakpoint", func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		f.record("SetHardwareBreakpoint")
		if f.onSet != nil {
			f.onSet()
		}
		return result(map[string]any{"ok": true}), nil
	})
	add("run", func(ctx context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		f.record("run")
		if f.blockRun {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		if f.watched != nil {
			*f.watched++
		}
		return result(map[string]any{"paused": true, "reason": "hardware_breakpoint"}), nil
	})
	add("GetCurrentAddress", func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		f.record("GetCurrentAddress")
		return result(map[string]any{"address": fmt.Sprintf("0x%X", f.instruction)}), nil
	})
	add("GetAllRegisters", func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		f.record("GetAllRegisters")
		return result(map[string]any{"rip": fmt.Sprintf("0x%X", f.instruction), "rax": "0x1"}), nil
	})
	add("GetThreads", func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		f.record("GetThreads")
		return result(map[string]any{"threads": []any{map[string]any{"threadId": float64(321), "current": true}}}), nil
	})
	add("GetCallStack", func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		f.record("GetCallStack")
		return result(map[string]any{"frames": []any{}}), nil
	})
	add("GetDebugState", func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		f.record("GetDebugState")
		return result(map[string]any{"state": "paused"}), nil
	})
	add("GetEventLog", func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		f.record("GetEventLog")
		return result(map[string]any{"events": []any{"hardware breakpoint"}}), nil
	})
	add("ExecuteDebuggerCommand", func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		f.record("ExecuteDebuggerCommand")
		if request != nil && request.Params != nil {
			var args map[string]any
			if json.Unmarshal(request.Params.Arguments, &args) == nil {
				if command, ok := args["command"].(string); ok {
					f.mu.Lock()
					f.commands = append(f.commands, command)
					f.mu.Unlock()
				}
			}
		}
		return result(map[string]any{"ok": true}), nil
	})
	add("StopDebug", func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		f.record("StopDebug")
		return result(map[string]any{"stopped": true}), nil
	})

	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverCtx, cancel := context.WithCancel(context.Background())
	go func() { _ = server.Run(serverCtx, serverTransport) }()
	client := mcp.NewClient(&mcp.Implementation{Name: "fake-watch-client", Version: "1.0.0"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	cleanup := func() error {
		cancel()
		return session.Close()
	}
	return session, cleanup, nil
}

func setupWatchRuntime(t *testing.T, fake *fakeWatchBackend) (*Runtime, processcontrol.Identity, processcontrol.Lease) {
	t.Helper()
	root := t.TempDir()
	identity, err := processcontrol.Inspect(uint32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	store, err := processcontrol.NewLeaseStore(filepath.Join(root, "state", "process-control"))
	if err != nil {
		t.Fatal(err)
	}
	lease, err := store.Acquire(processcontrol.AcquireRequest{Expected: identity, Owner: "watch-test"})
	if err != nil {
		t.Fatal(err)
	}
	runtime := New(root)
	runtime.xdbg[identity.Image.PE.Bits] = backend.NewLazy("fake-xdbg", fake.starter)
	t.Cleanup(func() { _ = runtime.Close() })
	return runtime, identity, lease
}

func TestObserveWriteCapturesContextAndRemovesOnlyOwnedHardwareBreakpoint(t *testing.T) {
	watched := uint64(41)
	address := uint64(uintptr(unsafe.Pointer(&watched)))
	fake := &fakeWatchBackend{
		watched:     &watched,
		instruction: 0,
	}
	runtime, identity, lease := setupWatchRuntime(t, fake)
	fake.instruction = identity.MainModuleBase + 0x1000

	report, err := runtime.ObserveWrite(context.Background(), X32WriteWatchRequest{
		PID:         identity.PID,
		ProcessKey:  identity.Key,
		Owner:       lease.Owner,
		LeaseID:     lease.LeaseID,
		OperationID: "watch-write-1",
		Address:     address,
		Size:        8,
		Timeout:     5 * time.Second,
		MaxEvents:   1,
		StopOnWrite: true,
	})
	goruntime.KeepAlive(&watched)
	if err != nil {
		t.Fatal(err)
	}
	if watched != 42 || !report.Complete || len(report.Events) != 1 {
		t.Fatalf("report=%+v watched=%d", report, watched)
	}
	event := report.Events[0]
	if !event.ValueChanged || event.ThreadID != 321 || event.InstructionPointer != fake.instruction {
		t.Fatalf("event=%+v", event)
	}
	if event.Module.Path == "" || len(event.Module.SHA256) != 64 || event.Module.FileSize <= 0 || event.Module.RVA == 0 || event.Module.RVAHex == "" {
		t.Fatalf("module evidence=%+v", event.Module)
	}
	if !report.Cleanup.HardwareBreakpointRemoved || !report.Cleanup.DebugSessionStopped || report.Cleanup.Error != "" {
		t.Fatalf("cleanup=%+v", report.Cleanup)
	}
	calls, commands := fake.snapshot()
	if strings.Contains(strings.Join(calls, ","), "DeleteAllBreakpoints") {
		t.Fatalf("watch used global breakpoint deletion: %v", calls)
	}
	if len(commands) != 1 || commands[0] != fmt.Sprintf("bphc 0x%X", address) {
		t.Fatalf("cleanup commands=%v", commands)
	}
}

func TestObserveWriteRejectsSameAddressBreakpointAndDoesNotDeleteIt(t *testing.T) {
	watched := uint64(7)
	address := uint64(uintptr(unsafe.Pointer(&watched)))
	fake := &fakeWatchBackend{watched: &watched, conflictAddress: address}
	runtime, identity, lease := setupWatchRuntime(t, fake)

	_, err := runtime.ObserveWrite(context.Background(), X32WriteWatchRequest{
		PID:         identity.PID,
		ProcessKey:  identity.Key,
		Owner:       lease.Owner,
		LeaseID:     lease.LeaseID,
		OperationID: "watch-conflict-1",
		Address:     address,
		Size:        8,
		Timeout:     5 * time.Second,
		MaxEvents:   1,
		StopOnWrite: true,
	})
	goruntime.KeepAlive(&watched)
	if !errors.Is(err, ErrX32WatchConflict) {
		t.Fatalf("err=%v", err)
	}
	calls, commands := fake.snapshot()
	if containsString(calls, "SetHardwareBreakpoint") || containsString(calls, "run") {
		t.Fatalf("conflicting watch mutated debugger: %v", calls)
	}
	if len(commands) != 0 {
		t.Fatalf("conflicting watch deleted breakpoint: %v", commands)
	}
	if !containsString(calls, "StopDebug") {
		t.Fatalf("owned attach session was not stopped: %v", calls)
	}
}

func TestObserveWriteTimeoutReleasesTaskResourcesAfterBackendReset(t *testing.T) {
	watched := uint64(11)
	address := uint64(uintptr(unsafe.Pointer(&watched)))
	fake := &fakeWatchBackend{watched: &watched, blockRun: true}
	runtime, identity, lease := setupWatchRuntime(t, fake)

	report, err := runtime.ObserveWrite(context.Background(), X32WriteWatchRequest{
		PID:         identity.PID,
		ProcessKey:  identity.Key,
		Owner:       lease.Owner,
		LeaseID:     lease.LeaseID,
		OperationID: "watch-timeout-1",
		Address:     address,
		Size:        8,
		Timeout:     5 * time.Second,
		MaxEvents:   1,
		StopOnWrite: true,
	})
	goruntime.KeepAlive(&watched)
	if err != nil {
		t.Fatal(err)
	}
	if report.Complete || report.PartialReason != "timeout_or_cancel" {
		t.Fatalf("report=%+v", report)
	}
	if !report.Cleanup.BackendReset || !report.Cleanup.DebugSessionStopped || !report.Cleanup.ResourcesReleased || report.Cleanup.Error != "" {
		t.Fatalf("cleanup=%+v", report.Cleanup)
	}
	calls, commands := fake.snapshot()
	if !containsString(calls, "run") {
		t.Fatalf("run was not attempted: %v", calls)
	}
	if len(commands) != 0 {
		t.Fatalf("backend-reset cleanup must not issue a command against a fresh session: %v", commands)
	}
}

func TestObserveWriteCallerCancellationCleansOnlyTaskResources(t *testing.T) {
	watched := uint64(13)
	address := uint64(uintptr(unsafe.Pointer(&watched)))
	ctx, cancel := context.WithCancel(context.Background())
	fake := &fakeWatchBackend{watched: &watched}
	fake.onSet = cancel
	runtime, identity, lease := setupWatchRuntime(t, fake)

	report, err := runtime.ObserveWrite(ctx, X32WriteWatchRequest{
		PID: identity.PID, ProcessKey: identity.Key, Owner: lease.Owner, LeaseID: lease.LeaseID,
		OperationID: "watch-cancel-1", Address: address, Size: 8,
		// Cancellation is injected immediately by fake.onSet. Keep the watch wall
		// budget above race-instrumented cleanup latency so this test measures caller
		// cancellation semantics rather than scheduler speed.
		Timeout: 5 * time.Second, MaxEvents: 1, StopOnWrite: true,
	})
	goruntime.KeepAlive(&watched)
	if err != nil {
		t.Fatalf("cancelled watch returned cleanup error: %v", err)
	}
	if report.Complete || report.PartialReason != "timeout_or_cancel" {
		t.Fatalf("report=%+v", report)
	}
	if !report.Cleanup.HardwareBreakpointRemoved || !report.Cleanup.DebugSessionStopped || !report.Cleanup.ResourcesReleased {
		t.Fatalf("cleanup=%+v", report.Cleanup)
	}
	calls, commands := fake.snapshot()
	if containsString(calls, "run") {
		t.Fatalf("cancelled watch ran target after cancellation: %v", calls)
	}
	if len(commands) != 1 || commands[0] != fmt.Sprintf("bphc 0x%X", address) {
		t.Fatalf("cleanup commands=%v", commands)
	}
}

func TestObserveWriteCanCollectBoundedMultipleEvents(t *testing.T) {
	watched := uint64(20)
	address := uint64(uintptr(unsafe.Pointer(&watched)))
	fake := &fakeWatchBackend{watched: &watched}
	runtime, identity, lease := setupWatchRuntime(t, fake)
	fake.instruction = identity.MainModuleBase + 0x1000

	report, err := runtime.ObserveWrite(context.Background(), X32WriteWatchRequest{
		PID: identity.PID, ProcessKey: identity.Key, Owner: lease.Owner, LeaseID: lease.LeaseID,
		OperationID: "watch-multi-1", Address: address, Size: 8,
		Timeout: 5 * time.Second, MaxEvents: 2, StopOnWrite: false,
	})
	goruntime.KeepAlive(&watched)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Complete || len(report.Events) != 2 || watched != 22 {
		t.Fatalf("report=%+v watched=%d", report, watched)
	}
	if report.Events[0].AfterHex == report.Events[1].AfterHex {
		t.Fatalf("events did not advance watched value: %+v", report.Events)
	}
}

func TestNormalizeWriteWatchRejectsMisalignedAndOversizedRequests(t *testing.T) {
	base := X32WriteWatchRequest{
		PID:         1,
		ProcessKey:  strings.Repeat("a", 64),
		Owner:       "owner",
		LeaseID:     "lease",
		OperationID: "watch-op",
		Address:     0x1001,
		Size:        8,
		Timeout:     time.Second,
		MaxEvents:   1,
	}
	if _, err := normalizeWriteWatchRequest(base); err == nil {
		t.Fatal("misaligned watch address was accepted")
	}
	base.Address = 0x1000
	base.MaxEvents = MaxWriteWatchEvents + 1
	if _, err := normalizeWriteWatchRequest(base); err == nil {
		t.Fatal("oversized watch event count was accepted")
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
