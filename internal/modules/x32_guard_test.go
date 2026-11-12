package modules

import (
	"context"
	"errors"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"reverseresearch/internal/processcontrol"
)

type fakeX32Leases struct {
	lease processcontrol.Lease
	err   error
}

func (f *fakeX32Leases) Get(pid uint32) (processcontrol.Lease, error) {
	if f.err != nil {
		return processcontrol.Lease{}, f.err
	}
	if f.lease.PID != pid {
		return processcontrol.Lease{}, processcontrol.ErrLeaseNotFound
	}
	return f.lease, nil
}

func guardedArgs(op string, extra map[string]any) map[string]any {
	out := map[string]any{}
	for key, value := range extra {
		out[key] = value
	}
	out[X32GuardArgument] = map[string]any{
		"pid":          42,
		"process_key":  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"owner":        "analysis-a",
		"lease_id":     "lease-fixture",
		"operation_id": op,
	}
	return out
}

func newTestX32Guard(t *testing.T) (*x32MutationGuard, *fakeX32Leases) {
	t.Helper()
	leases := &fakeX32Leases{lease: processcontrol.Lease{
		PID:        42,
		ProcessKey: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Owner:      "analysis-a",
		LeaseID:    "lease-fixture",
	}}
	guard, err := newX32MutationGuardWithLeases(t.TempDir(), leases)
	if err != nil {
		t.Fatal(err)
	}
	return guard, leases
}

func TestX32ReadOnlyCallDoesNotRequireMutationGuard(t *testing.T) {
	guard, _ := newTestX32Guard(t)
	calls := 0
	result, err := guard.Call(context.Background(), "ReadMemory", map[string]any{"address": "401000"}, func(_ context.Context, args any) (*mcp.CallToolResult, error) {
		calls++
		if _, ok := args.(map[string]any)[X32GuardArgument]; ok {
			t.Fatal("read-only call unexpectedly had guard metadata")
		}
		return &mcp.CallToolResult{StructuredContent: map[string]any{"ok": true}}, nil
	})
	if err != nil || result == nil || calls != 1 {
		t.Fatalf("result=%v err=%v calls=%d", result, err, calls)
	}
}

func TestX32MutationRequiresGuardBeforeExecutor(t *testing.T) {
	guard, _ := newTestX32Guard(t)
	calls := 0
	_, err := guard.Call(context.Background(), "WriteMemToAddress", map[string]any{"address": "401000", "byteString": "90"}, func(context.Context, any) (*mcp.CallToolResult, error) {
		calls++
		return &mcp.CallToolResult{}, nil
	})
	if !errors.Is(err, ErrX32GuardRequired) || calls != 0 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}

func TestX32AttachBindsSessionAndMutationReplayExecutesOnce(t *testing.T) {
	guard, _ := newTestX32Guard(t)
	calls := 0
	execute := func(_ context.Context, args any) (*mcp.CallToolResult, error) {
		calls++
		if _, ok := args.(map[string]any)[X32GuardArgument]; ok {
			t.Fatal("guard metadata leaked to backend")
		}
		return &mcp.CallToolResult{StructuredContent: map[string]any{"ok": true, "call": calls}}, nil
	}
	if _, err := guard.Call(context.Background(), "AttachProcess", guardedArgs("attach-1", map[string]any{"pid": 42}), execute); err != nil {
		t.Fatal(err)
	}
	mutation := guardedArgs("set-register-1", map[string]any{"register": "eax", "value": "1"})
	first, err := guard.Call(context.Background(), "SetRegister", mutation, execute)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := guard.Call(context.Background(), "SetRegister", mutation, execute)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("backend calls=%d want=2 (attach + one mutation)", calls)
	}
	if first.StructuredContent == nil || replayed.StructuredContent == nil {
		t.Fatalf("missing structured replay: first=%#v replay=%#v", first, replayed)
	}
}

func TestX32PreparedMutationIsNeverReplayed(t *testing.T) {
	guard, _ := newTestX32Guard(t)
	ok := func(context.Context, any) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{StructuredContent: map[string]any{"ok": true}}, nil
	}
	if _, err := guard.Call(context.Background(), "AttachProcess", guardedArgs("attach-1", map[string]any{"pid": 42}), ok); err != nil {
		t.Fatal(err)
	}
	calls := 0
	mutation := guardedArgs("uncertain-1", map[string]any{"address": "401000", "byteString": "90"})
	_, err := guard.Call(context.Background(), "WriteMemToAddress", mutation, func(context.Context, any) (*mcp.CallToolResult, error) {
		calls++
		return nil, errors.New("transport lost after request")
	})
	if err == nil {
		t.Fatal("uncertain mutation unexpectedly succeeded")
	}
	_, err = guard.Call(context.Background(), "WriteMemToAddress", mutation, func(context.Context, any) (*mcp.CallToolResult, error) {
		calls++
		return &mcp.CallToolResult{}, nil
	})
	if !errors.Is(err, ErrX32OutcomeUncertain) || calls != 1 {
		t.Fatalf("replay err=%v calls=%d", err, calls)
	}
}

func TestX32OperationIDConflictRejected(t *testing.T) {
	guard, _ := newTestX32Guard(t)
	ok := func(context.Context, any) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{StructuredContent: map[string]any{"ok": true}}, nil
	}
	if _, err := guard.Call(context.Background(), "AttachProcess", guardedArgs("attach-1", map[string]any{"pid": 42}), ok); err != nil {
		t.Fatal(err)
	}
	if _, err := guard.Call(context.Background(), "SetRegister", guardedArgs("shared-op", map[string]any{"register": "eax", "value": "1"}), ok); err != nil {
		t.Fatal(err)
	}
	_, err := guard.Call(context.Background(), "SetRegister", guardedArgs("shared-op", map[string]any{"register": "eax", "value": "2"}), ok)
	if err == nil {
		t.Fatal("operation_id reuse for a different request was accepted")
	}
}

func TestX32GenericAndUnboundLaunchToolsFailClosed(t *testing.T) {
	guard, _ := newTestX32Guard(t)
	for _, tool := range []string{"ExecuteDebuggerCommand", "LoadBinary", "RestartDebug"} {
		calls := 0
		_, err := guard.Call(context.Background(), tool, guardedArgs("blocked-"+tool, map[string]any{"command": "attach 99"}), func(context.Context, any) (*mcp.CallToolResult, error) {
			calls++
			return &mcp.CallToolResult{}, nil
		})
		if !errors.Is(err, ErrX32ToolBlocked) || calls != 0 {
			t.Fatalf("%s err=%v calls=%d", tool, err, calls)
		}
	}
}

func TestX32SessionBindingDoesNotCrossRuntimeInstances(t *testing.T) {
	root := t.TempDir()
	leases := &fakeX32Leases{lease: processcontrol.Lease{
		PID:        42,
		ProcessKey: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Owner:      "analysis-a",
		LeaseID:    "lease-fixture",
	}}
	first, err := newX32MutationGuardWithLeases(root, leases)
	if err != nil {
		t.Fatal(err)
	}
	second, err := newX32MutationGuardWithLeases(root, leases)
	if err != nil {
		t.Fatal(err)
	}
	ok := func(context.Context, any) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{StructuredContent: map[string]any{"ok": true}}, nil
	}
	if _, err := first.Call(context.Background(), "AttachProcess", guardedArgs("attach-runtime-1", map[string]any{"pid": 42}), ok); err != nil {
		t.Fatal(err)
	}

	_, err = second.Call(context.Background(), "SetRegister", guardedArgs("write-runtime-2", map[string]any{"register": "eax", "value": "1"}), ok)
	if !errors.Is(err, ErrX32SessionConflict) {
		t.Fatalf("second runtime inherited first binding: %v", err)
	}
	_, err = second.Call(context.Background(), "AttachProcess", guardedArgs("attach-runtime-1", map[string]any{"pid": 42}), ok)
	if !errors.Is(err, ErrX32SessionConflict) {
		t.Fatalf("completed attach replay crossed runtime boundary: %v", err)
	}

	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Call(context.Background(), "AttachProcess", guardedArgs("attach-runtime-2", map[string]any{"pid": 42}), ok); err != nil {
		t.Fatalf("second runtime could not attach after first runtime closed: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestX32StopDebugClearsBoundSession(t *testing.T) {
	guard, _ := newTestX32Guard(t)
	ok := func(context.Context, any) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{StructuredContent: map[string]any{"ok": true}}, nil
	}
	if _, err := guard.Call(context.Background(), "AttachProcess", guardedArgs("attach-1", map[string]any{"pid": 42}), ok); err != nil {
		t.Fatal(err)
	}
	if _, err := guard.Call(context.Background(), "StopDebug", guardedArgs("stop-1", map[string]any{}), ok); err != nil {
		t.Fatal(err)
	}
	_, err := guard.Call(context.Background(), "SetRegister", guardedArgs("after-stop", map[string]any{"register": "eax", "value": "1"}), ok)
	if !errors.Is(err, ErrX32SessionUnbound) {
		t.Fatalf("err=%v want unbound", err)
	}
}

func TestX32AttachPIDMustMatchGuard(t *testing.T) {
	guard, _ := newTestX32Guard(t)
	_, err := guard.Call(context.Background(), "AttachProcess", guardedArgs("attach-wrong", map[string]any{"pid": 99}), func(context.Context, any) (*mcp.CallToolResult, error) {
		t.Fatal("executor should not run")
		return nil, nil
	})
	if err == nil {
		t.Fatal("mismatched AttachProcess pid was accepted")
	}
}
