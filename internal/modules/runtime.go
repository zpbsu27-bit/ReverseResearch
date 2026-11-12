package modules

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/sync/semaphore"

	"reverseresearch/internal/backend"
)

type Runtime struct {
	root     string
	backends map[string]*backend.Lazy
	xdbg     map[int]*backend.Lazy

	routeMu      sync.Mutex
	xdbgBits     int
	xdbgWorkflow *semaphore.Weighted

	guardOnce sync.Once
	x32Guard  *x32MutationGuard
	guardErr  error
}

func New(root string) *Runtime {
	return &Runtime{
		root:         root,
		xdbgWorkflow: semaphore.NewWeighted(1),
		backends: map[string]*backend.Lazy{
			"ghidra": backend.NewGhidra(root),
			"r2":     backend.NewRadare2(root),
		},
		xdbg: map[int]*backend.Lazy{
			32: backend.NewXDBG(root, 32),
			64: backend.NewXDBG(root, 64),
		},
	}
}

func (r *Runtime) Statuses() []backend.Status {
	return []backend.Status{
		r.xdbgStatus(),
		r.backends["ghidra"].Status(),
		r.backends["r2"].Status(),
	}
}

func (r *Runtime) xdbgStatus() backend.Status {
	r.routeMu.Lock()
	bits := r.xdbgBits
	r.routeMu.Unlock()
	if bits == 0 {
		return backend.Status{Name: "x32dbg", State: "idle"}
	}
	target := r.xdbg[bits]
	if target == nil {
		return backend.Status{Name: "x32dbg", State: "error", Error: "invalid routed architecture"}
	}
	status := target.Status()
	status.Name = "x32dbg"
	status.Architecture = xdbgArchitectureName(bits)
	return status
}

func (r *Runtime) Call(ctx context.Context, module, tool string, arguments any) (*mcp.CallToolResult, error) {
	if tool == "" {
		return nil, errors.New("tool name is required")
	}
	if arguments == nil {
		arguments = map[string]any{}
	}
	if module == "x32dbg" {
		release, err := r.acquireXDBGWorkflow(ctx)
		if err != nil {
			return nil, err
		}
		defer release()
		return r.callXDBG(ctx, tool, arguments)
	}
	target := r.backends[module]
	if target == nil {
		return nil, fmt.Errorf("unknown module %q", module)
	}
	return callModuleBackend(ctx, target, module, tool, arguments)
}

func callModuleBackend(
	ctx context.Context,
	target *backend.Lazy,
	module, tool string,
	arguments any,
) (*mcp.CallToolResult, error) {
	raw, err := json.Marshal(arguments)
	if err != nil {
		return nil, fmt.Errorf("encode %s.%s arguments: %w", module, tool, err)
	}
	result, err := target.Call(ctx, tool, raw)
	if err != nil {
		return result, err
	}
	return withR2ResultMetadata(module, tool, result)
}

func (r *Runtime) acquireXDBGWorkflow(ctx context.Context) (func(), error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := r.xdbgWorkflow.Acquire(ctx, 1); err != nil {
		return nil, fmt.Errorf("wait for x32dbg workflow: %w", err)
	}
	return func() { r.xdbgWorkflow.Release(1) }, nil
}

func (r *Runtime) callXDBG(ctx context.Context, tool string, arguments any) (*mcp.CallToolResult, error) {
	policy := X32ToolPolicy(tool)
	if policy == X32Blocked {
		return nil, fmt.Errorf("%w: %s; use typed guarded AttachProcess/session tools instead", ErrX32ToolBlocked, tool)
	}
	guard, err := r.mutationGuard()
	if err != nil {
		return nil, err
	}

	if policy == X32ReadOnly {
		bits, err := r.currentXDBGBits()
		if err != nil {
			return nil, err
		}
		target, err := r.xdbgBackend(bits)
		if err != nil {
			return nil, err
		}
		result, callErr := callModuleBackend(ctx, target, "x32dbg", tool, arguments)
		if callErr != nil {
			return nil, errors.Join(callErr, r.resetXDBGSession(bits))
		}
		return result, nil
	}

	_, meta, err := extractX32Guard(arguments)
	if err != nil {
		return nil, err
	}
	if err := validateX32Guard(meta); err != nil {
		return nil, err
	}
	bits, err := guard.targetBits(meta)
	if err != nil {
		return nil, err
	}
	if tool != "AttachProcess" {
		if currentBits, routeErr := r.currentXDBGBits(); routeErr == nil {
			if currentBits != bits {
				return nil, fmt.Errorf(
					"%w: active architecture=%s requested architecture=%s",
					ErrX32SessionConflict, xdbgArchitectureName(currentBits), xdbgArchitectureName(bits),
				)
			}
		} else if !errors.Is(routeErr, ErrX32SessionUnbound) {
			return nil, routeErr
		}
	}
	target, err := r.xdbgBackend(bits)
	if err != nil {
		return nil, err
	}

	backendFailed := false
	execute := func(callCtx context.Context, callArguments any) (*mcp.CallToolResult, error) {
		result, callErr := callModuleBackend(callCtx, target, "x32dbg", tool, callArguments)
		if callErr != nil {
			backendFailed = true
		}
		return result, callErr
	}
	result, callErr := guard.Call(ctx, tool, arguments, execute)
	if backendFailed {
		return result, errors.Join(callErr, r.resetXDBGSession(bits))
	}
	if callErr != nil {
		return result, callErr
	}
	if result != nil && !result.IsError {
		switch tool {
		case "AttachProcess":
			r.setXDBGBits(bits)
		case "StopDebug":
			return result, r.resetXDBGSession(bits)
		}
	}
	return result, nil
}

func (r *Runtime) xdbgBackend(bits int) (*backend.Lazy, error) {
	target := r.xdbg[bits]
	if target == nil {
		return nil, fmt.Errorf("%w: width=%d", ErrXDBGArchitectureUnsupported, bits)
	}
	return target, nil
}

func (r *Runtime) currentXDBGBits() (int, error) {
	r.routeMu.Lock()
	defer r.routeMu.Unlock()
	if r.xdbgBits == 0 {
		return 0, ErrX32SessionUnbound
	}
	return r.xdbgBits, nil
}

func (r *Runtime) setXDBGBits(bits int) {
	r.routeMu.Lock()
	r.xdbgBits = bits
	r.routeMu.Unlock()
}

func (r *Runtime) resetXDBGSession(bits int) error {
	r.routeMu.Lock()
	if r.xdbgBits == bits {
		r.xdbgBits = 0
	}
	r.routeMu.Unlock()

	var result error
	if target := r.xdbg[bits]; target != nil {
		result = errors.Join(result, target.Close())
	}
	if guard := r.loadedGuard(); guard != nil {
		result = errors.Join(result, guard.Close())
	}
	return result
}

func (r *Runtime) mutationGuard() (*x32MutationGuard, error) {
	r.guardOnce.Do(func() {
		r.x32Guard, r.guardErr = newX32MutationGuard(r.root)
	})
	return r.x32Guard, r.guardErr
}

// loadedGuard reads the lazily created guard only through sync.Once, so it is
// safe from paths that never call mutationGuard, such as shutdown.
func (r *Runtime) loadedGuard() *x32MutationGuard {
	guard, _ := r.mutationGuard()
	return guard
}

// detachedCleanupWindow bounds the compensation-only context used when the
// caller's shutdown context is already expired but backends still must be
// drained and their process trees released.
const detachedCleanupWindow = 5 * time.Second

func (r *Runtime) cleanupContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx.Err() == nil {
		return ctx, func() {}
	}
	return context.WithTimeout(context.Background(), detachedCleanupWindow)
}

func (r *Runtime) CloseContext(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	var result error
	release, acquireErr := r.acquireXDBGWorkflow(ctx)
	if acquireErr != nil {
		// A busy workflow must not skip debugger teardown: skipping would leave
		// the session bound and the debugger un-drained. Close anyway with the
		// cleanup window and report the missed drain.
		result = errors.Join(result, fmt.Errorf("wait for x32dbg workflow before shutdown: %w", acquireErr))
		release = func() {}
	}
	defer release()

	cleanupCtx, cancelCleanup := r.cleanupContext(ctx)
	defer cancelCleanup()

	for _, bits := range []int{32, 64} {
		if target := r.xdbg[bits]; target != nil {
			result = errors.Join(result, target.CloseContext(cleanupCtx))
		}
	}
	if guard := r.loadedGuard(); guard != nil {
		result = errors.Join(result, guard.Close())
	}
	r.routeMu.Lock()
	r.xdbgBits = 0
	r.routeMu.Unlock()
	for _, name := range []string{"ghidra", "r2"} {
		result = errors.Join(result, r.backends[name].CloseContext(cleanupCtx))
	}
	return result
}

func (r *Runtime) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return r.CloseContext(ctx)
}
