package backend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	backendStartupTimeout = 60 * time.Second
	backendCloseTimeout   = 30 * time.Second
)

type Status struct {
	Name         string `json:"name"`
	State        string `json:"state"`
	Architecture string `json:"architecture,omitempty"`
	Error        string `json:"error,omitempty"`
}

type Starter func(context.Context) (*mcp.ClientSession, func() error, error)

type sessionGeneration struct {
	session  *mcp.ClientSession
	cleanup  func() error
	inflight int
	retired  bool
	closing  bool
	done     chan struct{}
	closeErr error
}

type Lazy struct {
	name  string
	start Starter

	mu          sync.Mutex
	closeMu     sync.Mutex
	current     *sessionGeneration
	starting    bool
	startDone   chan struct{}
	startCancel context.CancelFunc
	closing     bool
	closeEpoch  uint64
	state       string
	lastErr     error
}

func NewLazy(name string, start Starter) *Lazy {
	return &Lazy{name: name, start: start, state: "idle"}
}

func (b *Lazy) Name() string { return b.name }

func (b *Lazy) Status() Status {
	b.mu.Lock()
	status := Status{Name: b.name, State: b.state}
	if b.lastErr != nil {
		status.Error = b.lastErr.Error()
	}
	b.mu.Unlock()
	return status
}

func (b *Lazy) ensure(ctx context.Context) (*sessionGeneration, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		b.mu.Lock()
		if b.closing {
			b.mu.Unlock()
			return nil, errors.New("backend is closing")
		}
		if generation := b.current; generation != nil {
			if !generation.retired {
				generation.inflight++
				b.mu.Unlock()
				return generation, nil
			}
			done := generation.done
			b.mu.Unlock()
			select {
			case <-done:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		if b.starting {
			done := b.startDone
			b.mu.Unlock()
			select {
			case <-done:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		startupCtx, cancel := context.WithTimeout(ctx, backendStartupTimeout)
		done := make(chan struct{})
		b.starting = true
		b.startDone = done
		b.startCancel = cancel
		startEpoch := b.closeEpoch
		b.state = "starting"
		b.lastErr = nil
		b.mu.Unlock()

		session, cleanup, startErr := b.start(startupCtx)
		cancel()

		b.mu.Lock()
		closing := b.closing || b.closeEpoch != startEpoch
		if startErr == nil && !closing {
			generation := &sessionGeneration{
				session:  session,
				cleanup:  cleanup,
				inflight: 1,
				done:     make(chan struct{}),
			}
			b.current = generation
			b.starting = false
			b.startDone = nil
			b.startCancel = nil
			b.state = "running"
			b.lastErr = nil
			close(done)
			b.mu.Unlock()
			return generation, nil
		}
		if startErr != nil {
			b.lastErr = startErr
			if closing {
				b.state = "closing"
			} else {
				b.state = "error"
			}
		} else {
			b.state = "closing"
		}
		b.mu.Unlock()

		cleanupErr := closeBackendResources(session, cleanup)

		b.mu.Lock()
		b.starting = false
		b.startDone = nil
		b.startCancel = nil
		close(done)
		b.mu.Unlock()

		if startErr != nil {
			return nil, errors.Join(startErr, cleanupErr)
		}
		return nil, errors.Join(errors.New("backend closed during startup"), cleanupErr)
	}
}

func (b *Lazy) Call(ctx context.Context, tool string, raw json.RawMessage) (*mcp.CallToolResult, error) {
	var arguments any = map[string]any{}
	if len(raw) > 0 && string(raw) != "null" {
		if err := json.Unmarshal(raw, &arguments); err != nil {
			return nil, err
		}
	}

	generation, err := b.ensure(ctx)
	if err != nil {
		return nil, err
	}
	if generation.session == nil {
		releaseErr := b.release(generation)
		return nil, errors.Join(errors.New("backend starter returned a nil session"), releaseErr)
	}

	result, callErr := generation.session.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: arguments})
	var retireErr error
	if callErr != nil {
		// Calls may mutate debugger or analysis state, so never replay this call.
		// Retire only this session generation. Other already in-flight calls are
		// allowed to finish before the shared transport/process is torn down.
		retireErr = b.retire(generation, callErr)
	}
	releaseErr := b.release(generation)
	if callErr != nil {
		return nil, errors.Join(callErr, retireErr, releaseErr)
	}
	if releaseErr != nil {
		return result, releaseErr
	}
	return result, nil
}

func (b *Lazy) retire(generation *sessionGeneration, cause error) error {
	b.mu.Lock()
	if b.current == generation && !generation.retired {
		generation.retired = true
		if cause != nil {
			b.state = "error"
			b.lastErr = cause
		}
	}
	closeNow := claimGenerationCloseLocked(generation)
	b.mu.Unlock()
	if closeNow {
		return b.closeGeneration(generation)
	}
	return nil
}

func (b *Lazy) release(generation *sessionGeneration) error {
	b.mu.Lock()
	if generation.inflight <= 0 {
		b.mu.Unlock()
		return errors.New("backend session generation released without an in-flight call")
	}
	generation.inflight--
	closeNow := claimGenerationCloseLocked(generation)
	b.mu.Unlock()
	if closeNow {
		return b.closeGeneration(generation)
	}
	return nil
}

func claimGenerationCloseLocked(generation *sessionGeneration) bool {
	if generation == nil || !generation.retired || generation.inflight != 0 || generation.closing {
		return false
	}
	generation.closing = true
	return true
}

func (b *Lazy) closeGeneration(generation *sessionGeneration) error {
	closeErr := closeBackendResources(generation.session, generation.cleanup)

	b.mu.Lock()
	generation.closeErr = closeErr
	if b.current == generation {
		b.current = nil
	}
	close(generation.done)
	b.mu.Unlock()
	return closeErr
}

func closeBackendResources(session *mcp.ClientSession, cleanup func() error) error {
	var errs []error
	if session != nil {
		if err := session.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if cleanup != nil {
		if err := cleanup(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (b *Lazy) CloseContext(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	b.closeMu.Lock()
	defer b.closeMu.Unlock()

	b.mu.Lock()
	b.closing = true
	b.closeEpoch++
	b.state = "closing"
	startCancel := b.startCancel
	startDone := b.startDone
	b.mu.Unlock()

	if startCancel != nil {
		startCancel()
	}
	if startDone != nil {
		select {
		case <-startDone:
		case <-ctx.Done():
			b.finishCloseState()
			return fmt.Errorf("wait for backend startup shutdown: %w", ctx.Err())
		}
	}

	b.mu.Lock()
	generation := b.current
	var done <-chan struct{}
	closeNow := false
	if generation != nil {
		generation.retired = true
		done = generation.done
		closeNow = claimGenerationCloseLocked(generation)
	}
	b.mu.Unlock()

	if closeNow {
		_ = b.closeGeneration(generation)
	}
	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
			b.finishCloseState()
			return fmt.Errorf("wait for backend in-flight calls: %w", ctx.Err())
		}
	}

	var closeErr error
	if generation != nil {
		b.mu.Lock()
		closeErr = generation.closeErr
		b.mu.Unlock()
	}
	b.finishCloseState()
	return closeErr
}

func (b *Lazy) finishCloseState() {
	b.mu.Lock()
	b.closing = false
	if b.current == nil {
		b.state = "idle"
		b.lastErr = nil
	} else if b.current.retired {
		b.state = "draining"
	}
	b.mu.Unlock()
}

func (b *Lazy) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), backendCloseTimeout)
	defer cancel()
	return b.CloseContext(ctx)
}
