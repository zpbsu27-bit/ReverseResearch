package backend

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestLazyEnsureHonorsCallerCancellation(t *testing.T) {
	started := make(chan struct{})
	lazy := NewLazy("test", func(ctx context.Context) (*mcp.ClientSession, func() error, error) {
		close(started)
		<-ctx.Done()
		return nil, nil, ctx.Err()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	_, err := lazy.ensure(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ensure error = %v, want deadline exceeded", err)
	}
	select {
	case <-started:
	default:
		t.Fatal("starter was not invoked")
	}
}

func TestLazyStatusResponsiveDuringStartup(t *testing.T) {
	started := make(chan struct{})
	releaseStart := make(chan struct{})
	lazy := NewLazy("test", func(context.Context) (*mcp.ClientSession, func() error, error) {
		close(started)
		<-releaseStart
		return nil, nil, nil
	})

	done := make(chan error, 1)
	go func() {
		generation, err := lazy.ensure(context.Background())
		if err == nil {
			err = lazy.release(generation)
		}
		done <- err
	}()
	<-started

	statusDone := make(chan Status, 1)
	go func() { statusDone <- lazy.Status() }()
	select {
	case status := <-statusDone:
		if status.State != "starting" {
			t.Fatalf("status = %q, want starting", status.State)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("Status blocked behind backend startup")
	}

	close(releaseStart)
	if err := <-done; err != nil {
		t.Fatalf("ensure/release: %v", err)
	}
	if err := lazy.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func TestLazyRetiredGenerationDrainsBeforeCleanup(t *testing.T) {
	var cleanupCalls atomic.Int32
	lazy := NewLazy("test", func(context.Context) (*mcp.ClientSession, func() error, error) {
		return nil, func() error {
			cleanupCalls.Add(1)
			return nil
		}, nil
	})

	first, err := lazy.ensure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := lazy.ensure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("concurrent acquisitions did not share the same generation")
	}

	if err := lazy.retire(first, errors.New("transport failed")); err != nil {
		t.Fatalf("retire: %v", err)
	}
	if got := cleanupCalls.Load(); got != 0 {
		t.Fatalf("cleanup called with in-flight users: %d", got)
	}

	if err := lazy.release(first); err != nil {
		t.Fatalf("release first: %v", err)
	}
	if got := cleanupCalls.Load(); got != 0 {
		t.Fatalf("cleanup called before final in-flight release: %d", got)
	}

	if err := lazy.release(second); err != nil {
		t.Fatalf("release second: %v", err)
	}
	if got := cleanupCalls.Load(); got != 1 {
		t.Fatalf("cleanup calls = %d, want 1", got)
	}
}

func TestLazyCloseContextWaitsForInflight(t *testing.T) {
	var cleanupCalls atomic.Int32
	lazy := NewLazy("test", func(context.Context) (*mcp.ClientSession, func() error, error) {
		return nil, func() error {
			cleanupCalls.Add(1)
			return nil
		}, nil
	})

	generation, err := lazy.ensure(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	closeDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		closeDone <- lazy.CloseContext(ctx)
	}()

	select {
	case err := <-closeDone:
		t.Fatalf("CloseContext returned before in-flight release: %v", err)
	case <-time.After(25 * time.Millisecond):
	}

	if err := lazy.release(generation); err != nil {
		t.Fatalf("release: %v", err)
	}
	if err := <-closeDone; err != nil {
		t.Fatalf("CloseContext: %v", err)
	}
	if got := cleanupCalls.Load(); got != 1 {
		t.Fatalf("cleanup calls = %d, want 1", got)
	}
}
