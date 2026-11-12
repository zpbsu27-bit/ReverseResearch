package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/felixge/httpsnoop"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"reverseresearch/internal/consolelog"
)

// These process-local counters observe the existing Runtime. They do not own
// tool execution, authorization, durable operation state, or business results.
type runtimeActivity struct {
	requests   atomic.Uint64
	httpActive atomic.Int64
	calls      atomic.Uint64
	queued     atomic.Int64
	running    atomic.Int64
	succeeded  atomic.Uint64
	failed     atomic.Uint64
	cancelled  atomic.Uint64
}

type ActivitySnapshot struct {
	Requests   uint64
	HTTPActive int64
	Calls      uint64
	Queued     int64
	Running    int64
	Succeeded  uint64
	Failed     uint64
	Cancelled  uint64
}

func (r *Runtime) Activity() ActivitySnapshot {
	return ActivitySnapshot{
		Requests: r.activity.requests.Load(), HTTPActive: r.activity.httpActive.Load(),
		Calls: r.activity.calls.Load(), Queued: r.activity.queued.Load(), Running: r.activity.running.Load(),
		Succeeded: r.activity.succeeded.Load(), Failed: r.activity.failed.Load(), Cancelled: r.activity.cancelled.Load(),
	}
}

func (r *Runtime) callObservedTool(
	ctx context.Context, name string, weight int64, request *mcp.CallToolRequest,
	handler func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error),
) (result *mcp.CallToolResult, resultErr error) {
	call := r.activity.calls.Add(1)
	started := time.Now()
	r.activity.queued.Add(1)
	consolelog.Eventf(consolelog.ColorStatus, "TOOL", "调用 #%d | %s | 等待执行", call, name)
	if err := r.resourceGate.Acquire(ctx, weight); err != nil {
		r.activity.queued.Add(-1)
		color, state := consolelog.ColorRed, "资源准入失败，未进入执行"
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			r.activity.cancelled.Add(1)
			color, state = consolelog.ColorYellow, "等待已取消或超时，未进入执行"
		} else {
			r.activity.failed.Add(1)
		}
		consolelog.Eventf(color, "TOOL", "调用 #%d | %s | %s | 耗时 %d ms", call, name, state, time.Since(started).Milliseconds())
		return nil, fmt.Errorf("resource admission for %s: %w", name, err)
	}
	r.activity.queued.Add(-1)
	r.activity.running.Add(1)
	consolelog.Eventf(consolelog.ColorStatus, "TOOL", "调用 #%d | %s | 执行中 | 排队 %d ms", call, name, time.Since(started).Milliseconds())
	returned := false
	defer func() {
		r.resourceGate.Release(weight)
		r.activity.running.Add(-1)
		color, state := consolelog.ColorGreen, "调用已返回（协议成功）"
		switch {
		case !returned:
			r.activity.failed.Add(1)
			color, state = consolelog.ColorRed, "执行异常中断"
		case errors.Is(resultErr, context.Canceled), errors.Is(resultErr, context.DeadlineExceeded):
			r.activity.cancelled.Add(1)
			color, state = consolelog.ColorYellow, "调用已取消或超时"
		case resultErr != nil:
			r.activity.failed.Add(1)
			color, state = consolelog.ColorRed, "调用返回错误"
		case result == nil:
			r.activity.failed.Add(1)
			color, state = consolelog.ColorYellow, "调用返回空结果"
		case result.IsError:
			r.activity.failed.Add(1)
			color, state = consolelog.ColorRed, "工具返回错误结果"
		default:
			r.activity.succeeded.Add(1)
		}
		// Neither error text nor request/result contents belong in this log.
		consolelog.Eventf(color, "TOOL", "调用 #%d | %s | %s | 耗时 %d ms", call, name, state, time.Since(started).Milliseconds())
	}()
	result, resultErr = handler(ctx, request)
	returned = true
	return result, resultErr
}

func (r *Runtime) observeHTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		call := r.activity.requests.Add(1)
		r.activity.httpActive.Add(1)
		started := time.Now()
		route := observedHTTPRoute(request.URL.Path)
		method := observedHTTPMethod(request.Method)
		if route != "/healthz" {
			consolelog.Eventf(consolelog.ColorStatus, "HTTP", "请求 #%d | %s %s | 已接入", call, method, route)
		}
		metrics := httpsnoop.Metrics{Code: http.StatusOK}
		writeFailed := false
		returned := false
		defer func() {
			r.activity.httpActive.Add(-1)
			if !returned {
				consolelog.Eventf(consolelog.ColorRed, "HTTP", "请求 #%d | %s %s | 处理异常中断 | 耗时 %d ms", call, method, route, time.Since(started).Milliseconds())
				return
			}
			// Frequent healthy probes are counted, but do not flood the window.
			cancelled := request.Context().Err() != nil
			if route == "/healthz" && metrics.Code >= http.StatusOK && metrics.Code < http.StatusMultipleChoices && !writeFailed && !cancelled {
				return
			}
			color := consolelog.ColorGreen
			state := "已返回"
			if writeFailed {
				color, state = consolelog.ColorRed, "响应写入失败"
			} else if cancelled {
				color, state = consolelog.ColorYellow, "请求已取消或超时"
			} else if metrics.Code >= http.StatusInternalServerError {
				color = consolelog.ColorRed
			} else if metrics.Code >= http.StatusBadRequest {
				color = consolelog.ColorYellow
			}
			consolelog.Eventf(color, "HTTP", "请求 #%d | %s %s | HTTP %d | %s | 耗时 %d ms", call, method, route, metrics.Code, state, metrics.Duration.Milliseconds())
		}()
		// httpsnoop preserves exactly the optional ResponseWriter interfaces of
		// the underlying writer, including Flusher, Hijacker and Unwrap.
		writer := httpsnoop.Wrap(w, httpsnoop.Hooks{
			Write: func(next httpsnoop.WriteFunc) httpsnoop.WriteFunc {
				return func(body []byte) (int, error) {
					n, err := next(body)
					writeFailed = writeFailed || err != nil
					return n, err
				}
			},
			ReadFrom: func(next httpsnoop.ReadFromFunc) httpsnoop.ReadFromFunc {
				return func(body io.Reader) (int64, error) {
					n, err := next(body)
					writeFailed = writeFailed || err != nil
					return n, err
				}
			},
		})
		metrics.CaptureMetrics(writer, func(wrapped http.ResponseWriter) {
			next.ServeHTTP(wrapped, request)
		})
		returned = true
	})
}

func observedHTTPRoute(path string) string {
	switch path {
	case "/mcp", "/control/shutdown", "/healthz":
		return path
	default:
		return "other"
	}
}

func observedHTTPMethod(method string) string {
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodDelete, http.MethodPut,
		http.MethodPatch, http.MethodHead, http.MethodOptions:
		return method
	default:
		return "OTHER"
	}
}
