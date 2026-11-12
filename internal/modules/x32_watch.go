package modules

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"reverseresearch/internal/memscan"
)

const (
	DefaultWriteWatchTimeout   = 30 * time.Second
	MaxWriteWatchTimeout       = 2 * time.Minute
	DefaultWriteWatchMaxEvents = 1
	MaxWriteWatchEvents        = 16
)

var (
	ErrX32WatchSessionBusy = errors.New("write watch requires an idle x32dbg runtime")
	ErrX32WatchConflict    = errors.New("write watch address already has a breakpoint")
)

type X32WriteWatchRequest struct {
	PID         uint32        `json:"pid"`
	ProcessKey  string        `json:"process_key"`
	Owner       string        `json:"owner"`
	LeaseID     string        `json:"lease_id"`
	OperationID string        `json:"operation_id"`
	Address     uint64        `json:"address"`
	Size        int           `json:"size"`
	Timeout     time.Duration `json:"-"`
	MaxEvents   int           `json:"max_events"`
	StopOnWrite bool          `json:"stop_on_write"`
}

type X32WriteWatchModule struct {
	Path      string `json:"path,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
	FileSize  int64  `json:"file_size,omitempty"`
	Base      uint64 `json:"base,omitempty"`
	ImageSize uint64 `json:"image_size,omitempty"`
	RVA       uint64 `json:"rva,omitempty"`
	RVAHex    string `json:"rva_hex,omitempty"`
}

type X32WriteWatchEvent struct {
	Index              int                 `json:"index"`
	ObservedUTC        string              `json:"observed_utc"`
	InstructionPointer uint64              `json:"instruction_pointer,omitempty"`
	InstructionHex     string              `json:"instruction_hex,omitempty"`
	ThreadID           uint64              `json:"thread_id,omitempty"`
	Module             X32WriteWatchModule `json:"module,omitempty"`
	BeforeHex          string              `json:"before_hex"`
	AfterHex           string              `json:"after_hex"`
	ValueChanged       bool                `json:"value_changed"`
	RunResult          any                 `json:"run_result,omitempty"`
	DebugState         any                 `json:"debug_state,omitempty"`
	Registers          any                 `json:"registers,omitempty"`
	Threads            any                 `json:"threads,omitempty"`
	CallStack          any                 `json:"call_stack,omitempty"`
	EventLog           any                 `json:"event_log,omitempty"`
}

type X32WriteWatchCleanup struct {
	HardwareBreakpointRemoved bool   `json:"hardware_breakpoint_removed"`
	DebugSessionStopped       bool   `json:"debug_session_stopped"`
	BackendReset              bool   `json:"backend_reset"`
	ResourcesReleased         bool   `json:"resources_released"`
	Error                     string `json:"error,omitempty"`
}

type X32WriteWatchReport struct {
	OperationID   string               `json:"operation_id"`
	PID           uint32               `json:"pid"`
	ProcessKey    string               `json:"process_key"`
	Address       uint64               `json:"address"`
	AddressHex    string               `json:"address_hex"`
	Size          int                  `json:"size"`
	StartedUTC    string               `json:"started_utc"`
	CompletedUTC  string               `json:"completed_utc"`
	TimeoutMS     int64                `json:"timeout_ms"`
	MaxEvents     int                  `json:"max_events"`
	Complete      bool                 `json:"complete"`
	PartialReason string               `json:"partial_reason,omitempty"`
	Events        []X32WriteWatchEvent `json:"events"`
	Cleanup       X32WriteWatchCleanup `json:"cleanup"`
}

func (r *Runtime) ObserveWrite(ctx context.Context, request X32WriteWatchRequest) (report X32WriteWatchReport, err error) {
	request, err = normalizeWriteWatchRequest(request)
	if err != nil {
		return X32WriteWatchReport{}, err
	}
	report = X32WriteWatchReport{
		OperationID: request.OperationID,
		PID:         request.PID,
		ProcessKey:  request.ProcessKey,
		Address:     request.Address,
		AddressHex:  fmt.Sprintf("0x%X", request.Address),
		Size:        request.Size,
		StartedUTC:  time.Now().UTC().Format(time.RFC3339Nano),
		TimeoutMS:   request.Timeout.Milliseconds(),
		MaxEvents:   request.MaxEvents,
		Events:      make([]X32WriteWatchEvent, 0, request.MaxEvents),
	}

	releaseWorkflow, acquireErr := r.acquireXDBGWorkflow(ctx)
	if acquireErr != nil {
		return report, acquireErr
	}
	defer releaseWorkflow()

	if _, routeErr := r.currentXDBGBits(); routeErr == nil {
		return report, ErrX32WatchSessionBusy
	} else if !errors.Is(routeErr, ErrX32SessionUnbound) {
		return report, routeErr
	}

	watchCtx, cancel := context.WithTimeout(ctx, request.Timeout)
	defer cancel()

	memory, err := memscan.OpenReadOnlyMemory(request.PID)
	if err != nil {
		return report, err
	}
	defer memory.Close()
	before, err := memory.Read(request.Address, request.Size)
	if err != nil {
		return report, fmt.Errorf("read watched bytes before observation: %w", err)
	}

	attached := false
	breakpointSet := false
	cleanupDone := false
	defer func() {
		if cleanupDone {
			return
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cleanupCancel()
		cleanupErr := r.cleanupWriteWatch(cleanupCtx, request, breakpointSet, attached, &report.Cleanup)
		report.CompletedUTC = time.Now().UTC().Format(time.RFC3339Nano)
		if cleanupErr != nil {
			if err == nil {
				err = cleanupErr
			} else {
				err = errors.Join(err, cleanupErr)
			}
		}
	}()

	attachCtx, attachCancel := detachedWriteWatchEffectContext(watchCtx, 15*time.Second)
	_, err = r.callWriteWatchMutation(attachCtx, request, "attach", "AttachProcess", map[string]any{"pid": request.PID})
	attachCancel()
	if err != nil {
		return report, err
	}
	attached = true

	listed, err := r.callXDBG(watchCtx, "ListBreakpoints", map[string]any{})
	if err != nil {
		return report, err
	}
	if resultContainsAddress(listed, request.Address) {
		return report, fmt.Errorf("%w: %s", ErrX32WatchConflict, report.AddressHex)
	}

	breakpointSet = true
	setCtx, setCancel := detachedWriteWatchEffectContext(watchCtx, 15*time.Second)
	_, err = r.callWriteWatchMutation(setCtx, request, "set", "SetHardwareBreakpoint", map[string]any{
		"address": fmt.Sprintf("%X", request.Address),
		"type":    "w",
		"size":    request.Size,
	})
	setCancel()
	if err != nil {
		return report, err
	}

	currentBytes := append([]byte(nil), before...)
	for index := 0; index < request.MaxEvents; index++ {
		if watchCtx.Err() != nil {
			report.PartialReason = "timeout_or_cancel"
			break
		}
		deadline, ok := watchCtx.Deadline()
		if !ok {
			deadline = time.Now().Add(request.Timeout)
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			report.PartialReason = "timeout"
			break
		}
		runResult, runErr := r.callWriteWatchMutation(watchCtx, request, fmt.Sprintf("run.%d", index+1), "run", map[string]any{
			"timeoutMs": remaining.Milliseconds(),
		})
		if runErr != nil {
			if isWriteWatchTimeoutOrCancel(runErr, watchCtx) {
				report.PartialReason = "timeout_or_cancel"
				break
			}
			return report, runErr
		}
		if runResult != nil && runResult.IsError {
			report.PartialReason = "backend_run_error"
			break
		}

		event, captureErr := r.captureWriteWatchEvent(watchCtx, request, index+1, currentBytes, runResult, memory)
		if captureErr != nil {
			return report, captureErr
		}
		report.Events = append(report.Events, event)
		currentBytes, _ = hex.DecodeString(event.AfterHex)
		if request.StopOnWrite && event.ValueChanged {
			report.Complete = true
			break
		}
	}
	if !report.Complete && report.PartialReason == "" {
		if len(report.Events) >= request.MaxEvents {
			report.PartialReason = "max_events"
		} else {
			report.PartialReason = "no_write_observed"
		}
	}
	if !request.StopOnWrite && len(report.Events) == request.MaxEvents {
		report.Complete = true
	}

	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 8*time.Second)
	cleanupErr := r.cleanupWriteWatch(cleanupCtx, request, breakpointSet, attached, &report.Cleanup)
	cleanupCancel()
	cleanupDone = true
	report.CompletedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	if cleanupErr != nil {
		return report, cleanupErr
	}
	return report, nil
}

func normalizeWriteWatchRequest(request X32WriteWatchRequest) (X32WriteWatchRequest, error) {
	request.ProcessKey = strings.TrimSpace(request.ProcessKey)
	request.Owner = strings.TrimSpace(request.Owner)
	request.LeaseID = strings.TrimSpace(request.LeaseID)
	request.OperationID = strings.TrimSpace(request.OperationID)
	if request.PID == 0 || len(request.ProcessKey) != 64 || request.Owner == "" || request.LeaseID == "" {
		return request, errors.New("write watch requires pid, 64-char process_key, owner, and lease_id")
	}
	if !x32OperationIDPattern.MatchString(request.OperationID) || len(request.OperationID) > 140 {
		return request, errors.New("write watch operation_id must be <= 140 chars and match the guarded operation id syntax")
	}
	if request.Address == 0 {
		return request, errors.New("write watch address is required")
	}
	switch request.Size {
	case 0:
		request.Size = 1
	case 1, 2, 4, 8:
	default:
		return request, errors.New("write watch size must be 1, 2, 4, or 8")
	}
	if request.Address%uint64(request.Size) != 0 {
		return request, fmt.Errorf("write watch address 0x%X is not aligned to size %d", request.Address, request.Size)
	}
	if request.Timeout == 0 {
		request.Timeout = DefaultWriteWatchTimeout
	}
	if request.Timeout <= 0 || request.Timeout > MaxWriteWatchTimeout {
		return request, fmt.Errorf("write watch timeout must be > 0 and <= %s", MaxWriteWatchTimeout)
	}
	if request.MaxEvents == 0 {
		request.MaxEvents = DefaultWriteWatchMaxEvents
	}
	if request.MaxEvents < 1 || request.MaxEvents > MaxWriteWatchEvents {
		return request, fmt.Errorf("write watch max_events must be between 1 and %d", MaxWriteWatchEvents)
	}
	return request, nil
}

func (r *Runtime) callWriteWatchMutation(ctx context.Context, request X32WriteWatchRequest, suffix, tool string, arguments map[string]any) (*mcp.CallToolResult, error) {
	args := make(map[string]any, len(arguments)+1)
	for key, value := range arguments {
		args[key] = value
	}
	args[X32GuardArgument] = writeWatchGuard(request, suffix)
	result, err := r.callXDBG(ctx, tool, args)
	if err != nil {
		return result, err
	}
	if result != nil && result.IsError {
		return result, fmt.Errorf("%s failed: %s", tool, resultText(result))
	}
	return result, nil
}

func (r *Runtime) cleanupWriteWatch(ctx context.Context, request X32WriteWatchRequest, breakpointSet, attached bool, cleanup *X32WriteWatchCleanup) error {
	var errs []error
	if attached {
		if _, routeErr := r.currentXDBGBits(); errors.Is(routeErr, ErrX32SessionUnbound) {
			if err := r.clearWriteWatchBinding(request); err != nil {
				errs = append(errs, err)
			} else {
				cleanup.BackendReset = true
				cleanup.DebugSessionStopped = true
			}
			if len(errs) == 0 {
				cleanup.ResourcesReleased = true
				return nil
			}
			cleanup.Error = errors.Join(errs...).Error()
			return errors.Join(errs...)
		} else if routeErr != nil {
			errs = append(errs, routeErr)
		}
	}
	if breakpointSet {
		if err := r.deleteOwnedHardwareBreakpoint(ctx, request, "clear"); err != nil {
			errs = append(errs, err)
		} else {
			cleanup.HardwareBreakpointRemoved = true
		}
	}
	if attached {
		if _, err := r.callWriteWatchMutation(ctx, request, "stop", "StopDebug", map[string]any{}); err != nil {
			errs = append(errs, err)
		} else {
			cleanup.DebugSessionStopped = true
		}
	}
	if len(errs) > 0 {
		cleanup.Error = errors.Join(errs...).Error()
		return errors.Join(errs...)
	}
	cleanup.ResourcesReleased = true
	return nil
}

func (r *Runtime) clearWriteWatchBinding(request X32WriteWatchRequest) error {
	guard, err := r.mutationGuard()
	if err != nil {
		return err
	}
	return guard.clearBinding(x32GuardMetadata{
		PID: request.PID, ProcessKey: request.ProcessKey,
		Owner: request.Owner, LeaseID: request.LeaseID,
	})
}

func (r *Runtime) deleteOwnedHardwareBreakpoint(ctx context.Context, request X32WriteWatchRequest, suffix string) error {
	arguments := map[string]any{
		"address":        fmt.Sprintf("%X", request.Address),
		X32GuardArgument: writeWatchGuard(request, suffix),
	}
	guard, err := r.mutationGuard()
	if err != nil {
		return err
	}
	_, meta, err := extractX32Guard(arguments)
	if err != nil {
		return err
	}
	if err := validateX32Guard(meta); err != nil {
		return err
	}
	bits, err := guard.targetBits(meta)
	if err != nil {
		return err
	}
	currentBits, err := r.currentXDBGBits()
	if err != nil {
		return err
	}
	if bits != currentBits {
		return fmt.Errorf("%w: active architecture=%s requested architecture=%s", ErrX32SessionConflict, xdbgArchitectureName(currentBits), xdbgArchitectureName(bits))
	}
	target, err := r.xdbgBackend(bits)
	if err != nil {
		return err
	}
	result, err := guard.Call(ctx, "DeleteOwnedHardwareBreakpoint", arguments, func(callCtx context.Context, _ any) (*mcp.CallToolResult, error) {
		return callModuleBackend(callCtx, target, "x32dbg", "ExecuteDebuggerCommand", map[string]any{
			"command": fmt.Sprintf("bphc 0x%X", request.Address),
		})
	})
	if err != nil {
		return err
	}
	if result == nil {
		return errors.New("hardware breakpoint cleanup returned no result")
	}
	if result.IsError {
		return fmt.Errorf("hardware breakpoint cleanup failed: %s", resultText(result))
	}
	return nil
}

func (r *Runtime) captureWriteWatchEvent(ctx context.Context, request X32WriteWatchRequest, index int, before []byte, runResult *mcp.CallToolResult, memory memscan.ReadOnlyMemory) (X32WriteWatchEvent, error) {
	call := func(tool string) (*mcp.CallToolResult, error) {
		return r.callXDBG(ctx, tool, map[string]any{})
	}
	current, err := call("GetCurrentAddress")
	if err != nil {
		return X32WriteWatchEvent{}, err
	}
	registers, err := call("GetAllRegisters")
	if err != nil {
		return X32WriteWatchEvent{}, err
	}
	threads, err := call("GetThreads")
	if err != nil {
		return X32WriteWatchEvent{}, err
	}
	stack, err := call("GetCallStack")
	if err != nil {
		return X32WriteWatchEvent{}, err
	}
	debugState, err := call("GetDebugState")
	if err != nil {
		return X32WriteWatchEvent{}, err
	}
	eventLog, err := call("GetEventLog")
	if err != nil {
		return X32WriteWatchEvent{}, err
	}
	after, err := memory.Read(request.Address, request.Size)
	if err != nil {
		return X32WriteWatchEvent{}, fmt.Errorf("read watched bytes after event: %w", err)
	}
	ip, _ := extractCurrentAddress(resultPayload(current))
	if ip == 0 {
		ip, _ = extractCurrentAddress(resultPayload(registers))
	}
	threadID, _ := extractCurrentThreadID(resultPayload(threads))
	module, _ := moduleEvidenceForAddress(request.PID, ip)
	beforeHex := hex.EncodeToString(before)
	afterHex := hex.EncodeToString(after)
	return X32WriteWatchEvent{
		Index:              index,
		ObservedUTC:        time.Now().UTC().Format(time.RFC3339Nano),
		InstructionPointer: ip,
		InstructionHex:     formatOptionalAddress(ip),
		ThreadID:           threadID,
		Module:             module,
		BeforeHex:          beforeHex,
		AfterHex:           afterHex,
		ValueChanged:       !strings.EqualFold(beforeHex, afterHex),
		RunResult:          resultPayload(runResult),
		DebugState:         resultPayload(debugState),
		Registers:          resultPayload(registers),
		Threads:            resultPayload(threads),
		CallStack:          resultPayload(stack),
		EventLog:           resultPayload(eventLog),
	}, nil
}

func writeWatchGuard(request X32WriteWatchRequest, suffix string) map[string]any {
	return map[string]any{
		"pid":          request.PID,
		"process_key":  request.ProcessKey,
		"owner":        request.Owner,
		"lease_id":     request.LeaseID,
		"operation_id": request.OperationID + "." + suffix,
	}
}

func resultPayload(result *mcp.CallToolResult) any {
	if result == nil {
		return nil
	}
	if result.StructuredContent != nil {
		return result.StructuredContent
	}
	texts := make([]string, 0, len(result.Content))
	for _, item := range result.Content {
		if text, ok := item.(*mcp.TextContent); ok {
			texts = append(texts, text.Text)
		}
	}
	if len(texts) == 1 {
		var decoded any
		if json.Unmarshal([]byte(texts[0]), &decoded) == nil {
			return decoded
		}
		return texts[0]
	}
	return texts
}

func resultText(result *mcp.CallToolResult) string {
	payload := resultPayload(result)
	body, err := json.Marshal(payload)
	if err == nil {
		return string(body)
	}
	return fmt.Sprint(payload)
}

func resultContainsAddress(result *mcp.CallToolResult, address uint64) bool {
	return valueContainsAddress(resultPayload(result), address, false)
}

func valueContainsAddress(value any, address uint64, addressKey bool) bool {
	switch typed := value.(type) {
	case map[string]any:
		for key, nested := range typed {
			lower := strings.ToLower(key)
			keyLooksAddress := strings.Contains(lower, "address") || lower == "addr" || lower == "cip" || lower == "rip" || lower == "eip"
			if valueContainsAddress(nested, address, keyLooksAddress) {
				return true
			}
		}
	case []any:
		for _, nested := range typed {
			if valueContainsAddress(nested, address, addressKey) {
				return true
			}
		}
	case string:
		if addressKey {
			if parsed, ok := parseFlexibleUint(typed); ok && parsed == address {
				return true
			}
		}
	case float64:
		if addressKey && typed >= 0 && uint64(typed) == address {
			return true
		}
	}
	return false
}

func extractCurrentAddress(value any) (uint64, bool) {
	switch typed := value.(type) {
	case map[string]any:
		for _, key := range []string{"address", "current_address", "currentAddress", "cip", "rip", "eip", "instruction_pointer", "instructionPointer", "ip"} {
			if nested, ok := typed[key]; ok {
				if parsed, ok := parseAnyUint(nested); ok {
					return parsed, true
				}
			}
		}
		for _, nested := range typed {
			if parsed, ok := extractCurrentAddress(nested); ok {
				return parsed, true
			}
		}
	case []any:
		for _, nested := range typed {
			if parsed, ok := extractCurrentAddress(nested); ok {
				return parsed, true
			}
		}
	default:
		return parseAnyUint(typed)
	}
	return 0, false
}

func extractCurrentThreadID(value any) (uint64, bool) {
	switch typed := value.(type) {
	case map[string]any:
		active := false
		for _, key := range []string{"current", "active", "selected", "isCurrent", "is_current"} {
			if raw, ok := typed[key]; ok {
				if flag, ok := raw.(bool); ok && flag {
					active = true
					break
				}
			}
		}
		if active {
			for _, key := range []string{"threadId", "thread_id", "tid", "id"} {
				if raw, ok := typed[key]; ok {
					if parsed, ok := parseAnyUint(raw); ok {
						return parsed, true
					}
				}
			}
		}
		for _, nested := range typed {
			if parsed, ok := extractCurrentThreadID(nested); ok {
				return parsed, true
			}
		}
	case []any:
		if len(typed) == 1 {
			if item, ok := typed[0].(map[string]any); ok {
				for _, key := range []string{"threadId", "thread_id", "tid", "id"} {
					if raw, ok := item[key]; ok {
						if parsed, ok := parseAnyUint(raw); ok {
							return parsed, true
						}
					}
				}
			}
		}
		for _, nested := range typed {
			if parsed, ok := extractCurrentThreadID(nested); ok {
				return parsed, true
			}
		}
	}
	return 0, false
}

func parseAnyUint(value any) (uint64, bool) {
	switch typed := value.(type) {
	case string:
		return parseFlexibleUint(typed)
	case float64:
		if typed >= 0 {
			return uint64(typed), true
		}
	case uint64:
		return typed, true
	case uint32:
		return uint64(typed), true
	case int:
		if typed >= 0 {
			return uint64(typed), true
		}
	case int64:
		if typed >= 0 {
			return uint64(typed), true
		}
	}
	return 0, false
}

func parseFlexibleUint(text string) (uint64, bool) {
	text = strings.TrimSpace(text)
	if text == "" {
		return 0, false
	}
	if parsed, err := strconv.ParseUint(text, 0, 64); err == nil {
		return parsed, true
	}
	text = strings.TrimPrefix(strings.TrimPrefix(text, "0x"), "0X")
	if parsed, err := strconv.ParseUint(text, 16, 64); err == nil {
		return parsed, true
	}
	return 0, false
}

func detachedWriteWatchEffectContext(parent context.Context, limit time.Duration) (context.Context, context.CancelFunc) {
	deadline := time.Now().Add(limit)
	if parentDeadline, ok := parent.Deadline(); ok && parentDeadline.Before(deadline) {
		deadline = parentDeadline
	}
	return context.WithDeadline(context.Background(), deadline)
}

func isWriteWatchTimeoutOrCancel(err error, ctx context.Context) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || ctx.Err() != nil {
		return true
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "context deadline exceeded") || strings.Contains(message, "context canceled") || strings.Contains(message, "context cancelled")
}

func formatOptionalAddress(address uint64) string {
	if address == 0 {
		return ""
	}
	return fmt.Sprintf("0x%X", address)
}
