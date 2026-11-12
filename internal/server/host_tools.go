package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"reverseresearch/internal/compatibility"
	"reverseresearch/internal/die"
	"reverseresearch/internal/hookplan"
	"reverseresearch/internal/memscan"
	"reverseresearch/internal/migration"
	"reverseresearch/internal/modules"
	"reverseresearch/internal/patchplan"
	"reverseresearch/internal/pointermap"
)

func (r *Runtime) addHostTools() {
	r.addTool(&mcp.Tool{
		Name:        "target_identify",
		Description: "Freeze a local target file identity before reverse engineering: resolved path, SHA-256, size, timestamp, and PE architecture/header/section metadata when applicable. Does not start a backend.",
		InputSchema: objectSchema(map[string]any{
			"path": map[string]any{"type": "string", "minLength": 1, "description": "Local file path to inspect."},
		}, "path"),
	}, func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			Path string `json:"path"`
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		identity, err := r.core.IdentifyContext(ctx, args.Path)
		if err != nil {
			return nil, err
		}
		return structuredResult(identity)
	})

	r.addTool(&mcp.Tool{
		Name:        "target_compare",
		Description: "Compare two local target files by frozen SHA-256/size identity and PE architecture metadata. Use this before porting behavior between game builds.",
		InputSchema: objectSchema(map[string]any{
			"left_path":  map[string]any{"type": "string", "minLength": 1},
			"right_path": map[string]any{"type": "string", "minLength": 1},
		}, "left_path", "right_path"),
	}, func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			LeftPath  string `json:"left_path"`
			RightPath string `json:"right_path"`
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		comparison, err := r.core.CompareContext(ctx, args.LeftPath, args.RightPath)
		if err != nil {
			return nil, err
		}
		return structuredResult(comparison)
	})

	r.addTool(&mcp.Tool{
		Name:        "task_route",
		Description: "Classify a reverse-engineering task through the canonical config/routes.json and return the selected capability/tools plus ranked alternatives. Use task_prepare when a Seep-Reverse-Lab playbook is also needed. Does not start a backend.",
		InputSchema: objectSchema(map[string]any{
			"text": map[string]any{"type": "string", "minLength": 1},
		}, "text"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			Text string `json:"text"`
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		result, err := r.core.Route(args.Text)
		if err != nil {
			return nil, err
		}
		return structuredResult(result)
	})

	r.addTool(&mcp.Tool{
		Name:        "task_prepare",
		Description: "Build the read-only Seep-Reverse-Lab work plan for a task: canonical route, platform playbook gates, current tool capability/provision status, and sandbox recommendation. Does not start analysis/debugger/browser backends.",
		InputSchema: objectSchema(map[string]any{
			"text": map[string]any{"type": "string", "minLength": 1},
		}, "text"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			Text string `json:"text"`
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		result, err := r.core.Prepare(args.Text)
		if err != nil {
			return nil, err
		}
		return structuredResult(result)
	})

	r.addTool(&mcp.Tool{
		Name:        "playbook_get",
		Description: "Read one machine-validated Seep-Reverse-Lab playbook by playbook_id or route_id. Returns the master skill path, platform reference, gates, failure reference and done criteria without starting a backend.",
		InputSchema: objectSchema(map[string]any{
			"playbook_id": map[string]any{"type": "string"},
			"route_id":    map[string]any{"type": "string"},
		}),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			PlaybookID string `json:"playbook_id"`
			RouteID    string `json:"route_id"`
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		playbookID := strings.TrimSpace(args.PlaybookID)
		routeID := strings.TrimSpace(args.RouteID)
		if (playbookID == "") == (routeID == "") {
			return nil, errors.New("exactly one of playbook_id or route_id is required")
		}
		if playbookID != "" {
			value, err := r.core.GetPlaybook(playbookID)
			if err != nil {
				return nil, err
			}
			return structuredResult(value)
		}
		value, ok, err := r.core.PlaybookForRoute(routeID)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("route %q has no playbook; do not force-fit it", routeID)
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "tool_index_scan",
		Description: "Refresh and return the machine-local ReverseResearch tool index before bootstrapping or guessing tool paths. This may update state/tool-index.json but does not install tools or start analysis/debugger backends.",
		InputSchema: objectSchema(map[string]any{}),
	}, func(_ context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		index, err := r.core.ScanTools()
		if err != nil {
			return nil, err
		}
		return structuredResult(index)
	})

	r.addTool(&mcp.Tool{
		Name:        "die_scan",
		Description: "Run the pinned Detect It Easy 3.21 CLI as a bounded, read-only static scan. Verifies the exact diec runtime SHA-256 and version, parses JSON output, and rejects target drift during analysis. Does not start a backend.",
		InputSchema: objectSchema(map[string]any{
			"path":       map[string]any{"type": "string", "minLength": 1, "description": "Local file path to scan."},
			"timeout_ms": map[string]any{"type": "integer", "minimum": 1, "maximum": 120000, "default": 15000},
			"verbose":    map[string]any{"type": "boolean", "default": false},
			"deep":       map[string]any{"type": "boolean", "default": false},
			"heuristic":  map[string]any{"type": "boolean", "default": false},
			"all_types":  map[string]any{"type": "boolean", "default": false},
			"entropy":    map[string]any{"type": "boolean", "default": false},
			"info":       map[string]any{"type": "boolean", "default": false},
		}, "path"),
	}, func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			Path      string `json:"path"`
			TimeoutMS int64  `json:"timeout_ms"`
			Verbose   bool   `json:"verbose"`
			Deep      bool   `json:"deep"`
			Heuristic bool   `json:"heuristic"`
			AllTypes  bool   `json:"all_types"`
			Entropy   bool   `json:"entropy"`
			Info      bool   `json:"info"`
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		timeout := die.DefaultTimeout
		if args.TimeoutMS > 0 {
			timeout = time.Duration(args.TimeoutMS) * time.Millisecond
		}
		report, err := r.core.ScanDIE(ctx, args.Path, die.ScanOptions{
			Timeout: timeout, Verbose: args.Verbose, Deep: args.Deep, Heuristic: args.Heuristic,
			AllTypes: args.AllTypes, Entropy: args.Entropy, Info: args.Info,
		})
		if err != nil {
			return nil, err
		}
		return structuredResult(report)
	})

	r.addTool(&mcp.Tool{
		Name:        "process_identify",
		Description: "Inspect a live Windows process instance and freeze PID, creation time, main-module base, executable SHA-256, and PE architecture. Does not attach a debugger or start a backend.",
		InputSchema: objectSchema(map[string]any{
			"pid": map[string]any{"type": "integer", "minimum": 1},
		}, "pid"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			PID uint32 `json:"pid"`
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		identity, err := r.core.InspectProcess(args.PID)
		if err != nil {
			return nil, err
		}
		return structuredResult(identity)
	})

	r.addTool(&mcp.Tool{
		Name:        "process_debug_route",
		Description: "Preview the debugger backend for a live Windows process from its freshly inspected PE identity. Returns x32dbg or x64dbg routing without attaching a debugger or starting any backend.",
		InputSchema: objectSchema(map[string]any{
			"pid": map[string]any{"type": "integer", "minimum": 1},
		}, "pid"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			PID uint32 `json:"pid"`
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		route, err := r.core.DebugRouteProcess(args.PID)
		if err != nil {
			return nil, err
		}
		return structuredResult(route)
	})

	r.addTool(&mcp.Tool{
		Name:        "memory_scan_start",
		Description: "Start a bounded read-only live-process value scan bound to a fresh process_key. Persists a versioned candidate set with region identity/currentness metadata and never attaches or starts a debugger.",
		InputSchema: objectSchema(map[string]any{
			"pid":            map[string]any{"type": "integer", "minimum": 1},
			"process_key":    map[string]any{"type": "string", "minLength": 1},
			"value_type":     map[string]any{"type": "string", "enum": []string{"u8", "i8", "u16", "i16", "u32", "i32", "u64", "i64", "f32", "f64"}},
			"mode":           map[string]any{"type": "string", "enum": []string{"exact", "unknown"}},
			"value":          map[string]any{"type": "string"},
			"start_address":  map[string]any{"type": "integer", "minimum": 0},
			"end_address":    map[string]any{"type": "integer", "minimum": 0},
			"alignment":      map[string]any{"type": "integer", "minimum": 0, "maximum": 8},
			"max_bytes":      map[string]any{"type": "integer", "minimum": 1, "maximum": memscan.MaxScanBytes},
			"max_candidates": map[string]any{"type": "integer", "minimum": 1, "maximum": memscan.MaxCandidates},
			"timeout_ms":     map[string]any{"type": "integer", "minimum": 1, "maximum": 30000},
		}, "pid", "process_key", "value_type", "mode"),
	}, func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			PID           uint32 `json:"pid"`
			ProcessKey    string `json:"process_key"`
			ValueType     string `json:"value_type"`
			Mode          string `json:"mode"`
			Value         string `json:"value"`
			StartAddress  uint64 `json:"start_address"`
			EndAddress    uint64 `json:"end_address"`
			Alignment     int    `json:"alignment"`
			MaxBytes      uint64 `json:"max_bytes"`
			MaxCandidates int    `json:"max_candidates"`
			TimeoutMS     int64  `json:"timeout_ms"`
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		timeout := memscan.DefaultTimeout
		if args.TimeoutMS > 0 {
			timeout = time.Duration(args.TimeoutMS) * time.Millisecond
		}
		result, err := r.core.StartMemoryScan(ctx, memscan.StartRequest{
			PID: args.PID, ProcessKey: args.ProcessKey, ValueType: args.ValueType,
			Mode: memscan.Mode(args.Mode), Value: args.Value,
			StartAddress: args.StartAddress, EndAddress: args.EndAddress, Alignment: args.Alignment,
			MaxBytes: args.MaxBytes, MaxCandidates: args.MaxCandidates, Timeout: timeout,
		})
		if err != nil {
			return nil, err
		}
		return structuredResult(result)
	})

	r.addTool(&mcp.Tool{
		Name:        "memory_scan_refine",
		Description: "Refine a persisted live-memory candidate set by exact, changed, unchanged, increased, or decreased value. Requires the expected candidate-set version and rejects stale region identity.",
		InputSchema: objectSchema(map[string]any{
			"scan_id":          map[string]any{"type": "string", "minLength": 1},
			"expected_version": map[string]any{"type": "integer", "minimum": 1},
			"mode":             map[string]any{"type": "string", "enum": []string{"exact", "changed", "unchanged", "increased", "decreased"}},
			"value":            map[string]any{"type": "string"},
			"timeout_ms":       map[string]any{"type": "integer", "minimum": 1, "maximum": 30000},
		}, "scan_id", "expected_version", "mode"),
	}, func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			ScanID          string `json:"scan_id"`
			ExpectedVersion int    `json:"expected_version"`
			Mode            string `json:"mode"`
			Value           string `json:"value"`
			TimeoutMS       int64  `json:"timeout_ms"`
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		timeout := memscan.DefaultTimeout
		if args.TimeoutMS > 0 {
			timeout = time.Duration(args.TimeoutMS) * time.Millisecond
		}
		result, err := r.core.RefineMemoryScan(ctx, memscan.RefineRequest{
			ScanID: args.ScanID, ExpectedVersion: args.ExpectedVersion,
			Mode: memscan.Mode(args.Mode), Value: args.Value, Timeout: timeout,
		})
		if err != nil {
			return nil, err
		}
		return structuredResult(result)
	})

	r.addTool(&mcp.Tool{
		Name:        "memory_scan_get",
		Description: "Read a persisted memory scan summary and bounded candidate sample without reading or mutating the target process.",
		InputSchema: objectSchema(map[string]any{
			"scan_id":      map[string]any{"type": "string", "minLength": 1},
			"sample_limit": map[string]any{"type": "integer", "minimum": 1, "maximum": memscan.MaxSampleLimit},
		}, "scan_id"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			ScanID      string `json:"scan_id"`
			SampleLimit int    `json:"sample_limit"`
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		result, err := r.core.GetMemoryScan(args.ScanID, args.SampleLimit)
		if err != nil {
			return nil, err
		}
		return structuredResult(result)
	})

	r.addTool(&mcp.Tool{
		Name:        "memory_scan_delete",
		Description: "Explicitly delete one persisted memory scan to release durable quota. Requires the current expected_version; deletion is never automatic.",
		InputSchema: objectSchema(map[string]any{
			"scan_id":          map[string]any{"type": "string", "minLength": 1},
			"expected_version": map[string]any{"type": "integer", "minimum": 1},
		}, "scan_id", "expected_version"),
	}, func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args memscan.DeleteRequest
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		result, err := r.core.DeleteMemoryScan(ctx, args)
		if err != nil {
			return nil, err
		}
		return structuredResult(result)
	})
	r.addTool(&mcp.Tool{
		Name:        "pointer_map_build",
		Description: "Build a bounded read-only reverse pointer map for one live target address. Searches pointer-sized values plus positive offsets, retains module-RVA anchored chains, binds the source process identity, and never attaches or starts a debugger.",
		InputSchema: objectSchema(map[string]any{
			"pid":            map[string]any{"type": "integer", "minimum": 1},
			"process_key":    map[string]any{"type": "string", "minLength": 1},
			"target_address": map[string]any{"type": "integer", "minimum": 1},
			"start_address":  map[string]any{"type": "integer", "minimum": 0},
			"end_address":    map[string]any{"type": "integer", "minimum": 0},
			"max_offset":     map[string]any{"type": "integer", "minimum": 0, "maximum": pointermap.MaxOffset},
			"max_depth":      map[string]any{"type": "integer", "minimum": 1, "maximum": pointermap.MaxDepth},
			"alignment":      map[string]any{"type": "integer", "minimum": 0, "maximum": 8},
			"max_bytes":      map[string]any{"type": "integer", "minimum": 1, "maximum": pointermap.MaxBytes},
			"max_nodes":      map[string]any{"type": "integer", "minimum": 1, "maximum": pointermap.MaxNodes},
			"max_chains":     map[string]any{"type": "integer", "minimum": 1, "maximum": pointermap.MaxChains},
			"timeout_ms":     map[string]any{"type": "integer", "minimum": 1, "maximum": 60000},
		}, "pid", "process_key", "target_address"),
	}, func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			PID           uint32 `json:"pid"`
			ProcessKey    string `json:"process_key"`
			TargetAddress uint64 `json:"target_address"`
			StartAddress  uint64 `json:"start_address"`
			EndAddress    uint64 `json:"end_address"`
			MaxOffset     uint64 `json:"max_offset"`
			MaxDepth      int    `json:"max_depth"`
			Alignment     int    `json:"alignment"`
			MaxBytes      uint64 `json:"max_bytes"`
			MaxNodes      int    `json:"max_nodes"`
			MaxChains     int    `json:"max_chains"`
			TimeoutMS     int64  `json:"timeout_ms"`
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		timeout := pointermap.DefaultTimeout
		if args.TimeoutMS > 0 {
			timeout = time.Duration(args.TimeoutMS) * time.Millisecond
		}
		result, err := r.core.BuildPointerMap(ctx, pointermap.BuildRequest{
			PID: args.PID, ProcessKey: args.ProcessKey, TargetAddress: args.TargetAddress,
			StartAddress: args.StartAddress, EndAddress: args.EndAddress,
			MaxOffset: args.MaxOffset, MaxDepth: args.MaxDepth, Alignment: args.Alignment,
			MaxBytes: args.MaxBytes, MaxNodes: args.MaxNodes, MaxChains: args.MaxChains,
			Timeout: timeout,
		})
		if err != nil {
			return nil, err
		}
		return structuredResult(result)
	})

	r.addTool(&mcp.Tool{
		Name:        "pointer_map_get",
		Description: "Read one persisted pointer map summary and bounded module-anchored chain sample without touching the target process.",
		InputSchema: objectSchema(map[string]any{
			"map_id":       map[string]any{"type": "string", "minLength": 1},
			"sample_limit": map[string]any{"type": "integer", "minimum": 1, "maximum": pointermap.MaxSample},
		}, "map_id"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			MapID       string `json:"map_id"`
			SampleLimit int    `json:"sample_limit"`
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		result, err := r.core.GetPointerMap(args.MapID, args.SampleLimit)
		if err != nil {
			return nil, err
		}
		return structuredResult(result)
	})

	r.addTool(&mcp.Tool{
		Name:        "pointer_map_delete",
		Description: "Explicitly delete one persisted pointer map to release durable quota. Requires the current expected_version; deletion is never automatic.",
		InputSchema: objectSchema(map[string]any{
			"map_id":           map[string]any{"type": "string", "minLength": 1},
			"expected_version": map[string]any{"type": "integer", "minimum": 1},
		}, "map_id", "expected_version"),
	}, func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args pointermap.DeleteRequest
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		result, err := r.core.DeletePointerMap(ctx, args)
		if err != nil {
			return nil, err
		}
		return structuredResult(result)
	})
	r.addTool(&mcp.Tool{
		Name:        "pointer_map_verify",
		Description: "Verify persisted module-RVA pointer chains against a fresh live process identity. Rebases module roots, rechecks module file identity, dereferences each level read-only, and optionally requires the resolved address to equal a new target.",
		InputSchema: objectSchema(map[string]any{
			"map_id":         map[string]any{"type": "string", "minLength": 1},
			"pid":            map[string]any{"type": "integer", "minimum": 1},
			"process_key":    map[string]any{"type": "string", "minLength": 1},
			"target_address": map[string]any{"type": "integer", "minimum": 0},
			"timeout_ms":     map[string]any{"type": "integer", "minimum": 1, "maximum": 60000},
			"sample_limit":   map[string]any{"type": "integer", "minimum": 1, "maximum": pointermap.MaxSample},
		}, "map_id", "pid", "process_key"),
	}, func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			MapID         string `json:"map_id"`
			PID           uint32 `json:"pid"`
			ProcessKey    string `json:"process_key"`
			TargetAddress uint64 `json:"target_address"`
			TimeoutMS     int64  `json:"timeout_ms"`
			SampleLimit   int    `json:"sample_limit"`
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		timeout := pointermap.DefaultTimeout
		if args.TimeoutMS > 0 {
			timeout = time.Duration(args.TimeoutMS) * time.Millisecond
		}
		result, err := r.core.VerifyPointerMap(ctx, pointermap.VerifyRequest{
			MapID: args.MapID, PID: args.PID, ProcessKey: args.ProcessKey,
			TargetAddress: args.TargetAddress, Timeout: timeout, SampleLimit: args.SampleLimit,
		})
		if err != nil {
			return nil, err
		}
		return structuredResult(result)
	})

	r.addTool(&mcp.Tool{
		Name:        "write_watch",
		Description: "Observe bounded writes to one aligned address using a task-owned x32dbg hardware breakpoint. Requires a current process-control lease, creates and stops its own debugger session, captures instruction/module-RVA/thread/register/call-stack evidence, and removes only the breakpoint created by this watch.",
		InputSchema: objectSchema(map[string]any{
			"pid":          map[string]any{"type": "integer", "minimum": 1},
			"process_key":  map[string]any{"type": "string", "minLength": 64, "maxLength": 64},
			"owner":        map[string]any{"type": "string", "minLength": 1, "maxLength": 160},
			"lease_id":     map[string]any{"type": "string", "minLength": 1, "maxLength": 128},
			"operation_id": map[string]any{"type": "string", "minLength": 1, "maxLength": 140},
			"address":      map[string]any{"type": "string", "minLength": 1, "description": "Decimal or 0x-prefixed watched address."},
			"size":         map[string]any{"type": "integer", "enum": []int{1, 2, 4, 8}, "default": 1},
			"timeout_ms":   map[string]any{"type": "integer", "minimum": 1, "maximum": 120000, "default": 30000},
			"max_events":   map[string]any{"type": "integer", "minimum": 1, "maximum": modules.MaxWriteWatchEvents, "default": modules.DefaultWriteWatchMaxEvents},
		}, "pid", "process_key", "owner", "lease_id", "operation_id", "address"),
	}, func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			PID         uint32 `json:"pid"`
			ProcessKey  string `json:"process_key"`
			Owner       string `json:"owner"`
			LeaseID     string `json:"lease_id"`
			OperationID string `json:"operation_id"`
			Address     string `json:"address"`
			Size        int    `json:"size"`
			TimeoutMS   int64  `json:"timeout_ms"`
			MaxEvents   int    `json:"max_events"`
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		address, err := strconv.ParseUint(strings.TrimSpace(args.Address), 0, 64)
		if err != nil || address == 0 {
			return nil, fmt.Errorf("invalid write watch address %q", args.Address)
		}
		timeout := modules.DefaultWriteWatchTimeout
		if args.TimeoutMS > 0 {
			timeout = time.Duration(args.TimeoutMS) * time.Millisecond
		}
		report, err := r.modules.ObserveWrite(ctx, modules.X32WriteWatchRequest{
			PID: args.PID, ProcessKey: args.ProcessKey, Owner: args.Owner, LeaseID: args.LeaseID,
			OperationID: args.OperationID, Address: address, Size: args.Size,
			Timeout: timeout, MaxEvents: args.MaxEvents, StopOnWrite: true,
		})
		if err != nil {
			return nil, err
		}
		return structuredResult(report)
	})

	r.addTool(&mcp.Tool{
		Name:        "hook_plan",
		Description: "Plan a same-module PE rel32 detour without modifying the file. Proves a whole-instruction overwrite boundary, freezes original bytes and PE structure, and rejects overlap with active hook intervals.",
		InputSchema: objectSchema(map[string]any{
			"path":            map[string]any{"type": "string", "minLength": 1},
			"source_rva":      map[string]any{"type": "integer", "minimum": 0, "maximum": 4294967295},
			"destination_rva": map[string]any{"type": "integer", "minimum": 0, "maximum": 4294967295},
			"expected_hex":    map[string]any{"type": "string"},
			"description":     map[string]any{"type": "string"},
		}, "path", "source_rva", "destination_rva"),
	}, func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args hookplan.PlanRequest
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		hook, err := r.core.PlanHook(ctx, args)
		if err != nil {
			return nil, err
		}
		return structuredResult(hook)
	})

	r.addTool(&mcp.Tool{
		Name:        "hook_get",
		Description: "Read one persisted hook plan and its versioned lifecycle state without modifying the target.",
		InputSchema: objectSchema(map[string]any{
			"hook_id": map[string]any{"type": "string", "minLength": 1},
		}, "hook_id"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			HookID string `json:"hook_id"`
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		hook, err := r.core.GetHook(args.HookID)
		if err != nil {
			return nil, err
		}
		return structuredResult(hook)
	})

	r.addTool(&mcp.Tool{
		Name:        "hook_list",
		Description: "List persisted hook intervals, optionally filtered to one target path. Does not modify files or debugger state.",
		InputSchema: objectSchema(map[string]any{
			"path": map[string]any{"type": "string"},
		}),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			Path string `json:"path"`
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		hooks, err := r.core.ListHooks(args.Path)
		if err != nil {
			return nil, err
		}
		return structuredResult(map[string]any{"hooks": hooks, "count": len(hooks)})
	})

	r.addTool(&mcp.Tool{
		Name:        "hook_apply",
		Description: "Apply one planned PE detour in-place only after exact version, operation identity, PE structure and frozen original bytes are revalidated. Requires explicit confirmation.",
		InputSchema: objectSchema(map[string]any{
			"hook_id":          map[string]any{"type": "string", "minLength": 1},
			"expected_version": map[string]any{"type": "integer", "minimum": 1},
			"operation_id":     map[string]any{"type": "string", "minLength": 1, "maxLength": 140},
			"confirm_in_place": map[string]any{"type": "boolean"},
		}, "hook_id", "expected_version", "operation_id", "confirm_in_place"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args hookplan.ApplyRequest
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		hook, err := r.core.ApplyHook(args)
		if err != nil {
			return nil, err
		}
		return structuredResult(hook)
	})

	r.addTool(&mcp.Tool{
		Name:        "hook_verify",
		Description: "Verify PE structure and current bytes for one hook, classifying the source interval as original, patch, or unknown without modifying the target.",
		InputSchema: objectSchema(map[string]any{
			"hook_id": map[string]any{"type": "string", "minLength": 1},
		}, "hook_id"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			HookID string `json:"hook_id"`
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		result, err := r.core.VerifyHook(args.HookID)
		if err != nil {
			return nil, err
		}
		return structuredResult(result)
	})

	r.addTool(&mcp.Tool{
		Name:        "hook_rollback",
		Description: "Rollback an applied hook only when the current bytes still match the exact recorded detour. Uses version and operation identities for crash-safe retry.",
		InputSchema: objectSchema(map[string]any{
			"hook_id":          map[string]any{"type": "string", "minLength": 1},
			"expected_version": map[string]any{"type": "integer", "minimum": 1},
			"operation_id":     map[string]any{"type": "string", "minLength": 1, "maxLength": 140},
		}, "hook_id", "expected_version", "operation_id"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args hookplan.RollbackRequest
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		hook, err := r.core.RollbackHook(args)
		if err != nil {
			return nil, err
		}
		return structuredResult(hook)
	})

	r.addTool(&mcp.Tool{
		Name:        "hook_cancel",
		Description: "Cancel a still-planned hook interval so it no longer blocks future overlapping plans. Does not modify the target file.",
		InputSchema: objectSchema(map[string]any{
			"hook_id":          map[string]any{"type": "string", "minLength": 1},
			"expected_version": map[string]any{"type": "integer", "minimum": 1},
		}, "hook_id", "expected_version"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args hookplan.CancelRequest
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		hook, err := r.core.CancelHook(args)
		if err != nil {
			return nil, err
		}
		return structuredResult(hook)
	})

	r.addTool(&mcp.Tool{
		Name:        "compatibility_add",
		Description: "Persist one DLL/Hook compatibility record bound to the exact module SHA-256 and optional guarded hook/case evidence. A compatible outcome is accepted only with runtime-verified case evidence including at least one referenced evidence item whose kind is runtime or runtime-verification; merely recording a note never upgrades compatibility.",
		InputSchema: objectSchema(map[string]any{
			"game":         map[string]any{"type": "string", "minLength": 1},
			"build":        map[string]any{"type": "string", "minLength": 1},
			"module_path":  map[string]any{"type": "string", "minLength": 1},
			"module_role":  map[string]any{"type": "string"},
			"hook_id":      map[string]any{"type": "string"},
			"hook_name":    map[string]any{"type": "string"},
			"outcome":      map[string]any{"type": "string", "enum": []string{"unknown", "candidate", "compatible", "incompatible"}, "default": "unknown"},
			"validation":   map[string]any{"type": "string", "enum": []string{"record-only", "static-verified", "runtime-verified"}, "default": "record-only"},
			"case_id":      map[string]any{"type": "string"},
			"evidence_ids": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"notes":        map[string]any{"type": "string"},
		}, "game", "build", "module_path"),
	}, func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args compatibility.AddRequest
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		record, err := r.core.AddCompatibilityContext(ctx, args)
		if err != nil {
			return nil, err
		}
		return structuredResult(record)
	})

	r.addTool(&mcp.Tool{
		Name:        "compatibility_import",
		Description: "Import a JSON compatibility manifest. Relative module paths resolve against the manifest directory. Imported records retain their declared validation level and are never silently upgraded to compatible.",
		InputSchema: objectSchema(map[string]any{
			"manifest_path": map[string]any{"type": "string", "minLength": 1},
		}, "manifest_path"),
	}, func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			ManifestPath string `json:"manifest_path"`
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		result, err := r.core.ImportCompatibilityManifestContext(ctx, args.ManifestPath)
		if err != nil {
			return nil, err
		}
		return structuredResult(result)
	})

	r.addTool(&mcp.Tool{
		Name:        "compatibility_get",
		Description: "Read one immutable DLL/Hook compatibility record without revalidating the game or mutating any target.",
		InputSchema: objectSchema(map[string]any{
			"record_id": map[string]any{"type": "string", "minLength": 1},
		}, "record_id"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			RecordID string `json:"record_id"`
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		record, err := r.core.GetCompatibility(args.RecordID)
		if err != nil {
			return nil, err
		}
		return structuredResult(record)
	})

	r.addTool(&mcp.Tool{
		Name:        "compatibility_list",
		Description: "List DLL/Hook compatibility records by game/build/module SHA/hook/outcome/validation. This is record lookup only and performs no backend work.",
		InputSchema: objectSchema(map[string]any{
			"game":          map[string]any{"type": "string"},
			"build":         map[string]any{"type": "string"},
			"module_sha256": map[string]any{"type": "string"},
			"hook_id":       map[string]any{"type": "string"},
			"outcome":       map[string]any{"type": "string", "enum": []string{"", "unknown", "candidate", "compatible", "incompatible"}},
			"validation":    map[string]any{"type": "string", "enum": []string{"", "record-only", "static-verified", "runtime-verified"}},
			"limit":         map[string]any{"type": "integer", "minimum": 1, "maximum": 1000, "default": 100},
		}),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args compatibility.Filter
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		records, err := r.core.ListCompatibility(args)
		if err != nil {
			return nil, err
		}
		return structuredResult(map[string]any{"records": records, "count": len(records)})
	})

	r.addTool(&mcp.Tool{
		Name:        "compatibility_verify",
		Description: "Audit one compatibility record against current module identity, hook binding, and linked case/evidence. Never reruns the game; compatibility_revalidated is always false.",
		InputSchema: objectSchema(map[string]any{
			"record_id": map[string]any{"type": "string", "minLength": 1},
		}, "record_id"),
	}, func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			RecordID string `json:"record_id"`
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		result, err := r.core.VerifyCompatibilityContext(ctx, args.RecordID)
		if err != nil {
			return nil, err
		}
		return structuredResult(result)
	})

	r.addTool(&mcp.Tool{
		Name:        "semantic_sync_preview",
		Description: "Preview non-destructive migration of mapped function names/comments and structures between versions. Existing target user names and comments are preserved; conflicts are reported. This tool never starts Ghidra and never writes either database.",
		InputSchema: objectSchema(map[string]any{
			"migration": map[string]any{"type": "object"},
			"source":    map[string]any{"type": "object"},
			"target":    map[string]any{"type": "object"},
		}, "migration", "source", "target"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args migration.SyncPreviewRequest
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		result, err := r.core.PreviewSemanticSync(args)
		if err != nil {
			return nil, err
		}
		return structuredResult(result)
	})

	r.addTool(&mcp.Tool{
		Name:        "process_control_acquire",
		Description: "Acquire the cooperating-process control lease for an already identified process instance. The process_key must match a fresh process identity check; PID reuse or image/base drift fails closed.",
		InputSchema: objectSchema(map[string]any{
			"pid":         map[string]any{"type": "integer", "minimum": 1},
			"process_key": map[string]any{"type": "string", "minLength": 1},
			"owner":       map[string]any{"type": "string", "minLength": 1, "maxLength": 160},
		}, "pid", "process_key", "owner"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			PID        uint32 `json:"pid"`
			ProcessKey string `json:"process_key"`
			Owner      string `json:"owner"`
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		lease, err := r.core.AcquireProcessControl(args.PID, args.ProcessKey, args.Owner)
		if err != nil {
			return nil, err
		}
		return structuredResult(lease)
	})

	r.addTool(&mcp.Tool{
		Name:        "process_control_get",
		Description: "Read the current cooperating-process control lease after revalidating that the PID still identifies the same process instance.",
		InputSchema: objectSchema(map[string]any{
			"pid": map[string]any{"type": "integer", "minimum": 1},
		}, "pid"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			PID uint32 `json:"pid"`
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		lease, err := r.core.GetProcessControl(args.PID)
		if err != nil {
			return nil, err
		}
		return structuredResult(lease)
	})

	r.addTool(&mcp.Tool{
		Name:        "process_control_release",
		Description: "Release a cooperating-process control lease only when PID, process_key, owner, and lease_id all match the persisted lease. The lease_id prevents stale same-owner release requests from deleting a newer lease.",
		InputSchema: objectSchema(map[string]any{
			"pid":         map[string]any{"type": "integer", "minimum": 1},
			"process_key": map[string]any{"type": "string", "minLength": 1},
			"owner":       map[string]any{"type": "string", "minLength": 1, "maxLength": 160},
			"lease_id":    map[string]any{"type": "string", "minLength": 1},
		}, "pid", "process_key", "owner", "lease_id"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			PID        uint32 `json:"pid"`
			ProcessKey string `json:"process_key"`
			Owner      string `json:"owner"`
			LeaseID    string `json:"lease_id"`
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		if err := r.core.ReleaseProcessControl(args.PID, args.ProcessKey, args.Owner, args.LeaseID); err != nil {
			return nil, err
		}
		return structuredResult(map[string]any{"released": true, "pid": args.PID, "process_key": args.ProcessKey, "owner": args.Owner, "lease_id": args.LeaseID})
	})

	r.addTool(&mcp.Tool{
		Name:        "patch_plan",
		Description: "Create a guarded same-length file patch plan. Supports one edit or a canonicalized composite of disjoint edits. The exact source SHA-256 and all expected bytes must match before a plan is accepted. This does not modify the target file.",
		InputSchema: patchPlanSchema(),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args patchplan.PlanRequest
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		plan, err := r.core.PlanPatch(args)
		if err != nil {
			return nil, err
		}
		return structuredResult(plan)
	})

	r.addTool(&mcp.Tool{
		Name:        "patch_get",
		Description: "Read a persisted patch plan and its lifecycle state without modifying the target.",
		InputSchema: planIDSchema(),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		planID, err := decodePlanID(request)
		if err != nil {
			return nil, err
		}
		plan, err := r.core.GetPatch(planID)
		if err != nil {
			return nil, err
		}
		return structuredResult(plan)
	})

	r.addTool(&mcp.Tool{
		Name:        "patch_dry_run",
		Description: "Re-check a patch plan against the current source hash, size, and expected bytes. Fails closed on any drift and never writes the target.",
		InputSchema: planIDSchema(),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		planID, err := decodePlanID(request)
		if err != nil {
			return nil, err
		}
		result, err := r.core.DryRunPatch(planID)
		if err != nil {
			return nil, err
		}
		return structuredResult(result)
	})

	r.addTool(&mcp.Tool{
		Name:        "patch_apply",
		Description: "Apply a guarded patch after a fresh identity/expected-byte check. Default mode requires an explicit output_path and leaves the source unchanged; source modification requires in_place=true.",
		InputSchema: objectSchema(map[string]any{
			"plan_id":      map[string]any{"type": "string", "minLength": 32, "maxLength": 32},
			"in_place":     map[string]any{"type": "boolean", "default": false},
			"output_path":  map[string]any{"type": "string", "description": "Required for copy mode; must not resolve to the source."},
			"operation_id": map[string]any{"type": "string", "minLength": 1, "maxLength": 160, "description": "Optional replay identity. Reusing it for a different request is rejected."},
		}, "plan_id"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args patchplan.ApplyRequest
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		plan, err := r.core.ApplyPatch(args)
		if err != nil {
			return nil, err
		}
		return structuredResult(plan)
	})

	r.addTool(&mcp.Tool{
		Name:        "patch_verify",
		Description: "Verify the current file identity and patched/original bytes against a persisted plan state.",
		InputSchema: planIDSchema(),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		planID, err := decodePlanID(request)
		if err != nil {
			return nil, err
		}
		result, err := r.core.VerifyPatch(planID)
		if err != nil {
			return nil, err
		}
		return structuredResult(result)
	})

	r.addTool(&mcp.Tool{
		Name:        "patch_rollback",
		Description: "Rollback an applied in-place patch only when the entire current file still matches the recorded applied SHA-256 and replacement bytes. Fails closed if any later change is detected.",
		InputSchema: objectSchema(map[string]any{
			"plan_id":      map[string]any{"type": "string", "minLength": 32, "maxLength": 32},
			"operation_id": map[string]any{"type": "string", "minLength": 1, "maxLength": 160, "description": "Optional replay identity. Reusing it for a different request is rejected."},
		}, "plan_id"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args patchplan.RollbackRequest
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		plan, err := r.core.RollbackPatchOperation(args)
		if err != nil {
			return nil, err
		}
		return structuredResult(plan)
	})
}

func objectSchema(properties map[string]any, required ...string) map[string]any {
	schema := map[string]any{
		"type":                 "object",
		"properties":           properties,
		"additionalProperties": false,
	}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

func patchPlanSchema() map[string]any {
	editSchema := map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"properties": map[string]any{
			"offset":          map[string]any{"type": "integer", "minimum": 0, "description": "Zero-based file offset."},
			"expected_hex":    map[string]any{"type": "string", "minLength": 2},
			"replacement_hex": map[string]any{"type": "string", "minLength": 2},
		},
		"required": []string{"offset", "expected_hex", "replacement_hex"},
	}
	schema := objectSchema(map[string]any{
		"path":            map[string]any{"type": "string", "minLength": 1},
		"offset":          map[string]any{"type": "integer", "minimum": 0, "description": "Zero-based file offset for a single edit."},
		"expected_hex":    map[string]any{"type": "string", "minLength": 2, "description": "Expected original bytes for a single edit."},
		"replacement_hex": map[string]any{"type": "string", "minLength": 2, "description": "Replacement bytes for a single edit. Must have the same byte length as expected_hex."},
		"edits":           map[string]any{"type": "array", "minItems": 1, "maxItems": 4096, "items": editSchema, "description": "Composite disjoint edits. Cannot be combined with the single-edit fields."},
		"description":     map[string]any{"type": "string"},
	}, "path")
	schema["oneOf"] = []any{
		map[string]any{"required": []string{"offset", "expected_hex", "replacement_hex"}},
		map[string]any{"required": []string{"edits"}},
	}
	return schema
}

func planIDSchema() map[string]any {
	return objectSchema(map[string]any{
		"plan_id": map[string]any{"type": "string", "minLength": 32, "maxLength": 32},
	}, "plan_id")
}

func decodePlanID(request *mcp.CallToolRequest) (string, error) {
	var args struct {
		PlanID string `json:"plan_id"`
	}
	if err := decodeArguments(request, &args); err != nil {
		return "", err
	}
	if args.PlanID == "" {
		return "", errors.New("plan_id is required")
	}
	return args.PlanID, nil
}

func decodeArguments(request *mcp.CallToolRequest, destination any) error {
	if request == nil || request.Params == nil {
		return errors.New("missing tool parameters")
	}
	body, err := json.Marshal(request.Params.Arguments)
	if err != nil {
		return fmt.Errorf("encode tool arguments: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode tool arguments: %w", err)
	}
	return nil
}

const (
	maxStructuredTextMirrorBytes = 256 << 10
	maxStructuredMirrorDepth     = 64
)

var (
	jsonMarshalerType  = reflect.TypeOf((*json.Marshaler)(nil)).Elem()
	jsonRawMessageType = reflect.TypeOf(json.RawMessage{})
	timeType           = reflect.TypeOf(time.Time{})
)

func structuredResult(value any) (*mcp.CallToolResult, error) {
	text := fmt.Sprintf(
		"{\"notice\":\"full result is available in structuredContent\",\"text_mirror_limit_bytes\":%d}",
		maxStructuredTextMirrorBytes,
	)
	if structuredMirrorWithinLimit(reflect.ValueOf(value), maxStructuredTextMirrorBytes, 0) {
		body, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		if len(body) <= maxStructuredTextMirrorBytes {
			text = string(body)
		} else {
			text = fmt.Sprintf(
				"{\"notice\":\"full result is available in structuredContent\",\"json_bytes\":%d}",
				len(body),
			)
		}
	}
	return &mcp.CallToolResult{
		Content:           []mcp.Content{&mcp.TextContent{Text: text}},
		StructuredContent: value,
	}, nil
}

// structuredMirrorWithinLimit performs a conservative, allocation-light
// preflight before json.Marshal. Large results keep only StructuredContent and
// never allocate a second full JSON/text copy merely for the compatibility
// text mirror.
func structuredMirrorWithinLimit(value reflect.Value, remaining int, depth int) bool {
	_, ok := consumeStructuredMirrorBudget(value, remaining, depth)
	return ok
}

func consumeStructuredMirrorBudget(value reflect.Value, remaining int, depth int) (int, bool) {
	if remaining < 0 || depth > maxStructuredMirrorDepth {
		return remaining, false
	}
	if !value.IsValid() {
		return consumeStructuredBytes(remaining, 4)
	}
	for value.Kind() == reflect.Interface {
		if value.IsNil() {
			return consumeStructuredBytes(remaining, 4)
		}
		value = value.Elem()
	}
	if value.Type() == timeType {
		return consumeStructuredBytes(remaining, 40)
	}
	if value.Type() == jsonRawMessageType {
		return consumeStructuredBytes(remaining, value.Len())
	}
	if value.CanInterface() {
		if value.Type().Implements(jsonMarshalerType) {
			return remaining, false
		}
		if value.Kind() != reflect.Pointer && reflect.PointerTo(value.Type()).Implements(jsonMarshalerType) {
			return remaining, false
		}
	}

	switch value.Kind() {
	case reflect.Pointer:
		if value.IsNil() {
			return consumeStructuredBytes(remaining, 4)
		}
		return consumeStructuredMirrorBudget(value.Elem(), remaining, depth+1)
	case reflect.Bool:
		return consumeStructuredBytes(remaining, 5)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64:
		return consumeStructuredBytes(remaining, 32)
	case reflect.String:
		return consumeStructuredBytes(remaining, 2+6*value.Len())
	case reflect.Slice:
		if value.IsNil() {
			return consumeStructuredBytes(remaining, 4)
		}
		if value.Type().Elem().Kind() == reflect.Uint8 {
			return consumeStructuredBytes(remaining, 2+4*((value.Len()+2)/3))
		}
		fallthrough
	case reflect.Array:
		var ok bool
		remaining, ok = consumeStructuredBytes(remaining, 2)
		if !ok {
			return remaining, false
		}
		for i := 0; i < value.Len(); i++ {
			if i > 0 {
				remaining, ok = consumeStructuredBytes(remaining, 1)
				if !ok {
					return remaining, false
				}
			}
			remaining, ok = consumeStructuredMirrorBudget(value.Index(i), remaining, depth+1)
			if !ok {
				return remaining, false
			}
		}
		return remaining, true
	case reflect.Map:
		if value.IsNil() {
			return consumeStructuredBytes(remaining, 4)
		}
		var ok bool
		remaining, ok = consumeStructuredBytes(remaining, 2)
		if !ok {
			return remaining, false
		}
		iter := value.MapRange()
		first := true
		for iter.Next() {
			if !first {
				remaining, ok = consumeStructuredBytes(remaining, 1)
				if !ok {
					return remaining, false
				}
			}
			first = false
			key := iter.Key()
			switch key.Kind() {
			case reflect.String:
				remaining, ok = consumeStructuredBytes(remaining, 2+6*key.Len()+1)
			case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
				reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
				remaining, ok = consumeStructuredBytes(remaining, 34)
			default:
				return remaining, false
			}
			if !ok {
				return remaining, false
			}
			remaining, ok = consumeStructuredMirrorBudget(iter.Value(), remaining, depth+1)
			if !ok {
				return remaining, false
			}
		}
		return remaining, true
	case reflect.Struct:
		var ok bool
		remaining, ok = consumeStructuredBytes(remaining, 2)
		if !ok {
			return remaining, false
		}
		first := true
		for i := 0; i < value.NumField(); i++ {
			fieldType := value.Type().Field(i)
			if fieldType.PkgPath != "" {
				continue
			}
			tag := fieldType.Tag.Get("json")
			name := strings.Split(tag, ",")[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = fieldType.Name
			}
			if !first {
				remaining, ok = consumeStructuredBytes(remaining, 1)
				if !ok {
					return remaining, false
				}
			}
			first = false
			remaining, ok = consumeStructuredBytes(remaining, 2+6*len(name)+1)
			if !ok {
				return remaining, false
			}
			remaining, ok = consumeStructuredMirrorBudget(value.Field(i), remaining, depth+1)
			if !ok {
				return remaining, false
			}
		}
		return remaining, true
	default:
		// Channels, funcs, complex numbers and other unsupported kinds would
		// fail json.Marshal; do not risk an unbounded mirror attempt here.
		return remaining, false
	}
}

func consumeStructuredBytes(remaining, size int) (int, bool) {
	if size < 0 || size > remaining {
		return remaining, false
	}
	return remaining - size, true
}
