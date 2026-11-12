package server

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	researchcore "reverseresearch/internal/core"
)

func (r *Runtime) addP2SecurityTools() {
	r.addTool(&mcp.Tool{
		Name:        "attack_graph_import",
		Description: "Import a bounded content-addressed attack-path graph and optionally compute one bounded directed path. Graph analysis is observation-only and does not authorize exploitation.",
		InputSchema: objectSchema(map[string]any{
			"path":      map[string]any{"type": "string", "minLength": 1},
			"case_id":   map[string]any{"type": "string"},
			"from":      map[string]any{"type": "string"},
			"to":        map[string]any{"type": "string"},
			"max_bytes": map[string]any{"type": "integer", "minimum": 1},
			"max_depth": map[string]any{"type": "integer", "minimum": 1, "maximum": 64},
		}, "path"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args researchcore.AttackGraphImportRequest
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.ImportAttackGraph(args)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "cloud_inventory_import",
		Description: "Import a bounded read-only AWS/Azure/GCP/Kubernetes snapshot into the canonical resource/attack graph. No live credentials or provider actions are used.",
		InputSchema: objectSchema(map[string]any{
			"path":      map[string]any{"type": "string", "minLength": 1},
			"case_id":   map[string]any{"type": "string"},
			"max_bytes": map[string]any{"type": "integer", "minimum": 1},
		}, "path"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args researchcore.CloudInventoryRequest
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.ImportCloudInventory(args)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "cti_stix_import",
		Description: "Import a bounded local STIX 2.1 bundle with immutable source identity. Private Case data is not uploaded and unsupported objects remain explicitly rejected.",
		InputSchema: objectSchema(map[string]any{
			"path":        map[string]any{"type": "string", "minLength": 1},
			"case_id":     map[string]any{"type": "string"},
			"max_bytes":   map[string]any{"type": "integer", "minimum": 1},
			"max_objects": map[string]any{"type": "integer", "minimum": 1},
		}, "path"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args researchcore.STIXImportRequest
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.ImportSTIX(args)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "hunt_plan",
		Description: "Prepare an evidence-oriented threat-hunt hypothesis with required telemetry and adapters. This is plan-only and always returns execution_performed=false.",
		InputSchema: objectSchema(map[string]any{
			"case_id":    map[string]any{"type": "string"},
			"hypothesis": map[string]any{"type": "string", "minLength": 1},
			"techniques": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"telemetry":  map[string]any{"type": "array", "minItems": 1, "items": map[string]any{"type": "string"}},
			"adapters":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		}, "hypothesis", "telemetry"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args researchcore.HuntPlanRequest
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.BuildHuntPlan(args)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "ios_inspect",
		Description: "Inspect an IPA read-only for app roots, plist paths, frameworks and Mach-O candidates. It does not extract, re-sign, authorize a device or instrument a runtime.",
		InputSchema: objectSchema(map[string]any{
			"path":    map[string]any{"type": "string", "minLength": 1},
			"case_id": map[string]any{"type": "string"},
		}, "path"),
	}, func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args researchcore.IOSInspectRequest
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.InspectIOSContext(ctx, args)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "firmware_inspect",
		Description: "Classify a firmware image from bounded local bytes and return recommended analysis tools. It performs no extraction, emulation, flashing or target mutation.",
		InputSchema: objectSchema(map[string]any{
			"path":    map[string]any{"type": "string", "minLength": 1},
			"case_id": map[string]any{"type": "string"},
		}, "path"),
	}, func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args researchcore.FirmwareInspectRequest
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.InspectFirmwareContext(ctx, args)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})
}
