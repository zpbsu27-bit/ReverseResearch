package server

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"reverseresearch/internal/androidinspect"
)

func (r *Runtime) addAndroidTools() {
	r.addTool(&mcp.Tool{
		Name:        "android_runtime_status",
		Description: "Report current adb/frida availability from the local tool index. Does not connect to a device or start a session.",
		InputSchema: objectSchema(map[string]any{}),
	}, func(_ context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		result, err := r.core.AndroidStatus()
		if err != nil {
			return nil, err
		}
		return structuredResult(result)
	})

	r.addTool(&mcp.Tool{
		Name:        "android_device_list",
		Description: "List adb-visible devices and authorization state. Unauthorized/offline devices are reported but never auto-authorized.",
		InputSchema: objectSchema(map[string]any{}),
	}, func(ctx context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		result, err := r.core.AndroidDevices(ctx)
		if err != nil {
			return nil, err
		}
		return structuredResult(result)
	})

	r.addTool(&mcp.Tool{
		Name:        "android_device_probe",
		Description: "Probe an explicitly authorized adb device for model, Android/SDK, ABI, and shell UID/root status. Rejects unauthorized/offline devices.",
		InputSchema: objectSchema(map[string]any{
			"serial": map[string]any{"type": "string", "minLength": 1},
		}, "serial"),
	}, func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			Serial string `json:"serial"`
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		result, err := r.core.ProbeAndroidDevice(ctx, args.Serial)
		if err != nil {
			return nil, err
		}
		return structuredResult(result)
	})

	r.addTool(&mcp.Tool{
		Name:        "android_workspace_prepare",
		Description: "Create a per-device hashed Android workspace with isolated evidence, certificate, and operation-receipt directories. Raw device serials are not used in persisted paths; this never substitutes for device authorization.",
		InputSchema: objectSchema(map[string]any{
			"serial": map[string]any{"type": "string", "minLength": 1},
		}, "serial"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			Serial string `json:"serial"`
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		result, err := r.core.PrepareAndroidWorkspace(args.Serial)
		if err != nil {
			return nil, err
		}
		return structuredResult(result)
	})

	r.addTool(&mcp.Tool{
		Name:        "android_ui_snapshot",
		Description: "Capture a reviewable UI hierarchy plus screenshot from one explicitly authorized device into its isolated evidence directory, returning stable SHA-256 identities.",
		InputSchema: objectSchema(map[string]any{
			"serial": map[string]any{"type": "string", "minLength": 1},
		}, "serial"),
	}, func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			Serial string `json:"serial"`
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		result, err := r.core.SnapshotAndroidUI(ctx, args.Serial)
		if err != nil {
			return nil, err
		}
		return structuredResult(result)
	})

	r.addTool(&mcp.Tool{
		Name:        "android_ui_tap",
		Description: "Execute one selector-bound tap only after UI SHA-256 currentness verification. operation_id is one-shot: prepared/failed/applied receipts are never auto-replayed after disconnect or uncertainty.",
		InputSchema: objectSchema(map[string]any{
			"serial":             map[string]any{"type": "string", "minLength": 1},
			"snapshot_id":        map[string]any{"type": "string", "minLength": 1},
			"expected_ui_sha256": map[string]any{"type": "string", "pattern": "^[A-Fa-f0-9]{64}$"},
			"resource_id":        map[string]any{"type": "string"},
			"text":               map[string]any{"type": "string"},
			"content_desc":       map[string]any{"type": "string"},
			"operation_id":       map[string]any{"type": "string", "minLength": 1},
		}, "serial", "snapshot_id", "expected_ui_sha256", "operation_id"),
	}, func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			Serial           string `json:"serial"`
			SnapshotID       string `json:"snapshot_id"`
			ExpectedUISHA256 string `json:"expected_ui_sha256"`
			ResourceID       string `json:"resource_id"`
			Text             string `json:"text"`
			ContentDesc      string `json:"content_desc"`
			OperationID      string `json:"operation_id"`
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		result, err := r.core.TapAndroidUI(ctx, androidinspect.TapRequest{
			Serial: args.Serial, SnapshotID: args.SnapshotID, ExpectedUISHA256: args.ExpectedUISHA256,
			Selector:    androidinspect.Selector{ResourceID: args.ResourceID, Text: args.Text, ContentDesc: args.ContentDesc},
			OperationID: args.OperationID,
		})
		if err != nil {
			return nil, err
		}
		return structuredResult(result)
	})
}
