package server

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"reverseresearch/internal/capability"
	"reverseresearch/internal/playbook"
	"reverseresearch/internal/sandbox"
)

func researchListSchema() map[string]any {
	return map[string]any{
		"offset":                 map[string]any{"type": "integer", "minimum": 0},
		"limit":                  map[string]any{"type": "integer", "minimum": 1, "maximum": 200},
		"expected_result_sha256": map[string]any{"type": "string", "pattern": "^[A-Fa-f0-9]{64}$"},
	}
}

func (r *Runtime) addResearchCatalogTools() {
	closed, destructive := false, false
	readOnly := &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: &closed}
	capabilityProperties := researchListSchema()
	capabilityProperties["route_id"] = map[string]any{"type": "string", "minLength": 1, "maxLength": 64}
	r.addTool(&mcp.Tool{Name: "capability_status", Description: "Query canonical route capability readiness for one route_id or all routes. Refreshes the existing machine-local ToolIndex; does not install or start tools. External-tool routes are runnable when some tools exist and full_ready when all exist; an explicitly built_in route with no external requirements is ready. Readiness does not prove target/runtime behavior. Returns bounded pages; follow next_offset with expected_result_sha256 and restart if tool availability changes.", InputSchema: objectSchema(capabilityProperties), Annotations: readOnly}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var a struct {
			RouteID string `json:"route_id,omitempty"`
			researchPageOptions
		}
		if err := decodeArguments(request, &a); err != nil {
			return nil, err
		}
		var values []capability.Status
		if a.RouteID == "" {
			v, err := r.core.CapabilityStatuses()
			if err != nil {
				return nil, err
			}
			values = v
		} else {
			v, err := r.core.CapabilityStatus(a.RouteID)
			if err != nil {
				return nil, err
			}
			values = []capability.Status{v}
		}
		return pagedResearchResult(values, len(values), a.researchPageOptions, func(start, end int) []capability.Status { return values[start:end] })
	})
	r.addTool(&mcp.Tool{Name: "playbook_list", Description: "List machine-validated playbooks from the canonical registry: master Skill/reference paths, routes, gates and done criteria. Does not launch backends or read whole Skill documents. Returns bounded pages; follow next_offset with expected_result_sha256 under the same registry revision.", InputSchema: objectSchema(researchListSchema()), Annotations: readOnly}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var a researchPageOptions
		if err := decodeArguments(request, &a); err != nil {
			return nil, err
		}
		values, err := r.core.ListPlaybooks()
		if err != nil {
			return nil, err
		}
		return pagedResearchResult(values, len(values), a, func(start, end int) []playbook.Playbook { return values[start:end] })
	})
	path := map[string]any{"type": "string", "minLength": 1, "maxLength": 4096}
	toolNames := map[string]any{"type": "array", "maxItems": 32, "items": map[string]any{"type": "string", "minLength": 1, "maxLength": 64}}
	plan := objectSchema(map[string]any{
		"id":    map[string]any{"type": "string", "pattern": "^sandbox_[a-f0-9]{16}$"},
		"name":  map[string]any{"type": "string", "minLength": 1, "maxLength": 256},
		"route": map[string]any{"type": "string", "maxLength": 64},
		"kind":  map[string]any{"type": "string", "enum": []string{"filesystem", "wsl", "docker"}},
		"root":  path, "input_dir": path, "work_dir": path, "output_dir": path,
		"required_tools": toolNames, "missing_tools": toolNames,
		"ready":       map[string]any{"type": "boolean"},
		"created_utc": map[string]any{"type": "string", "minLength": 1, "maxLength": 64},
	}, "id", "name", "kind", "root", "input_dir", "work_dir", "output_dir", "ready", "created_utc")
	r.addTool(&mcp.Tool{Name: "sandbox_create", Description: "Prepare the canonical input/work/output directories from the sandbox plan returned by task_prepare. Reuse the complete original plan and its stable id after uncertainty: an identical committed plan returns the original metadata; conflicting reuse or incomplete/changed directories is refused. The existing sandbox Manager is the sole writer. This prepares local directories; isolation_started=false and target_execution_performed=false even for wsl/docker kinds. Does not start a VM/container or execute a target.", InputSchema: objectSchema(map[string]any{"plan": plan}, "plan"), Annotations: &mcp.ToolAnnotations{IdempotentHint: true, DestructiveHint: &destructive, OpenWorldHint: &closed}}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var a struct {
			Plan sandbox.Plan `json:"plan"`
		}
		if err := decodeArguments(request, &a); err != nil {
			return nil, err
		}
		value, err := r.core.CreateSandbox(a.Plan)
		if err != nil {
			return nil, err
		}
		return boundedResearchResult(map[string]any{"plan": value, "isolation_started": false, "target_execution_performed": false})
	})
}
