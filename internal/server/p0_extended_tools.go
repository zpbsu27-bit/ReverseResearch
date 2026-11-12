package server

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"reverseresearch/internal/casebook"
)

func (r *Runtime) addP0ExtendedTools() {
	r.addTool(&mcp.Tool{
		Name:        "case_review",
		Description: "Run the strict report-handoff Case review gate. It composes structural/currentness verification with Case v2 engagement, target/artifact, lead-role, timeline, workitem, evidence, finding, detection, and retest readiness checks.",
		InputSchema: objectSchema(map[string]any{"case_id": map[string]any{"type": "string", "minLength": 1}}, "case_id"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			CaseID string `json:"case_id"`
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.ReviewCase(args.CaseID)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "case_role_assign",
		Description: "Assign a logical analyst/specialist role to a Case. Roles are handoff metadata only; this does not create or control agent processes.",
		InputSchema: objectSchema(map[string]any{
			"case_id":          map[string]any{"type": "string", "minLength": 1},
			"role":             map[string]any{"type": "string", "minLength": 1},
			"specialist_skill": map[string]any{"type": "string"},
			"handoff_when":     map[string]any{"type": "string"},
		}, "case_id", "role"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			CaseID string `json:"case_id"`
			casebook.RoleAssignmentRequest
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.AssignCaseRole(args.CaseID, args.RoleAssignmentRequest)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "case_workitem_add",
		Description: "Create a Case workitem with logical owner role, coverage note, and optional evidence links.",
		InputSchema: objectSchema(map[string]any{
			"case_id":      map[string]any{"type": "string", "minLength": 1},
			"title":        map[string]any{"type": "string", "minLength": 1},
			"owner_role":   map[string]any{"type": "string"},
			"coverage":     map[string]any{"type": "string"},
			"evidence_ids": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		}, "case_id", "title"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			CaseID string `json:"case_id"`
			casebook.WorkItemRequest
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.AddCaseWorkItem(args.CaseID, args.WorkItemRequest)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "case_workitem_update",
		Description: "Update a Case workitem status/coverage/evidence. Blocked items require a durable blocked_reason.",
		InputSchema: objectSchema(map[string]any{
			"case_id":        map[string]any{"type": "string", "minLength": 1},
			"workitem_id":    map[string]any{"type": "string", "minLength": 1},
			"status":         map[string]any{"type": "string", "enum": []string{"planned", "running", "blocked", "done", "cancelled"}},
			"coverage":       map[string]any{"type": "string"},
			"evidence_ids":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"blocked_reason": map[string]any{"type": "string"},
		}, "case_id", "workitem_id", "status"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			CaseID     string `json:"case_id"`
			WorkItemID string `json:"workitem_id"`
			casebook.WorkItemUpdateRequest
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.UpdateCaseWorkItem(args.CaseID, args.WorkItemID, args.WorkItemUpdateRequest)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "case_timeline_add",
		Description: "Append an immutable Case timeline entry linked to optional role, workitem, Generic Job receipt, and Evidence.",
		InputSchema: objectSchema(map[string]any{
			"case_id":      map[string]any{"type": "string", "minLength": 1},
			"kind":         map[string]any{"type": "string", "minLength": 1},
			"summary":      map[string]any{"type": "string", "minLength": 1},
			"role":         map[string]any{"type": "string"},
			"workitem_id":  map[string]any{"type": "string"},
			"job_id":       map[string]any{"type": "string"},
			"evidence_ids": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		}, "case_id", "kind", "summary"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			CaseID string `json:"case_id"`
			casebook.TimelineRequest
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.AddCaseTimeline(args.CaseID, args.TimelineRequest)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "case_artifact_add",
		Description: "Add a canonical target-derived Artifact identity to Case v2.",
		InputSchema: objectSchema(map[string]any{
			"case_id":  map[string]any{"type": "string", "minLength": 1},
			"kind":     map[string]any{"type": "string", "minLength": 1},
			"identity": map[string]any{"type": "string", "minLength": 1},
			"source":   map[string]any{"type": "string"},
			"sha256":   map[string]any{"type": "string"},
			"size":     map[string]any{"type": "integer", "minimum": 0},
		}, "case_id", "kind", "identity"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			CaseID string `json:"case_id"`
			casebook.ArtifactRequest
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.AddCaseArtifact(args.CaseID, args.ArtifactRequest)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "case_observation_add",
		Description: "Add a Case observation backed by existing Evidence IDs.",
		InputSchema: objectSchema(map[string]any{
			"case_id":      map[string]any{"type": "string", "minLength": 1},
			"summary":      map[string]any{"type": "string", "minLength": 1},
			"evidence_ids": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		}, "case_id", "summary"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			CaseID string `json:"case_id"`
			casebook.ObservationRequest
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.AddCaseObservation(args.CaseID, args.ObservationRequest)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "case_vulnerability_add",
		Description: "Add a canonical vulnerability object linked to known Findings and Evidence.",
		InputSchema: objectSchema(map[string]any{
			"case_id":      map[string]any{"type": "string", "minLength": 1},
			"title":        map[string]any{"type": "string", "minLength": 1},
			"cwe":          map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"capec":        map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"cve":          map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"finding_ids":  map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"evidence_ids": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		}, "case_id", "title"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			CaseID string `json:"case_id"`
			casebook.VulnerabilityRequest
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.AddCaseVulnerability(args.CaseID, args.VulnerabilityRequest)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "case_ioc_add",
		Description: "Add an IOC linked to an existing source object such as Evidence, Finding, Artifact, or Observation.",
		InputSchema: objectSchema(map[string]any{
			"case_id":   map[string]any{"type": "string", "minLength": 1},
			"type":      map[string]any{"type": "string", "minLength": 1},
			"value":     map[string]any{"type": "string", "minLength": 1},
			"source_id": map[string]any{"type": "string"},
		}, "case_id", "type", "value"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			CaseID string `json:"case_id"`
			casebook.IOCRequest
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.AddCaseIOC(args.CaseID, args.IOCRequest)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "case_ttp_add",
		Description: "Add an ATT&CK/TTP relationship object linked to known Findings.",
		InputSchema: objectSchema(map[string]any{
			"case_id":     map[string]any{"type": "string", "minLength": 1},
			"technique":   map[string]any{"type": "string", "minLength": 1},
			"tactic":      map[string]any{"type": "string"},
			"finding_ids": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		}, "case_id", "technique"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			CaseID string `json:"case_id"`
			casebook.TTPRequest
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.AddCaseTTP(args.CaseID, args.TTPRequest)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "case_mitigation_add",
		Description: "Add a mitigation/countermeasure linked to known Findings and Evidence.",
		InputSchema: objectSchema(map[string]any{
			"case_id":      map[string]any{"type": "string", "minLength": 1},
			"summary":      map[string]any{"type": "string", "minLength": 1},
			"technique":    map[string]any{"type": "string"},
			"finding_ids":  map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"evidence_ids": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		}, "case_id", "summary"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			CaseID string `json:"case_id"`
			casebook.MitigationRequest
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.AddCaseMitigation(args.CaseID, args.MitigationRequest)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "case_report_add",
		Description: "Register one report revision and optionally bind it to a Case Artifact.",
		InputSchema: objectSchema(map[string]any{
			"case_id":              map[string]any{"type": "string", "minLength": 1},
			"kind":                 map[string]any{"type": "string", "minLength": 1},
			"format":               map[string]any{"type": "string", "minLength": 1},
			"revision":             map[string]any{"type": "string", "minLength": 1},
			"profile":              map[string]any{"type": "string"},
			"classification":       map[string]any{"type": "string"},
			"status":               map[string]any{"type": "string", "enum": []string{"draft", "final"}},
			"summary":              map[string]any{"type": "string"},
			"artifact_id":          map[string]any{"type": "string"},
			"finding_ids":          map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"evidence_ids":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"sections":             map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"supersedes_report_id": map[string]any{"type": "string"},
		}, "case_id", "kind", "format", "revision"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			CaseID string `json:"case_id"`
			casebook.ReportRequest
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.AddCaseReport(args.CaseID, args.ReportRequest)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "domain_pack_audit",
		Description: "Statically audit one Domain Pack skill tree for source identity, hashes, executable/script surface, symlinks, dynamic download/exec patterns, sensitive-path references, and MCP/bootstrap supply-chain indicators. This performs no external execution.",
		InputSchema: objectSchema(map[string]any{"pack_id": map[string]any{"type": "string", "minLength": 1}}, "pack_id"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			PackID string `json:"pack_id"`
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.AuditDomainPack(args.PackID)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})
}
