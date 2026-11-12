package server

import (
	"context"
	"errors"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"reverseresearch/internal/casebook"
	"reverseresearch/internal/engagement"
	"reverseresearch/internal/job"
)

func (r *Runtime) addP0Tools() {
	r.addTool(&mcp.Tool{
		Name:        "engagement_create",
		Description: "Create a durable Engagement/Scope record. Scope is deny-by-default and owns exact targets, excluded targets, allowed actions, optional time window, credentials references, data sensitivity, cleanup requirements, report classification, and rate-limit metadata.",
		InputSchema: objectSchema(map[string]any{
			"organization": map[string]any{"type": "string", "minLength": 1},
			"operator":     map[string]any{"type": "string", "minLength": 1},
			"scope":        engagementScopeSchema(),
		}, "organization", "operator", "scope"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args engagement.CreateRequest
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.CreateEngagement(args)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "engagement_get",
		Description: "Read a durable Engagement/Scope record without performing target actions.",
		InputSchema: objectSchema(map[string]any{
			"engagement_id": map[string]any{"type": "string", "minLength": 1},
		}, "engagement_id"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			EngagementID string `json:"engagement_id"`
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.GetEngagement(args.EngagementID)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "engagement_authorize",
		Description: "Evaluate whether one exact target/action is currently allowed by an Engagement/Scope record. This performs no target action.",
		InputSchema: objectSchema(map[string]any{
			"engagement_id": map[string]any{"type": "string", "minLength": 1},
			"target":        map[string]any{"type": "string", "minLength": 1},
			"action":        map[string]any{"type": "string", "minLength": 1},
			"effect_class":  map[string]any{"type": "string", "description": "Optional effect class; defaults to observation."},
			"at_utc":        map[string]any{"type": "string", "description": "Optional RFC3339 timestamp; defaults to current UTC time."},
		}, "engagement_id", "target", "action"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			EngagementID string `json:"engagement_id"`
			Target       string `json:"target"`
			Action       string `json:"action"`
			EffectClass  string `json:"effect_class"`
			AtUTC        string `json:"at_utc"`
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		at := time.Now().UTC()
		if args.AtUTC != "" {
			parsed, err := time.Parse(time.RFC3339, args.AtUTC)
			if err != nil {
				return nil, errors.New("at_utc must be RFC3339")
			}
			at = parsed
		}
		value, err := r.core.AuthorizeEngagementEffect(args.EngagementID, args.Target, args.Action, args.EffectClass, at)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "job_plan",
		Description: "Create or replay-read a durable Generic Job receipt binding engagement_id + target + action + operation_id. Reusing an operation_id for a different request fails closed.",
		InputSchema: objectSchema(map[string]any{
			"operation_id":   map[string]any{"type": "string", "minLength": 1, "maxLength": 160},
			"engagement_id":  map[string]any{"type": "string", "minLength": 1},
			"target":         map[string]any{"type": "string", "minLength": 1},
			"action":         map[string]any{"type": "string", "minLength": 1},
			"effect_class":   map[string]any{"type": "string", "minLength": 1},
			"tool_identity":  map[string]any{"type": "string"},
			"input_revision": map[string]any{"type": "string"},
			"evidence_ids":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		}, "operation_id", "engagement_id", "target", "action", "effect_class"),
	}, func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args job.PlanRequest
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.PlanJobContext(ctx, args)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "job_get",
		Description: "Read one durable Generic Job receipt without advancing it.",
		InputSchema: objectSchema(map[string]any{
			"job_id": map[string]any{"type": "string", "minLength": 1},
		}, "job_id"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			JobID string `json:"job_id"`
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.GetJob(args.JobID)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "job_prepare",
		Description: "Advance a planned Generic Job to prepared only after current Engagement/Scope authorization succeeds for the exact target/action.",
		InputSchema: objectSchema(map[string]any{
			"job_id":       map[string]any{"type": "string", "minLength": 1},
			"operation_id": map[string]any{"type": "string", "minLength": 1, "maxLength": 160},
		}, "job_id", "operation_id"),
	}, func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			JobID       string `json:"job_id"`
			OperationID string `json:"operation_id"`
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.PrepareJobContext(ctx, args.JobID, args.OperationID)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "job_transition",
		Description: "Advance a Generic Job through its explicit lifecycle. An uncertain job cannot be automatically replayed or advanced; reconcile effect evidence first.",
		InputSchema: objectSchema(map[string]any{
			"job_id":          map[string]any{"type": "string", "minLength": 1},
			"operation_id":    map[string]any{"type": "string", "minLength": 1, "maxLength": 160},
			"to":              map[string]any{"type": "string", "enum": []string{"prepared", "running", "applied", "failed", "uncertain", "rolled_back", "cancelled"}},
			"result_identity": map[string]any{"type": "string"},
			"cleanup_state":   map[string]any{"type": "string"},
			"evidence_ids":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"failure":         map[string]any{"type": "string"},
		}, "job_id", "operation_id", "to"),
	}, func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args job.TransitionRequest
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.TransitionJobContext(ctx, args)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "case_create",
		Description: "Create a durable Case v2 record with optional canonical route, Engagement binding, and target identities.",
		InputSchema: objectSchema(map[string]any{
			"title":         map[string]any{"type": "string", "minLength": 1},
			"route":         map[string]any{"type": "string"},
			"engagement_id": map[string]any{"type": "string"},
			"targets": map[string]any{"type": "array", "items": map[string]any{
				"type": "object", "additionalProperties": false,
				"properties": map[string]any{
					"id": map[string]any{"type": "string"}, "kind": map[string]any{"type": "string"},
					"identity": map[string]any{"type": "string", "minLength": 1}, "label": map[string]any{"type": "string"},
				},
				"required": []string{"identity"},
			}},
		}, "title"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args casebook.CreateRequest
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.CreateCase(args)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "case_get",
		Description: "Read one durable research Case without rewriting it.",
		InputSchema: objectSchema(map[string]any{"case_id": map[string]any{"type": "string", "minLength": 1}}, "case_id"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			CaseID string `json:"case_id"`
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.GetCase(args.CaseID)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "case_list",
		Description: "List newest durable research Cases without running analysis backends.",
		InputSchema: objectSchema(map[string]any{"limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 100}}),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			Limit int `json:"limit"`
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		values, err := r.core.ListCases(args.Limit)
		if err != nil {
			return nil, err
		}
		return structuredResult(map[string]any{"cases": values, "count": len(values)})
	})

	r.addTool(&mcp.Tool{
		Name:        "case_verify",
		Description: "Audit one Case record for structural integrity, current bound source identity, evidence/finding/path links, Case v2 hypothesis lineage, validated-detection prerequisites, and retest bindings. Does not rerun experiments.",
		InputSchema: objectSchema(map[string]any{"case_id": map[string]any{"type": "string", "minLength": 1}}, "case_id"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			CaseID string `json:"case_id"`
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.VerifyCase(args.CaseID)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "case_evidence_add",
		Description: "Add Evidence to a Case, optionally binding the exact current bytes of a local source path by SHA-256 and size.",
		InputSchema: objectSchema(map[string]any{
			"case_id": map[string]any{"type": "string", "minLength": 1},
			"summary": map[string]any{"type": "string", "minLength": 1},
			"kind":    map[string]any{"type": "string"}, "source_path": map[string]any{"type": "string"}, "notes": map[string]any{"type": "string"},
			"observed_at": map[string]any{"type": "string"}, "repro_command": map[string]any{"type": "string"}, "raw_excerpt": map[string]any{"type": "string"},
			"linked_workitem_id": map[string]any{"type": "string"}, "supersedes_evidence_id": map[string]any{"type": "string"},
		}, "case_id", "summary"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			CaseID string `json:"case_id"`
			casebook.EvidenceRequest
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.AddCaseEvidence(args.CaseID, args.EvidenceRequest)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "case_finding_add",
		Description: "Add an evidence-linked Finding with independent strength, confidence, severity, vulnerability/TTP tags, affected asset, reproducibility, detection/remediation, and retest status.",
		InputSchema: objectSchema(map[string]any{
			"case_id": map[string]any{"type": "string", "minLength": 1}, "title": map[string]any{"type": "string", "minLength": 1},
			"conclusion": map[string]any{"type": "string", "minLength": 1},
			"strength":   map[string]any{"type": "string", "enum": []string{"observed", "inferred", "unverified"}},
			"confidence": map[string]any{"type": "string"}, "severity": map[string]any{"type": "string"},
			"cwe":            map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"capec":          map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"cve":            map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"attack":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"affected_asset": map[string]any{"type": "string"}, "reproducibility": map[string]any{"type": "string"},
			"detection_status": map[string]any{"type": "string"}, "remediation_status": map[string]any{"type": "string"}, "retest_status": map[string]any{"type": "string"},
			"category": map[string]any{"type": "string"}, "status": map[string]any{"type": "string"}, "location": map[string]any{"type": "string"},
			"impact": map[string]any{"type": "string"}, "repro_steps": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}, "remediation": map[string]any{"type": "string"},
			"evidence_ids": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		}, "case_id", "title", "conclusion"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			CaseID string `json:"case_id"`
			casebook.FindingRequest
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.AddCaseFinding(args.CaseID, args.FindingRequest)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "case_path_add",
		Description: "Add an evidence-backed research/validation Path linked to known Finding IDs.",
		InputSchema: objectSchema(map[string]any{
			"case_id": map[string]any{"type": "string", "minLength": 1}, "title": map[string]any{"type": "string", "minLength": 1},
			"details": map[string]any{"type": "string", "minLength": 1}, "path_type": map[string]any{"type": "string"}, "start": map[string]any{"type": "string"}, "goal": map[string]any{"type": "string"},
			"steps":          map[string]any{"type": "array", "items": objectSchema(map[string]any{"action": map[string]any{"type": "string", "minLength": 1}, "evidence_ids": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}, "finding_ids": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}, "job_id": map[string]any{"type": "string"}}, "action")},
			"residual_risks": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}, "finding_ids": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		}, "case_id", "title", "details"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			CaseID string `json:"case_id"`
			casebook.PathRequest
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.AddCasePath(args.CaseID, args.PathRequest)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "case_hypothesis_add",
		Description: "Add one Case v2 hypothesis with supporting/conflicting evidence and a required experiment. The initial status is open.",
		InputSchema: objectSchema(map[string]any{
			"case_id":                  map[string]any{"type": "string", "minLength": 1},
			"hypothesis":               map[string]any{"type": "string", "minLength": 1},
			"supporting_evidence_ids":  map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"conflicting_evidence_ids": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"required_experiment":      map[string]any{"type": "string"},
		}, "case_id", "hypothesis"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			CaseID string `json:"case_id"`
			casebook.HypothesisRequest
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.AddCaseHypothesis(args.CaseID, args.HypothesisRequest)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "case_hypothesis_update",
		Description: "Update hypothesis evidence/status. Rejected or retracted hypotheses require a durable reason; an optional replacement hypothesis preserves lineage.",
		InputSchema: objectSchema(map[string]any{
			"case_id":                   map[string]any{"type": "string", "minLength": 1},
			"hypothesis_id":             map[string]any{"type": "string", "minLength": 1},
			"status":                    map[string]any{"type": "string", "enum": []string{"open", "supported", "rejected", "retracted"}},
			"supporting_evidence_ids":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"conflicting_evidence_ids":  map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"required_experiment":       map[string]any{"type": "string"},
			"rejected_reason":           map[string]any{"type": "string"},
			"replacement_hypothesis_id": map[string]any{"type": "string"},
		}, "case_id", "hypothesis_id", "status"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			CaseID       string `json:"case_id"`
			HypothesisID string `json:"hypothesis_id"`
			casebook.HypothesisUpdateRequest
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.UpdateCaseHypothesis(args.CaseID, args.HypothesisID, args.HypothesisUpdateRequest)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "case_detection_add",
		Description: "Add a Case v2 Detection artifact. Setting validated=true requires evidence plus positive and negative fixtures and an expected hit.",
		InputSchema: objectSchema(map[string]any{
			"case_id":               map[string]any{"type": "string", "minLength": 1},
			"name":                  map[string]any{"type": "string", "minLength": 1},
			"kind":                  map[string]any{"type": "string", "minLength": 1},
			"technique":             map[string]any{"type": "string"},
			"telemetry_requirement": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"rule":                  map[string]any{"type": "string", "minLength": 1},
			"revision":              map[string]any{"type": "string", "minLength": 1},
			"positive_fixture":      map[string]any{"type": "string"},
			"negative_fixture":      map[string]any{"type": "string"},
			"expected_hit":          map[string]any{"type": "string"},
			"false_positive_notes":  map[string]any{"type": "string"},
			"coverage":              map[string]any{"type": "string"},
			"evidence_ids":          map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"syntax_valid":          map[string]any{"type": "boolean"}, "schema_valid": map[string]any{"type": "boolean"},
			"positive_passed": map[string]any{"type": "boolean"}, "negative_passed": map[string]any{"type": "boolean"},
			"telemetry_available": map[string]any{"type": "boolean"}, "validated": map[string]any{"type": "boolean"},
		}, "case_id", "name", "kind", "rule", "revision"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			CaseID string `json:"case_id"`
			casebook.DetectionRequest
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.AddCaseDetection(args.CaseID, args.DetectionRequest)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "case_retest_add",
		Description: "Add an evidence-backed Case v2 retest result for a finding, detection, mitigation, vulnerability, or other case object.",
		InputSchema: objectSchema(map[string]any{
			"case_id":      map[string]any{"type": "string", "minLength": 1},
			"subject_type": map[string]any{"type": "string", "minLength": 1},
			"subject_id":   map[string]any{"type": "string", "minLength": 1},
			"status":       map[string]any{"type": "string", "minLength": 1},
			"summary":      map[string]any{"type": "string", "minLength": 1},
			"evidence_ids": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		}, "case_id", "subject_type", "subject_id", "status", "summary"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			CaseID string `json:"case_id"`
			casebook.RetestRequest
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.AddCaseRetest(args.CaseID, args.RetestRequest)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "domain_pack_get",
		Description: "Read one validated Domain Pack by pack_id or canonical route_id. Specialist skills never own routing.",
		InputSchema: objectSchema(map[string]any{
			"pack_id":  map[string]any{"type": "string"},
			"route_id": map[string]any{"type": "string"},
		}),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			PackID  string `json:"pack_id"`
			RouteID string `json:"route_id"`
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		if (args.PackID == "") == (args.RouteID == "") {
			return nil, errors.New("exactly one of pack_id or route_id is required")
		}
		if args.PackID != "" {
			value, err := r.core.GetDomainPack(args.PackID)
			if err != nil {
				return nil, err
			}
			return structuredResult(value)
		}
		value, ok, err := r.core.DomainPackForRoute(args.RouteID)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errors.New("route has no domain pack")
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "domain_pack_list",
		Description: "List validated Domain Packs and their specialist skill/playbook contracts without starting any backend.",
		InputSchema: objectSchema(map[string]any{}),
	}, func(_ context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		values, err := r.core.ListDomainPacks()
		if err != nil {
			return nil, err
		}
		return structuredResult(map[string]any{"packs": values, "count": len(values)})
	})
}

func engagementScopeSchema() map[string]any {
	return objectSchema(map[string]any{
		"targets":          map[string]any{"type": "array", "minItems": 1, "items": map[string]any{"type": "string"}},
		"excluded_targets": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"surfaces":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"allowed_actions":  map[string]any{"type": "array", "minItems": 1, "items": map[string]any{"type": "string"}},
		"excluded_actions": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"authorization": objectSchema(map[string]any{
			"status":        map[string]any{"type": "string", "enum": []string{"granted", "pending", "denied"}},
			"basis":         map[string]any{"type": "string"},
			"evidence_refs": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		}, "status"),
		"network_profile": objectSchema(map[string]any{
			"mode":  map[string]any{"type": "string", "enum": []string{"offline", "lab_only", "authorized_target_only", "unrestricted_lab"}},
			"notes": map[string]any{"type": "string"},
		}, "mode"),
		"rate_limits":           map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}},
		"credential_refs":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"data_sensitivity":      map[string]any{"type": "string"},
		"data_handling":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"stealth":               map[string]any{"type": "string", "enum": []string{"low", "medium", "high"}},
		"deliverables":          map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"cleanup_requirements":  map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"report_classification": map[string]any{"type": "string"},
		"starts_utc":            map[string]any{"type": "string"},
		"ends_utc":              map[string]any{"type": "string"},
	}, "targets", "allowed_actions", "authorization", "network_profile")
}
