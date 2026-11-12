package server

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	researchcore "reverseresearch/internal/core"
	"reverseresearch/internal/malware"
)

func (r *Runtime) addP1SecurityTools() {
	r.addTool(&mcp.Tool{
		Name:        "malware_triage",
		Description: "Run bounded observation-only static malware triage over a frozen local sample identity. Optionally persists Artifact/Evidence/Observation into a malware-analysis Case. It never executes the sample or performs sample network interaction.",
		InputSchema: objectSchema(map[string]any{
			"path":              map[string]any{"type": "string", "minLength": 1},
			"case_id":           map[string]any{"type": "string"},
			"use_die":           map[string]any{"type": "boolean"},
			"max_bytes":         map[string]any{"type": "integer", "minimum": 1, "maximum": malware.MaxMaxBytes},
			"min_string_length": map[string]any{"type": "integer", "minimum": 4, "maximum": 64},
			"max_strings":       map[string]any{"type": "integer", "minimum": 1, "maximum": malware.MaxStrings},
		}, "path"),
	}, func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			Path            string `json:"path"`
			CaseID          string `json:"case_id"`
			UseDIE          bool   `json:"use_die"`
			MaxBytes        int64  `json:"max_bytes"`
			MinStringLength int    `json:"min_string_length"`
			MaxStrings      int    `json:"max_strings"`
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.TriageMalware(ctx, researchcore.MalwareTriageRequest{
			Path: args.Path, CaseID: args.CaseID,
			Options: malware.Options{
				UseDIE: args.UseDIE, MaxBytes: args.MaxBytes,
				MinStringLength: args.MinStringLength, MaxStrings: args.MaxStrings,
			},
		})
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "detection_sigma_validate",
		Description: "Validate a bounded local Sigma subset against source-identity-pinned positive and negative JSON fixtures. Optionally persists rule/fixture Evidence plus a canonical Detection. Unsupported Sigma modifiers/condition forms fail closed.",
		InputSchema: objectSchema(map[string]any{
			"rule_path":            map[string]any{"type": "string", "minLength": 1},
			"positive_fixtures":    map[string]any{"type": "array", "items": map[string]any{"type": "string", "minLength": 1}},
			"negative_fixtures":    map[string]any{"type": "array", "items": map[string]any{"type": "string", "minLength": 1}},
			"case_id":              map[string]any{"type": "string"},
			"name":                 map[string]any{"type": "string"},
			"technique":            map[string]any{"type": "string"},
			"telemetry":            map[string]any{"type": "array", "items": map[string]any{"type": "string", "minLength": 1}},
			"telemetry_available":  map[string]any{"type": "boolean"},
			"false_positive_notes": map[string]any{"type": "string"},
			"coverage":             map[string]any{"type": "string"},
		}, "rule_path", "positive_fixtures", "negative_fixtures"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args researchcore.SigmaValidationRequest
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.ValidateSigma(args)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})
}
