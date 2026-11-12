package server

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	researchcore "reverseresearch/internal/core"
	"reverseresearch/internal/fuzz"
)

type crashBatchArgs struct {
	Crashes []fuzz.Crash `json:"crashes"`
}

type purpleCoverageArgs struct {
	CaseID string `json:"case_id"`
}

func (r *Runtime) addP1ResearchTools() {
	r.addTool(&mcp.Tool{
		Name:        "dfir_artifact_inspect",
		Description: "Identify and classify one local forensic artifact read-only, pinning its content identity. Optionally persist Artifact/Evidence/Observation into a dfir-forensics Case.",
		InputSchema: objectSchema(map[string]any{
			"path":    map[string]any{"type": "string", "minLength": 1},
			"case_id": map[string]any{"type": "string"},
		}, "path"),
	}, func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args researchcore.DFIRInspectRequest
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.InspectDFIRArtifactContext(ctx, args)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "dfir_timeline_import",
		Description: "Import a bounded JSONL forensic timeline into a provenance-preserving normalized view. Raw source identity remains authoritative; duplicate and rejected counts stay explicit.",
		InputSchema: objectSchema(map[string]any{
			"path":        map[string]any{"type": "string", "minLength": 1},
			"case_id":     map[string]any{"type": "string"},
			"format":      map[string]any{"type": "string"},
			"max_bytes":   map[string]any{"type": "integer", "minimum": 1},
			"max_entries": map[string]any{"type": "integer", "minimum": 1},
		}, "path"),
	}, func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args researchcore.DFIRTimelineRequest
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.ImportDFIRTimelineContext(ctx, args)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "fuzz_plan",
		Description: "Create a plan-only fuzzing record that freezes target, harness and corpus identities. It never executes the target; a future fuzz run remains effectful and requires Engagement/Job/Lab scope.",
		InputSchema: objectSchema(map[string]any{
			"case_id":     map[string]any{"type": "string"},
			"target_path": map[string]any{"type": "string", "minLength": 1},
			"harness":     map[string]any{"type": "string", "minLength": 1},
			"corpus_dir":  map[string]any{"type": "string", "minLength": 1},
			"engine":      map[string]any{"type": "string", "enum": []string{"libfuzzer", "afl++", "winafl", "jazzer"}},
			"sanitizers":  map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"seed":        map[string]any{"type": "integer"},
		}, "target_path", "harness", "corpus_dir", "engine"),
	}, func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args researchcore.FuzzPlanRequest
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.BuildFuzzPlanContext(ctx, args)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "crash_fingerprint",
		Description: "Fingerprint one already-observed crash using module, exception/signal, fault instruction and normalized stack. It does not execute a reproducer or assess exploitability.",
		InputSchema: objectSchema(map[string]any{
			"exception":         map[string]any{"type": "string", "minLength": 1},
			"module":            map[string]any{"type": "string", "minLength": 1},
			"fault_instruction": map[string]any{"type": "string", "minLength": 1},
			"frames":            map[string]any{"type": "array", "items": map[string]any{"type": "object"}},
			"input_sha256":      map[string]any{"type": "string"},
			"engine":            map[string]any{"type": "string"},
			"sanitizer":         map[string]any{"type": "string"},
			"observed_utc":      map[string]any{"type": "string"},
		}, "exception", "module", "fault_instruction"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var crash fuzz.Crash
		if err := decodeArguments(request, &crash); err != nil {
			return nil, err
		}
		value, err := r.core.FingerprintCrash(crash)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "crash_dedupe",
		Description: "Group already-observed crash records by canonical structural fingerprint. It does not execute inputs or infer exploitability.",
		InputSchema: objectSchema(map[string]any{
			"crashes": map[string]any{"type": "array", "minItems": 1, "items": map[string]any{"type": "object"}},
		}, "crashes"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args crashBatchArgs
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.DedupeCrashes(args.Crashes)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "crash_record",
		Description: "Persist an already-observed crash and current reproducer input identity into a vuln-research or n-day Case. It does not execute the reproducer and does not equate a crash with exploitability.",
		InputSchema: objectSchema(map[string]any{
			"case_id":    map[string]any{"type": "string", "minLength": 1},
			"input_path": map[string]any{"type": "string", "minLength": 1},
			"crash":      map[string]any{"type": "object"},
		}, "case_id", "input_path", "crash"),
	}, func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args researchcore.CrashRecordRequest
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.RecordCrashContext(ctx, args)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "protocol_infer",
		Description: "Analyze a bounded local JSON message corpus and return candidate framing/length/checksum structure plus a candidate Kaitai schema. It performs no network replay.",
		InputSchema: objectSchema(map[string]any{
			"samples_path": map[string]any{"type": "string", "minLength": 1},
			"case_id":      map[string]any{"type": "string"},
			"name":         map[string]any{"type": "string"},
			"max_bytes":    map[string]any{"type": "integer", "minimum": 1},
		}, "samples_path"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args researchcore.ProtocolFileRequest
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.InferProtocolFile(args)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "source_audit",
		Description: "Run bounded read-only source/supply-chain inventory with language/manifests/dependencies and redacted secret candidates. Candidates are not automatically Findings.",
		InputSchema: objectSchema(map[string]any{
			"root":    map[string]any{"type": "string", "minLength": 1},
			"case_id": map[string]any{"type": "string"},
			"options": map[string]any{"type": "object", "properties": map[string]any{
				"max_files":       map[string]any{"type": "integer", "minimum": 1},
				"max_file_bytes":  map[string]any{"type": "integer", "minimum": 1},
				"max_total_bytes": map[string]any{"type": "integer", "minimum": 1},
			}},
		}, "root"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args researchcore.SourceAuditRequest
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.AuditSource(args)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "sarif_import",
		Description: "Import bounded SARIF as canonical unverified/candidate Findings linked to the exact SARIF source identity. Static tool output is never promoted directly to observed vulnerability proof.",
		InputSchema: objectSchema(map[string]any{
			"path":        map[string]any{"type": "string", "minLength": 1},
			"case_id":     map[string]any{"type": "string"},
			"max_bytes":   map[string]any{"type": "integer", "minimum": 1},
			"max_results": map[string]any{"type": "integer", "minimum": 1},
		}, "path"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args researchcore.SARIFImportRequest
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.ImportSARIF(args)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "sbom_import",
		Description: "Import bounded CycloneDX or SPDX JSON as content-addressed component inventory Evidence. Component presence does not create vulnerability Findings.",
		InputSchema: objectSchema(map[string]any{
			"path":           map[string]any{"type": "string", "minLength": 1},
			"case_id":        map[string]any{"type": "string"},
			"max_bytes":      map[string]any{"type": "integer", "minimum": 1},
			"max_components": map[string]any{"type": "integer", "minimum": 1},
		}, "path"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args researchcore.SBOMImportRequest
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.ImportSBOM(args)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "protocol_validate",
		Description: "Validate a protocol model against a distinct content-addressed fixture corpus. Reusing the model corpus as validation fails closed. No network replay is performed.",
		InputSchema: objectSchema(map[string]any{
			"model_samples_path": map[string]any{"type": "string", "minLength": 1},
			"fixtures_path":      map[string]any{"type": "string", "minLength": 1},
			"case_id":            map[string]any{"type": "string"},
			"name":               map[string]any{"type": "string"},
			"max_bytes":          map[string]any{"type": "integer", "minimum": 1},
		}, "model_samples_path", "fixtures_path"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args researchcore.ProtocolValidationRequest
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.ValidateProtocol(args)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "purple_coverage",
		Description: "Build the evidence-backed TTP-to-detection-to-mitigation-to-retest coverage view for a purple-validation Case. This is read-only.",
		InputSchema: objectSchema(map[string]any{
			"case_id": map[string]any{"type": "string", "minLength": 1},
		}, "case_id"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args purpleCoverageArgs
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.PurpleCoverage(args.CaseID)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "purple_emulation_plan",
		Description: "Prepare a scoped Generic Job for one existing ATT&CK technique in a purple-validation Case. It records the Job and timeline but does not execute emulation.",
		InputSchema: objectSchema(map[string]any{
			"case_id":       map[string]any{"type": "string", "minLength": 1},
			"technique":     map[string]any{"type": "string", "minLength": 1},
			"target":        map[string]any{"type": "string", "minLength": 1},
			"action":        map[string]any{"type": "string", "minLength": 1},
			"effect_class":  map[string]any{"type": "string", "enum": []string{"local mutation", "runtime mutation", "active network interaction"}},
			"operation_id":  map[string]any{"type": "string", "minLength": 1},
			"tool_identity": map[string]any{"type": "string"},
			"evidence_ids":  map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		}, "case_id", "technique", "target", "action", "effect_class", "operation_id"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args researchcore.PurpleEmulationPlanRequest
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		value, err := r.core.PreparePurpleEmulation(args)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})
}
