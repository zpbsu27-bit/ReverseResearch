package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"reverseresearch/internal/migration"
)

func TestHostSafetyToolsPublishAndStayBackendLazy(t *testing.T) {
	root, sourceRoot := isolatedServerRoot(t)
	runtime, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	// This is the lifetime of an eight-call contract workflow, including two
	// machine-local scans. Individual cancellation/admission budgets are tested
	// separately; filesystem latency is not a ten-second workflow SLA.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	go func() { _ = runtime.Run(ctx, serverTransport) }()

	client := mcp.NewClient(&mcp.Implementation{Name: "host-tools-test", Version: "1.0.0"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	listed, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	wantNames := map[string]bool{
		"target_identify":           false,
		"target_compare":            false,
		"task_route":                false,
		"task_prepare":              false,
		"playbook_get":              false,
		"tool_index_scan":           false,
		"die_scan":                  false,
		"process_identify":          false,
		"process_debug_route":       false,
		"memory_scan_start":         false,
		"memory_scan_refine":        false,
		"memory_scan_get":           false,
		"memory_scan_delete":        false,
		"pointer_map_build":         false,
		"pointer_map_get":           false,
		"pointer_map_delete":        false,
		"pointer_map_verify":        false,
		"write_watch":               false,
		"hook_plan":                 false,
		"hook_get":                  false,
		"hook_list":                 false,
		"hook_apply":                false,
		"hook_verify":               false,
		"hook_rollback":             false,
		"hook_cancel":               false,
		"compatibility_add":         false,
		"compatibility_import":      false,
		"compatibility_get":         false,
		"compatibility_list":        false,
		"compatibility_verify":      false,
		"semantic_sync_preview":     false,
		"process_control_acquire":   false,
		"process_control_get":       false,
		"process_control_release":   false,
		"patch_plan":                false,
		"patch_get":                 false,
		"patch_dry_run":             false,
		"patch_apply":               false,
		"patch_verify":              false,
		"patch_rollback":            false,
		"web_backend_status":        false,
		"web_profile_prepare":       false,
		"web_cdp_inspect":           false,
		"web_source_analyze":        false,
		"web_source_map_read":       false,
		"web_sse_inspect":           false,
		"web_har_inspect":           false,
		"web_wasm_inspect":          false,
		"android_runtime_status":    false,
		"android_device_list":       false,
		"android_device_probe":      false,
		"android_workspace_prepare": false,
		"android_ui_snapshot":       false,
		"android_ui_tap":            false,
		"engagement_create":         false,
		"engagement_get":            false,
		"engagement_authorize":      false,
		"job_plan":                  false,
		"job_get":                   false,
		"job_prepare":               false,
		"job_transition":            false,
		"case_create":               false,
		"case_get":                  false,
		"case_list":                 false,
		"case_verify":               false,
		"case_evidence_add":         false,
		"case_finding_add":          false,
		"case_path_add":             false,
		"case_hypothesis_add":       false,
		"case_hypothesis_update":    false,
		"case_detection_add":        false,
		"case_retest_add":           false,
		"domain_pack_get":           false,
		"domain_pack_list":          false,
		"case_review":               false,
		"case_role_assign":          false,
		"case_workitem_add":         false,
		"case_workitem_update":      false,
		"case_timeline_add":         false,
		"case_artifact_add":         false,
		"case_observation_add":      false,
		"case_vulnerability_add":    false,
		"case_ioc_add":              false,
		"case_ttp_add":              false,
		"case_mitigation_add":       false,
		"case_report_add":           false,
		"domain_pack_audit":         false,
		"knowledge_pack_list":       false,
		"knowledge_pack_get":        false,
		"knowledge_pack_route":      false,
		"malware_triage":            false,
		"detection_sigma_validate":  false,
		"dfir_artifact_inspect":     false,
		"dfir_timeline_import":      false,
		"fuzz_plan":                 false,
		"crash_fingerprint":         false,
		"crash_dedupe":              false,
		"crash_record":              false,
		"protocol_infer":            false,
		"source_audit":              false,
		"purple_coverage":           false,
		"purple_emulation_plan":     false,
		"attack_graph_import":       false,
		"cloud_inventory_import":    false,
		"cti_stix_import":           false,
		"hunt_plan":                 false,
		"ios_inspect":               false,
		"firmware_inspect":          false,
		"report_render":             false,
		"dashboard_render":          false,
		"collaboration_get":         false,
		"collaboration_apply":       false,
		"rbac_check":                false,
		"remote_agent_manage":       false,
		"pack_verify":               false,
		"pack_registry":             false,
		"sarif_import":              false,
		"sbom_import":               false,
		"protocol_validate":         false,
	}
	for _, tool := range listed.Tools {
		if _, ok := wantNames[tool.Name]; ok {
			wantNames[tool.Name] = true
		}
	}
	for name, found := range wantNames {
		if !found {
			t.Fatalf("host tool %s not published", name)
		}
	}
	if got, want := len(listed.Tools), 282; got != want {
		t.Fatalf("tool count=%d want=%d", got, want)
	}

	routed, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "task_route", Arguments: map[string]any{"text": "分析这个 APK 的 DEX 和 smali"},
	})
	if err != nil || routed.IsError {
		t.Fatalf("task_route failed: result=%#v err=%v", routed, err)
	}
	var routeResult struct {
		Route struct {
			ID string `json:"id"`
		} `json:"route"`
	}
	decodeStructured(t, routed.StructuredContent, &routeResult)
	if routeResult.Route.ID != "android" {
		t.Fatalf("task route=%+v", routeResult)
	}

	prepared, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "task_prepare", Arguments: map[string]any{"text": "analyze this Android APK DEX with JADX"},
	})
	if err != nil || prepared.IsError {
		t.Fatalf("task_prepare failed: result=%#v err=%v", prepared, err)
	}
	var prepareResult struct {
		Route struct {
			Route struct {
				ID string `json:"id"`
			} `json:"route"`
		} `json:"route"`
		Playbook *struct {
			ID            string `json:"id"`
			SkillPath     string `json:"skill_path"`
			ReferencePath string `json:"reference_path"`
			Gates         []any  `json:"gates"`
		} `json:"playbook"`
	}
	decodeStructured(t, prepared.StructuredContent, &prepareResult)
	if prepareResult.Route.Route.ID != "android" || prepareResult.Playbook == nil || prepareResult.Playbook.ID != "android" || prepareResult.Playbook.SkillPath != "skills/seep-reverse-lab/SKILL.md" || prepareResult.Playbook.ReferencePath != "skills/seep-reverse-lab/references/android.md" || len(prepareResult.Playbook.Gates) < 4 {
		t.Fatalf("task prepare=%+v", prepareResult)
	}

	playbookResult, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "playbook_get", Arguments: map[string]any{"route_id": "js-web"},
	})
	if err != nil || playbookResult.IsError {
		t.Fatalf("playbook_get failed: result=%#v err=%v", playbookResult, err)
	}
	var webPlaybook struct {
		ID            string `json:"id"`
		Platform      string `json:"platform"`
		SkillPath     string `json:"skill_path"`
		ReferencePath string `json:"reference_path"`
	}
	decodeStructured(t, playbookResult.StructuredContent, &webPlaybook)
	if webPlaybook.ID != "js-web" || webPlaybook.Platform != "web" || webPlaybook.SkillPath != "skills/seep-reverse-lab/SKILL.md" || webPlaybook.ReferencePath != "skills/seep-reverse-lab/references/web.md" {
		t.Fatalf("web playbook=%+v", webPlaybook)
	}

	indexed, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "tool_index_scan", Arguments: map[string]any{}})
	if err != nil || indexed.IsError {
		t.Fatalf("tool_index_scan failed: result=%#v err=%v", indexed, err)
	}
	var indexResult struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	decodeStructured(t, indexed.StructuredContent, &indexResult)
	if len(indexResult.Tools) < 10 {
		t.Fatalf("tool index unexpectedly small: %d", len(indexResult.Tools))
	}

	compatFixture := filepath.Join(sourceRoot, "testdata", "mcp-smoke.exe")
	compatAdded, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "compatibility_add",
		Arguments: map[string]any{
			"game": "Host Tool Fixture", "build": "1.0", "module_path": compatFixture,
			"outcome": "candidate", "validation": "record-only",
		},
	})
	if err != nil || compatAdded.IsError {
		t.Fatalf("compatibility_add failed: result=%#v err=%v", compatAdded, err)
	}
	var compatRecord struct {
		ID         string `json:"id"`
		Validation string `json:"validation"`
		Outcome    string `json:"outcome"`
	}
	decodeStructured(t, compatAdded.StructuredContent, &compatRecord)
	if compatRecord.ID == "" || compatRecord.Validation != "record-only" || compatRecord.Outcome != "candidate" {
		t.Fatalf("compatibility record=%+v", compatRecord)
	}
	compatVerified, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "compatibility_verify", Arguments: map[string]any{"record_id": compatRecord.ID},
	})
	if err != nil || compatVerified.IsError {
		t.Fatalf("compatibility_verify failed: result=%#v err=%v", compatVerified, err)
	}
	var compatVerification struct {
		RecordValid              bool `json:"record_valid"`
		SourceCurrent            bool `json:"source_current"`
		CompatibilityRevalidated bool `json:"compatibility_revalidated"`
	}
	decodeStructured(t, compatVerified.StructuredContent, &compatVerification)
	if !compatVerification.RecordValid || !compatVerification.SourceCurrent || compatVerification.CompatibilityRevalidated {
		t.Fatalf("compatibility verification=%+v", compatVerification)
	}

	syncPreview, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "semantic_sync_preview",
		Arguments: map[string]any{
			"migration": map[string]any{
				"entries": []any{map[string]any{
					"label": "unit-update", "status": "mapped",
					"old_rva": 4096, "new_rva": 8192,
				}},
			},
			"source": map[string]any{
				"functions": []any{map[string]any{
					"rva": 4096, "name": "UpdateUnit", "name_origin": "user",
					"comments": []any{map[string]any{"kind": "plate", "text": "source note"}},
				}},
			},
			"target": map[string]any{
				"functions": []any{map[string]any{
					"rva": 8192, "name": "ManualUpdateUnit", "name_origin": "user",
					"comments": []any{map[string]any{"kind": "plate", "text": "target note"}},
				}},
			},
		},
	})
	if err != nil || syncPreview.IsError {
		t.Fatalf("semantic_sync_preview failed: result=%#v err=%v", syncPreview, err)
	}
	var syncResult migration.SyncPreview
	decodeStructured(t, syncPreview.StructuredContent, &syncResult)
	if syncResult.Validation != "preview-only" || syncResult.RuntimeVerified || syncResult.WritesPerformed ||
		syncResult.Preserved != 1 || syncResult.Conflicts != 1 || syncResult.Suggested != 0 {
		t.Fatalf("semantic sync result=%+v", syncResult)
	}

	fixture := filepath.Join(sourceRoot, "testdata", "mcp-smoke.exe")
	identified, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "target_identify",
		Arguments: map[string]any{"path": fixture},
	})
	if err != nil {
		t.Fatal(err)
	}
	if identified.IsError {
		t.Fatalf("target_identify tool error: %#v", identified.Content)
	}
	payload := struct {
		SHA256 string `json:"sha256"`
		PE     *struct {
			Bits int `json:"bits"`
		} `json:"pe"`
	}{}
	decodeStructured(t, identified.StructuredContent, &payload)
	if len(payload.SHA256) != 64 || payload.PE == nil || payload.PE.Bits != 32 {
		t.Fatalf("target identity=%+v", payload)
	}

	// Pinned DiE runtime execution is covered by the isolated candidate smoke.
	// This unit test keeps its writable Core root fully temporary and does not mount production runtime files.
	if _, err := os.Stat(filepath.Join(root, "runtime", "die", "diec.exe")); err == nil {
		scanned, err := session.CallTool(ctx, &mcp.CallToolParams{
			Name: "die_scan",
			Arguments: map[string]any{
				"path": fixture, "verbose": true, "timeout_ms": 15000,
			},
		})
		if err != nil || scanned.IsError {
			t.Fatalf("die_scan failed: result=%#v err=%v", scanned, err)
		}
		var diePayload struct {
			Tool struct {
				Version string `json:"version"`
				SHA256  string `json:"sha256"`
			} `json:"tool"`
			Detects []any `json:"detects"`
		}
		decodeStructured(t, scanned.StructuredContent, &diePayload)
		if diePayload.Tool.Version != "3.21" || len(diePayload.Tool.SHA256) != 64 || len(diePayload.Detects) == 0 {
			t.Fatalf("die scan payload=%+v", diePayload)
		}
	}

	for _, item := range runtime.statuses() {
		if item.State != "idle" {
			t.Fatalf("host-only call started backend %s: %s", item.Name, item.State)
		}
	}
}

func TestProcessControlToolsRoundTripThroughMCP(t *testing.T) {
	root := t.TempDir()
	runtime, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	go func() { _ = runtime.Run(ctx, serverTransport) }()

	client := mcp.NewClient(&mcp.Implementation{Name: "process-control-test", Version: "1.0.0"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	pid := os.Getpid()
	identified, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "process_identify", Arguments: map[string]any{"pid": pid},
	})
	if err != nil || identified.IsError {
		t.Fatalf("process_identify failed: result=%#v err=%v", identified, err)
	}
	var identity struct {
		Key            string `json:"key"`
		MainModuleBase uint64 `json:"main_module_base"`
	}
	decodeStructured(t, identified.StructuredContent, &identity)
	if identity.Key == "" {
		t.Fatal("process_identify returned empty key")
	}

	routed, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "process_debug_route", Arguments: map[string]any{"pid": pid},
	})
	if err != nil || routed.IsError {
		t.Fatalf("process_debug_route failed: result=%#v err=%v", routed, err)
	}
	var route struct {
		ProcessKey      string `json:"process_key"`
		Machine         string `json:"machine"`
		Bits            int    `json:"bits"`
		Architecture    string `json:"architecture"`
		Backend         string `json:"backend"`
		AttachPerformed bool   `json:"attach_performed"`
	}
	decodeStructured(t, routed.StructuredContent, &route)
	if route.ProcessKey != identity.Key || route.AttachPerformed {
		t.Fatalf("process debug route=%+v identity=%+v", route, identity)
	}
	switch route.Bits {
	case 32:
		if route.Machine != "i386" || route.Architecture != "x86" || route.Backend != "x32dbg" {
			t.Fatalf("32-bit route=%+v", route)
		}
	case 64:
		if route.Machine != "amd64" || route.Architecture != "x86-64" || route.Backend != "x64dbg" {
			t.Fatalf("64-bit route=%+v", route)
		}
	default:
		t.Fatalf("unexpected route=%+v", route)
	}

	memoryStarted, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "memory_scan_start",
		Arguments: map[string]any{
			"pid": pid, "process_key": identity.Key, "value_type": "u32", "mode": "unknown",
			"start_address": identity.MainModuleBase, "end_address": identity.MainModuleBase + 4096,
			"max_bytes": 4096, "max_candidates": 2048, "timeout_ms": 3000,
		},
	})
	if err != nil || memoryStarted.IsError {
		t.Fatalf("memory_scan_start failed: result=%#v err=%v", memoryStarted, err)
	}
	var memoryScan struct {
		ID             string `json:"id"`
		Version        int    `json:"version"`
		CandidateCount int    `json:"candidate_count"`
		StepComplete   bool   `json:"step_complete"`
	}
	decodeStructured(t, memoryStarted.StructuredContent, &memoryScan)
	if memoryScan.ID == "" || memoryScan.Version != 1 || memoryScan.CandidateCount == 0 || !memoryScan.StepComplete {
		t.Fatalf("memory scan=%+v", memoryScan)
	}
	memoryRefined, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "memory_scan_refine",
		Arguments: map[string]any{
			"scan_id": memoryScan.ID, "expected_version": 1, "mode": "unchanged", "timeout_ms": 3000,
		},
	})
	if err != nil || memoryRefined.IsError {
		t.Fatalf("memory_scan_refine failed: result=%#v err=%v", memoryRefined, err)
	}
	var refined struct {
		Version        int  `json:"version"`
		CandidateCount int  `json:"candidate_count"`
		StepComplete   bool `json:"step_complete"`
	}
	decodeStructured(t, memoryRefined.StructuredContent, &refined)
	if refined.Version != 2 || refined.CandidateCount == 0 || !refined.StepComplete {
		t.Fatalf("refined memory scan=%+v", refined)
	}
	memoryGot, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "memory_scan_get", Arguments: map[string]any{"scan_id": memoryScan.ID, "sample_limit": 4},
	})
	if err != nil || memoryGot.IsError {
		t.Fatalf("memory_scan_get failed: result=%#v err=%v", memoryGot, err)
	}

	pointerBuilt, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "pointer_map_build",
		Arguments: map[string]any{
			"pid": pid, "process_key": identity.Key, "target_address": identity.MainModuleBase,
			"start_address": identity.MainModuleBase, "end_address": identity.MainModuleBase + 4096,
			"max_offset": 4096, "max_depth": 1, "max_bytes": 4096,
			"max_nodes": 4096, "max_chains": 1024, "timeout_ms": 3000,
		},
	})
	if err != nil || pointerBuilt.IsError {
		t.Fatalf("pointer_map_build failed: result=%#v err=%v", pointerBuilt, err)
	}
	var pointerMap struct {
		ID            string `json:"id"`
		Version       int    `json:"version"`
		PointerSize   int    `json:"pointer_size"`
		SourceProcess struct {
			Key string `json:"key"`
		} `json:"source_process"`
	}
	decodeStructured(t, pointerBuilt.StructuredContent, &pointerMap)
	if pointerMap.ID == "" || pointerMap.Version != 1 || pointerMap.SourceProcess.Key != identity.Key || (pointerMap.PointerSize != 4 && pointerMap.PointerSize != 8) {
		t.Fatalf("pointer map=%+v", pointerMap)
	}
	pointerGot, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "pointer_map_get", Arguments: map[string]any{"map_id": pointerMap.ID, "sample_limit": 4},
	})
	if err != nil || pointerGot.IsError {
		t.Fatalf("pointer_map_get failed: result=%#v err=%v", pointerGot, err)
	}
	pointerVerified, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "pointer_map_verify",
		Arguments: map[string]any{
			"map_id": pointerMap.ID, "pid": pid, "process_key": identity.Key,
			"target_address": identity.MainModuleBase, "timeout_ms": 3000, "sample_limit": 4,
		},
	})
	if err != nil || pointerVerified.IsError {
		t.Fatalf("pointer_map_verify failed: result=%#v err=%v", pointerVerified, err)
	}
	var pointerVerification struct {
		CrossProcess  bool `json:"cross_process"`
		CheckedChains int  `json:"checked_chains"`
		ValidChains   int  `json:"valid_chains"`
		InvalidChains int  `json:"invalid_chains"`
		Complete      bool `json:"complete"`
	}
	decodeStructured(t, pointerVerified.StructuredContent, &pointerVerification)
	if pointerVerification.CrossProcess || !pointerVerification.Complete || pointerVerification.CheckedChains != pointerVerification.ValidChains+pointerVerification.InvalidChains {
		t.Fatalf("pointer verification=%+v", pointerVerification)
	}

	acquired, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "process_control_acquire",
		Arguments: map[string]any{"pid": pid, "process_key": identity.Key, "owner": "mcp-process-test"},
	})
	if err != nil || acquired.IsError {
		t.Fatalf("process_control_acquire failed: result=%#v err=%v", acquired, err)
	}
	var lease struct {
		LeaseID string `json:"lease_id"`
	}
	decodeStructured(t, acquired.StructuredContent, &lease)
	if lease.LeaseID == "" {
		t.Fatal("process control lease id is empty")
	}

	got, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "process_control_get", Arguments: map[string]any{"pid": pid},
	})
	if err != nil || got.IsError {
		t.Fatalf("process_control_get failed: result=%#v err=%v", got, err)
	}

	released, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "process_control_release",
		Arguments: map[string]any{"pid": pid, "process_key": identity.Key, "owner": "mcp-process-test", "lease_id": lease.LeaseID},
	})
	if err != nil || released.IsError {
		t.Fatalf("process_control_release failed: result=%#v err=%v", released, err)
	}
	for _, item := range runtime.statuses() {
		if item.State != "idle" {
			t.Fatalf("process host tool started backend %s: %s", item.Name, item.State)
		}
	}
}

func TestPatchToolsRoundTripThroughMCP(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "sample.bin")
	original := []byte{0x10, 0x20, 0x30, 0x40}
	if err := os.WriteFile(target, original, 0o600); err != nil {
		t.Fatal(err)
	}
	runtime, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	go func() { _ = runtime.Run(ctx, serverTransport) }()

	client := mcp.NewClient(&mcp.Implementation{Name: "patch-tools-test", Version: "1.0.0"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	planned, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "patch_plan",
		Arguments: map[string]any{
			"path": target, "offset": 1,
			"expected_hex": "20 30", "replacement_hex": "AA BB",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var plan struct {
		ID string `json:"id"`
	}
	decodeStructured(t, planned.StructuredContent, &plan)
	if plan.ID == "" {
		t.Fatal("patch_plan returned empty id")
	}

	for _, name := range []string{"patch_get", "patch_dry_run"} {
		result, err := session.CallTool(ctx, &mcp.CallToolParams{
			Name: name, Arguments: map[string]any{"plan_id": plan.ID},
		})
		if err != nil || result.IsError {
			t.Fatalf("%s failed: result=%#v err=%v", name, result, err)
		}
	}

	applied, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "patch_apply",
		Arguments: map[string]any{"plan_id": plan.ID, "in_place": true, "operation_id": "mcp-apply-roundtrip"},
	})
	if err != nil || applied.IsError {
		t.Fatalf("patch_apply failed: result=%#v err=%v", applied, err)
	}
	replayed, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "patch_apply",
		Arguments: map[string]any{"plan_id": plan.ID, "in_place": true, "operation_id": "mcp-apply-roundtrip"},
	})
	if err != nil || replayed.IsError {
		t.Fatalf("patch_apply replay failed: result=%#v err=%v", replayed, err)
	}

	verified, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "patch_verify", Arguments: map[string]any{"plan_id": plan.ID},
	})
	if err != nil || verified.IsError {
		t.Fatalf("patch_verify failed: result=%#v err=%v", verified, err)
	}
	var verify struct {
		Valid bool `json:"valid"`
	}
	decodeStructured(t, verified.StructuredContent, &verify)
	if !verify.Valid {
		t.Fatalf("verify=%+v", verify)
	}

	rolled, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "patch_rollback", Arguments: map[string]any{"plan_id": plan.ID, "operation_id": "mcp-rollback-roundtrip"},
	})
	if err != nil || rolled.IsError {
		t.Fatalf("patch_rollback failed: result=%#v err=%v", rolled, err)
	}
	replayedRollback, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "patch_rollback", Arguments: map[string]any{"plan_id": plan.ID, "operation_id": "mcp-rollback-roundtrip"},
	})
	if err != nil || replayedRollback.IsError {
		t.Fatalf("patch_rollback replay failed: result=%#v err=%v", replayedRollback, err)
	}

	now, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(now) != string(original) {
		t.Fatalf("rollback bytes=%x want=%x", now, original)
	}

	composite, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "patch_plan",
		Arguments: map[string]any{
			"path": target,
			"edits": []any{
				map[string]any{"offset": 3, "expected_hex": "40", "replacement_hex": "A4"},
				map[string]any{"offset": 0, "expected_hex": "10", "replacement_hex": "A1"},
			},
		},
	})
	if err != nil || composite.IsError {
		t.Fatalf("composite patch_plan failed: result=%#v err=%v", composite, err)
	}
	var compositePlan struct {
		ID    string `json:"id"`
		Edits []struct {
			Offset int64 `json:"offset"`
		} `json:"edits"`
	}
	decodeStructured(t, composite.StructuredContent, &compositePlan)
	if compositePlan.ID == "" || len(compositePlan.Edits) != 2 ||
		compositePlan.Edits[0].Offset != 0 || compositePlan.Edits[1].Offset != 3 {
		t.Fatalf("composite plan=%+v", compositePlan)
	}
	compositeApply, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "patch_apply",
		Arguments: map[string]any{
			"plan_id": compositePlan.ID, "in_place": true, "operation_id": "mcp-composite-apply",
		},
	})
	if err != nil || compositeApply.IsError {
		t.Fatalf("composite patch_apply failed: result=%#v err=%v", compositeApply, err)
	}
	compositeRollback, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "patch_rollback",
		Arguments: map[string]any{
			"plan_id": compositePlan.ID, "operation_id": "mcp-composite-rollback",
		},
	})
	if err != nil || compositeRollback.IsError {
		t.Fatalf("composite patch_rollback failed: result=%#v err=%v", compositeRollback, err)
	}
	now, err = os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(now) != string(original) {
		t.Fatalf("composite rollback bytes=%x want=%x", now, original)
	}

	for _, item := range runtime.statuses() {
		if item.State != "idle" {
			t.Fatalf("patch host tool started backend %s: %s", item.Name, item.State)
		}
	}
}

func decodeStructured(t *testing.T, value any, dst any) {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, dst); err != nil {
		t.Fatal(err)
	}
}
