package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"reverseresearch/internal/buildversion"
)

func TestCLIVersionDoesNotCreateState(t *testing.T) {
	root := t.TempDir()
	for _, command := range []string{"version", "--version"} {
		var stdout, stderr bytes.Buffer
		if err := runCLI(context.Background(), root, []string{command}, &stdout, &stderr); err != nil {
			t.Fatal(err)
		}
		var result struct {
			Version string `json:"version"`
		}
		if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || result.Version != buildversion.Version {
			t.Fatalf("version query: %q %v", stdout.Bytes(), err)
		}
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("read-only version query created state: %v %v", entries, err)
	}
}

func TestCLIWithoutCommandPrintsUsageAndDoesNotServe(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := runCLI(context.Background(), t.TempDir(), nil, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "Usage:") {
		t.Fatalf("stdout=%q", stdout.String())
	}
	if strings.Contains(stdout.String(), "Local endpoint ready") {
		t.Fatalf("no-command invocation must not start MCP: %q", stdout.String())
	}
}

func TestCLITargetIdentify(t *testing.T) {
	root, _ := isolatedCLIRoot(t)
	target := filepath.Join(root, "testdata", "mcp-smoke.exe")
	var stdout, stderr bytes.Buffer
	if err := runCLI(context.Background(), root, []string{"target", "identify", target}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	var got struct {
		SHA256 string `json:"sha256"`
		Format string `json:"format"`
		PE     *struct {
			Bits int `json:"bits"`
		} `json:"pe"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode output: %v\n%s", err, stdout.String())
	}
	if len(got.SHA256) != 64 || got.Format != "pe" || got.PE == nil || got.PE.Bits != 32 {
		t.Fatalf("identity=%+v", got)
	}
}

func TestCLICompatibilityRecordRoundTrip(t *testing.T) {
	repoRoot := filepath.Clean(filepath.Join("..", ".."))
	fixture := filepath.Join(repoRoot, "testdata", "mcp-smoke.exe")
	root := t.TempDir()
	call := func(args ...string) []byte {
		t.Helper()
		var stdout, stderr bytes.Buffer
		if err := runCLI(context.Background(), root, args, &stdout, &stderr); err != nil {
			t.Fatalf("run %v: %v\nstderr=%s\nstdout=%s", args, err, stderr.String(), stdout.String())
		}
		return append([]byte(nil), stdout.Bytes()...)
	}

	var added struct {
		ID         string `json:"id"`
		Outcome    string `json:"outcome"`
		Validation string `json:"validation"`
		Module     struct {
			SHA256 string `json:"sha256"`
		} `json:"module"`
	}
	if err := json.Unmarshal(call(
		"compat", "add",
		"--game", "CLI Fixture",
		"--build", "1.0",
		"--module", fixture,
		"--outcome", "candidate",
		"--validation", "record-only",
	), &added); err != nil {
		t.Fatal(err)
	}
	if added.ID == "" || added.Outcome != "candidate" || added.Validation != "record-only" || len(added.Module.SHA256) != 64 {
		t.Fatalf("added=%+v", added)
	}

	var got struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(call("compat", "get", added.ID), &got); err != nil {
		t.Fatal(err)
	}
	if got.ID != added.ID {
		t.Fatalf("get=%+v", got)
	}

	var listed []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(call("compat", "list", "--game", "CLI Fixture"), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].ID != added.ID {
		t.Fatalf("list=%+v", listed)
	}

	var verified struct {
		RecordValid              bool `json:"record_valid"`
		SourceCurrent            bool `json:"source_current"`
		CompatibilityRevalidated bool `json:"compatibility_revalidated"`
	}
	if err := json.Unmarshal(call("compat", "verify", added.ID), &verified); err != nil {
		t.Fatal(err)
	}
	if !verified.RecordValid || !verified.SourceCurrent || verified.CompatibilityRevalidated {
		t.Fatalf("verify=%+v", verified)
	}
}

func TestCLIPrepareAndPlaybookSurface(t *testing.T) {
	root, _ := isolatedCLIRoot(t)
	var stdout, stderr bytes.Buffer
	if err := runCLI(context.Background(), root, []string{"prepare", "trace", "the", "browser", "JavaScript", "signature", "chain"}, &stdout, &stderr); err != nil {
		t.Fatalf("prepare: %v\nstderr=%s", err, stderr.String())
	}
	var prepared struct {
		Route struct {
			Route struct {
				ID string `json:"id"`
			} `json:"route"`
		} `json:"route"`
		Playbook *struct {
			ID        string `json:"id"`
			SkillPath string `json:"skill_path"`
			Gates     []any  `json:"gates"`
		} `json:"playbook"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &prepared); err != nil {
		t.Fatal(err)
	}
	if prepared.Route.Route.ID != "js-web" || prepared.Playbook == nil || prepared.Playbook.ID != "js-web" || len(prepared.Playbook.Gates) < 4 {
		t.Fatalf("prepared=%+v", prepared)
	}

	stdout.Reset()
	stderr.Reset()
	if err := runCLI(context.Background(), root, []string{"playbook", "route", "android"}, &stdout, &stderr); err != nil {
		t.Fatalf("playbook route: %v\nstderr=%s", err, stderr.String())
	}
	var playbook struct {
		ID       string `json:"id"`
		Platform string `json:"platform"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &playbook); err != nil {
		t.Fatal(err)
	}
	if playbook.ID != "android" || playbook.Platform != "android" {
		t.Fatalf("playbook=%+v", playbook)
	}
}

func TestCLIDIEScanWhenRuntimePresent(t *testing.T) {
	root, sourceRoot := isolatedCLIRoot(t)
	if _, err := os.Stat(filepath.Join(sourceRoot, "runtime", "die", "diec.exe")); err != nil {
		t.Skipf("bundled DiE runtime not present: %v", err)
	}
	fixture := filepath.Join(root, "testdata", "mcp-smoke.exe")
	var stdout, stderr bytes.Buffer
	if err := runCLI(context.Background(), root, []string{
		"die", "scan", fixture, "--verbose", "--timeout", "15s",
	}, &stdout, &stderr); err != nil {
		t.Fatalf("die scan: %v\nstderr=%s", err, stderr.String())
	}
	var payload struct {
		Tool struct {
			Version string `json:"version"`
			SHA256  string `json:"sha256"`
		} `json:"tool"`
		Detects []any `json:"detects"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("decode die scan: %v\n%s", err, stdout.String())
	}
	if payload.Tool.Version != "3.21" || len(payload.Tool.SHA256) != 64 || len(payload.Detects) == 0 {
		t.Fatalf("die scan payload=%+v", payload)
	}
}

func TestCLIProcessIdentityAndLeaseRoundTrip(t *testing.T) {
	root := t.TempDir()
	pid := strconv.Itoa(os.Getpid())
	call := func(args ...string) map[string]any {
		t.Helper()
		var stdout, stderr bytes.Buffer
		if err := runCLI(context.Background(), root, args, &stdout, &stderr); err != nil {
			t.Fatalf("%v: %v\\nstderr=%s", args, err, stderr.String())
		}
		var payload map[string]any
		if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
			t.Fatalf("%v decode: %v\\n%s", args, err, stdout.String())
		}
		return payload
	}

	identity := call("process", "inspect", pid)
	key, _ := identity["key"].(string)
	if key == "" || identity["creation_utc"] == "" || identity["main_module_base"] == float64(0) {
		t.Fatalf("process identity=%v", identity)
	}
	route := call("process", "debug-route", pid)
	if route["process_key"] != key || route["attach_performed"] != false {
		t.Fatalf("process debug route=%v identity=%v", route, identity)
	}
	switch route["bits"] {
	case float64(32):
		if route["machine"] != "i386" || route["architecture"] != "x86" || route["backend"] != "x32dbg" {
			t.Fatalf("32-bit route=%v", route)
		}
	case float64(64):
		if route["machine"] != "amd64" || route["architecture"] != "x86-64" || route["backend"] != "x64dbg" {
			t.Fatalf("64-bit route=%v", route)
		}
	default:
		t.Fatalf("unexpected route=%v", route)
	}
	baseFloat, ok := identity["main_module_base"].(float64)
	if !ok || baseFloat <= 0 {
		t.Fatalf("invalid main module base in identity=%v", identity)
	}
	base := uint64(baseFloat)
	scan := call(
		"memory", "scan", pid,
		"--key", key,
		"--type", "u32",
		"--unknown",
		"--start", strconv.FormatUint(base, 10),
		"--end", strconv.FormatUint(base+4096, 10),
		"--max-bytes", "4096",
		"--max-candidates", "2048",
		"--timeout", "3s",
	)
	scanID, _ := scan["id"].(string)
	scanCount, _ := scan["candidate_count"].(float64)
	if scanID == "" || scan["version"] != float64(1) || scanCount <= 0 || scan["step_complete"] != true {
		t.Fatalf("memory scan=%v", scan)
	}
	refined := call("memory", "refine", scanID, "--expected-version", "1", "--mode", "unchanged", "--timeout", "3s")
	refinedCount, _ := refined["candidate_count"].(float64)
	if refined["version"] != float64(2) || refinedCount <= 0 || refined["step_complete"] != true {
		t.Fatalf("memory refine=%v", refined)
	}
	storedScan := call("memory", "get", scanID, "--sample", "4")
	if storedScan["version"] != float64(2) || storedScan["candidate_count"] != refined["candidate_count"] {
		t.Fatalf("memory get=%v refined=%v", storedScan, refined)
	}
	pointerMap := call(
		"pointer", "scan", pid,
		"--key", key,
		"--target", strconv.FormatUint(base, 10),
		"--start", strconv.FormatUint(base, 10),
		"--end", strconv.FormatUint(base+4096, 10),
		"--max-offset", "4096",
		"--max-depth", "1",
		"--max-bytes", "4096",
		"--max-nodes", "4096",
		"--max-chains", "1024",
		"--timeout", "3s",
	)
	pointerMapID, _ := pointerMap["id"].(string)
	sourceProcess, _ := pointerMap["source_process"].(map[string]any)
	if pointerMapID == "" || pointerMap["version"] != float64(1) || sourceProcess["key"] != key {
		t.Fatalf("pointer map=%v", pointerMap)
	}
	storedMap := call("pointer", "get", pointerMapID, "--sample", "4")
	if storedMap["id"] != pointerMapID || storedMap["version"] != float64(1) {
		t.Fatalf("pointer get=%v", storedMap)
	}
	verifiedMap := call(
		"pointer", "verify", pointerMapID,
		"--pid", pid,
		"--key", key,
		"--target", strconv.FormatUint(base, 10),
		"--timeout", "3s",
		"--sample", "4",
	)
	if verifiedMap["complete"] != true || verifiedMap["cross_process"] != false {
		t.Fatalf("pointer verify=%v", verifiedMap)
	}
	lease := call("process", "acquire", pid, "--key", key, "--owner", "cli-process-test")
	if lease["process_key"] != key || lease["owner"] != "cli-process-test" {
		t.Fatalf("lease=%v", lease)
	}
	replayed := call("process", "acquire", pid, "--key", key, "--owner", "cli-process-test")
	if replayed["lease_id"] != lease["lease_id"] {
		t.Fatalf("lease replay changed identity: first=%v replay=%v", lease, replayed)
	}
	got := call("process", "get", pid)
	if got["lease_id"] != lease["lease_id"] {
		t.Fatalf("get=%v lease=%v", got, lease)
	}
	leaseID, _ := lease["lease_id"].(string)
	if leaseID == "" {
		t.Fatalf("lease id missing: %v", lease)
	}
	call("process", "release", pid, "--key", key, "--owner", "cli-process-test", "--lease-id", leaseID)

	var stdout, stderr bytes.Buffer
	if err := runCLI(context.Background(), root, []string{"process", "get", pid}, &stdout, &stderr); err == nil {
		t.Fatal("released process lease remained readable")
	}
}

func TestCLIX32GuardFlagsReachBoundaryWithoutStartingBackend(t *testing.T) {
	root := t.TempDir()
	var stdout, stderr bytes.Buffer
	err := runCLI(context.Background(), root, []string{
		"x32dbg", "WriteMemToAddress",
		"--json", `{"address":"401000","byteString":"90"}`,
		"--pid", "42",
		"--process-key", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"--owner", "cli-guard-test",
		"--lease-id", "lease-test",
		"--operation-id", "write-1",
	}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "process control lease not found") {
		t.Fatalf("guard flags did not reach lease boundary: err=%v stderr=%s", err, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	err = runCLI(context.Background(), root, []string{
		"x32dbg", "ExecuteDebuggerCommand",
		"--json", `{"command":"attach 99"}`,
	}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "blocked by the guarded mutation boundary") {
		t.Fatalf("generic debugger command was not blocked before backend startup: err=%v", err)
	}
}

func TestCLICompositePatchRoundTrip(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "composite.bin")
	original := []byte{0x10, 0x20, 0x30, 0x40, 0x50, 0x60}
	if err := os.WriteFile(target, original, 0o600); err != nil {
		t.Fatal(err)
	}
	call := func(args ...string) []byte {
		t.Helper()
		var stdout, stderr bytes.Buffer
		if err := runCLI(context.Background(), root, args, &stdout, &stderr); err != nil {
			t.Fatalf("%v: %v\nstderr=%s", args, err, stderr.String())
		}
		return stdout.Bytes()
	}

	var plan struct {
		ID    string `json:"id"`
		Edits []struct {
			Offset int64 `json:"offset"`
		} `json:"edits"`
	}
	if err := json.Unmarshal(call(
		"patch", "plan",
		"--path", target,
		"--edits-json", `[{"offset":4,"expected_hex":"50 60","replacement_hex":"A5 A6"},{"offset":1,"expected_hex":"20","replacement_hex":"B2"}]`,
		"--description", "cli composite",
	), &plan); err != nil {
		t.Fatal(err)
	}
	if plan.ID == "" || len(plan.Edits) != 2 || plan.Edits[0].Offset != 1 || plan.Edits[1].Offset != 4 {
		t.Fatalf("plan=%+v", plan)
	}

	var dry struct {
		Ready          bool `json:"ready"`
		EditCount      int  `json:"edit_count"`
		TotalByteCount int  `json:"total_byte_count"`
	}
	if err := json.Unmarshal(call("patch", "dry-run", plan.ID), &dry); err != nil {
		t.Fatal(err)
	}
	if !dry.Ready || dry.EditCount != 2 || dry.TotalByteCount != 3 {
		t.Fatalf("dry=%+v", dry)
	}
	call("patch", "apply", plan.ID, "--in-place", "--operation-id", "cli-composite-apply")
	call("patch", "verify", plan.ID)
	call("patch", "rollback", plan.ID, "--operation-id", "cli-composite-rollback")

	restored, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored, original) {
		t.Fatalf("restored=%x original=%x", restored, original)
	}
}

func TestCLIPatchRoundTrip(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "sample.bin")
	original := []byte{0x10, 0x20, 0x30, 0x40}
	if err := os.WriteFile(target, original, 0o600); err != nil {
		t.Fatal(err)
	}

	call := func(args ...string) map[string]any {
		t.Helper()
		var stdout, stderr bytes.Buffer
		if err := runCLI(context.Background(), root, args, &stdout, &stderr); err != nil {
			t.Fatalf("%v: %v\nstderr=%s", args, err, stderr.String())
		}
		var payload map[string]any
		if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
			t.Fatalf("%v decode: %v\n%s", args, err, stdout.String())
		}
		return payload
	}

	plan := call(
		"patch", "plan",
		"--path", target,
		"--offset", "0x1",
		"--expected", "20 30",
		"--replacement", "AA BB",
	)
	id, _ := plan["id"].(string)
	if id == "" {
		t.Fatalf("plan=%v", plan)
	}
	dry := call("patch", "dry-run", id)
	if ready, _ := dry["ready"].(bool); !ready {
		t.Fatalf("dry-run=%v", dry)
	}
	call("patch", "apply", id, "--in-place", "--operation-id", "cli-apply-roundtrip")
	verify := call("patch", "verify", id)
	if valid, _ := verify["valid"].(bool); !valid {
		t.Fatalf("verify=%v", verify)
	}
	call("patch", "rollback", id, "--operation-id", "cli-rollback-roundtrip")

	now, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(now) != string(original) {
		t.Fatalf("rollback=%x want=%x", now, original)
	}
}

func TestCLIModuleStatusIsLocalAndIdle(t *testing.T) {
	root, _ := isolatedCLIRoot(t)
	var stdout, stderr bytes.Buffer
	if err := runCLI(context.Background(), root, []string{"module", "status"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Backends []struct {
			Name  string `json:"name"`
			State string `json:"state"`
		} `json:"backends"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v\n%s", err, stdout.String())
	}
	if len(got.Backends) != 3 {
		t.Fatalf("backends=%v", got.Backends)
	}
	for _, backend := range got.Backends {
		if backend.State != "idle" {
			t.Fatalf("%s state=%q want idle", backend.Name, backend.State)
		}
	}
}

func TestDecodeModuleBatch(t *testing.T) {
	steps, err := decodeModuleBatch([]byte(`[
		{"module":"r2","tool":"open_file","arguments":{"file_path":"a.exe"}},
		{"module":"r2","tool":"show_info"}
	]`))
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 2 || steps[0].Module != "r2" || steps[1].Tool != "show_info" {
		t.Fatalf("steps=%+v", steps)
	}
	if _, err := decodeModuleBatch([]byte(`[{"module":"","tool":"x"}]`)); err == nil {
		t.Fatal("missing module must fail")
	}
}

func TestCLIRouteAndToolsScan(t *testing.T) {
	root, _ := isolatedCLIRoot(t)
	var routeOut, routeErr bytes.Buffer
	if err := runCLI(context.Background(), root, []string{"route", "找这个老游戏金币的内存地址"}, &routeOut, &routeErr); err != nil {
		t.Fatal(err)
	}
	var route struct {
		Route struct {
			ID string `json:"id"`
		} `json:"route"`
	}
	if err := json.Unmarshal(routeOut.Bytes(), &route); err != nil {
		t.Fatal(err)
	}
	if route.Route.ID != "memory-search" {
		t.Fatalf("route=%+v", route)
	}

	var toolsOut, toolsErr bytes.Buffer
	if err := runCLI(context.Background(), root, []string{"tools", "scan"}, &toolsOut, &toolsErr); err != nil {
		t.Fatal(err)
	}
	var index struct {
		Tools []struct {
			Name      string `json:"name"`
			Available bool   `json:"available"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(toolsOut.Bytes(), &index); err != nil {
		t.Fatal(err)
	}
	if len(index.Tools) == 0 {
		t.Fatal("tool index is empty")
	}
}

func TestCLICaseAndJournalLifecycle(t *testing.T) {
	root := t.TempDir()

	call := func(args ...string) map[string]any {
		t.Helper()
		var stdout, stderr bytes.Buffer
		if err := runCLI(context.Background(), root, args, &stdout, &stderr); err != nil {
			t.Fatalf("%v: %v\nstderr=%s", args, err, stderr.String())
		}
		var payload map[string]any
		if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
			t.Fatalf("%v decode: %v\n%s", args, err, stdout.String())
		}
		return payload
	}

	c := call("case", "create", "--title", "Unicode Ghidra regression", "--route", "native-static")
	caseID, _ := c["id"].(string)
	if caseID == "" {
		t.Fatalf("case=%v", c)
	}

	source := filepath.Join(root, "sample.bin")
	if err := os.WriteFile(source, []byte{1, 2, 3, 4}, 0o600); err != nil {
		t.Fatal(err)
	}
	e := call("case", "evidence", caseID, "--summary", "reproduction sample", "--kind", "file", "--source", source)
	evidenceID, _ := e["id"].(string)
	if evidenceID == "" {
		t.Fatalf("evidence=%v", e)
	}

	f := call(
		"case", "finding", caseID,
		"--title", "path handling fixed",
		"--conclusion", "content-addressed ASCII project names avoid invalid Unicode project names",
		"--strength", "observed",
		"--confidence", "high",
		"--evidence", evidenceID,
	)
	findingID, _ := f["id"].(string)
	if findingID == "" || f["strength"] != "observed" {
		t.Fatalf("finding=%v", f)
	}

	p := call(
		"case", "path", caseID,
		"--title", "validated import path",
		"--details", "unicode target -> ASCII project id -> Ghidra import",
		"--findings", findingID,
	)
	if id, _ := p["id"].(string); id == "" {
		t.Fatalf("path=%v", p)
	}

	got := call("case", "show", caseID)
	if len(got["evidence"].([]any)) != 1 || len(got["findings"].([]any)) != 1 || len(got["paths"].([]any)) != 1 {
		t.Fatalf("case show=%v", got)
	}

	note := call(
		"journal", "add",
		"--title", "Ghidra Unicode project naming",
		"--body", "Use a content-addressed ASCII project name and reclaim dead database IDs.",
		"--route", "native-static",
		"--tags", "ghidra,unicode,database",
	)
	if id, _ := note["id"].(string); id == "" {
		t.Fatalf("note=%v", note)
	}

	var stdout, stderr bytes.Buffer
	if err := runCLI(context.Background(), root, []string{"journal", "search", "unicode", "database"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	var results []map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &results); err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 {
		t.Fatal("journal search returned no results")
	}
}

func TestCLIKnowledgeFiltersAndBuiltinCorpus(t *testing.T) {
	root := t.TempDir()
	call := func(args ...string) []byte {
		t.Helper()
		var stdout, stderr bytes.Buffer
		if err := runCLI(context.Background(), root, args, &stdout, &stderr); err != nil {
			t.Fatalf("%v: %v\nstderr=%s", args, err, stderr.String())
		}
		return stdout.Bytes()
	}

	var note struct {
		ID            string   `json:"id"`
		Origin        string   `json:"origin"`
		Domain        string   `json:"domain"`
		Architectures []string `json:"architectures"`
		Tools         []string `json:"tools"`
	}
	if err := json.Unmarshal(call(
		"journal", "add",
		"--title", "structured unicode note",
		"--body", "unicode database recovery",
		"--route", "native-static",
		"--domain", "static-analysis",
		"--arch", "amd64",
		"--tools", "ghidra",
	), &note); err != nil {
		t.Fatal(err)
	}
	if note.ID == "" || note.Origin != "journal" || note.Domain != "static-analysis" ||
		len(note.Architectures) != 1 || note.Architectures[0] != "x86-64" ||
		len(note.Tools) != 1 || note.Tools[0] != "ghidra" {
		t.Fatalf("note=%+v", note)
	}

	var journal []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(call(
		"journal", "search",
		"--origin", "journal",
		"--domain", "static-analysis",
		"--arch", "x64",
		"--tools", "ghidra",
		"unicode",
	), &journal); err != nil {
		t.Fatal(err)
	}
	if len(journal) != 1 || journal[0].ID != note.ID {
		t.Fatalf("journal results=%+v", journal)
	}

	var builtins []struct {
		ID       string `json:"id"`
		Revision string `json:"revision"`
		Origin   string `json:"origin"`
	}
	if err := json.Unmarshal(call(
		"journal", "search",
		"--origin", "builtin",
		"--domain", "native-dynamic",
		"--arch", "x86",
		"--tools", "x32dbg",
	), &builtins); err != nil {
		t.Fatal(err)
	}
	if len(builtins) != 1 || builtins[0].ID != "builtin_x32_process_guard" ||
		builtins[0].Origin != "builtin" || len(builtins[0].Revision) != 64 {
		t.Fatalf("builtin results=%+v", builtins)
	}

	var shown struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(call("journal", "show", builtins[0].ID), &shown); err != nil {
		t.Fatal(err)
	}
	if shown.ID != builtins[0].ID {
		t.Fatalf("shown=%+v", shown)
	}
	var excerpt struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(call(
		"journal", "read", builtins[0].ID,
		"--revision", builtins[0].Revision,
		"--max-lines", "1",
	), &excerpt); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(excerpt.Text, "typed x32dbg mutation") {
		t.Fatalf("excerpt=%+v", excerpt)
	}
}

func TestCLIToolEnsurePlanAndSandboxCreate(t *testing.T) {
	root, _ := isolatedCLIRoot(t)
	var toolsOut, toolsErr bytes.Buffer
	if err := runCLI(context.Background(), root, []string{"tools", "ensure", "frida", "ghidra"}, &toolsOut, &toolsErr); err != nil {
		t.Fatal(err)
	}
	var plan struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(toolsOut.Bytes(), &plan); err != nil {
		t.Fatal(err)
	}
	if len(plan.Items) != 2 {
		t.Fatalf("plan=%+v", plan)
	}

	tempRoot := t.TempDir()
	var sandboxOut, sandboxErr bytes.Buffer
	if err := runCLI(context.Background(), tempRoot, []string{
		"sandbox", "create", "--name", "local lab", "--kind", "filesystem", "--route", "ctf-sandbox",
	}, &sandboxOut, &sandboxErr); err != nil {
		t.Fatal(err)
	}
	var created struct {
		Root  string `json:"root"`
		Ready bool   `json:"ready"`
	}
	if err := json.Unmarshal(sandboxOut.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Root == "" || !created.Ready {
		t.Fatalf("created=%+v", created)
	}
}

func TestCLIContractAuditCurrentSnapshot(t *testing.T) {
	root, _ := isolatedCLIRoot(t)
	var stdout, stderr bytes.Buffer
	if err := runCLI(context.Background(), root, []string{"contract", "audit"}, &stdout, &stderr); err != nil {
		t.Fatalf("contract audit: %v\nstderr=%s", err, stderr.String())
	}
	var report struct {
		Match              bool `json:"match"`
		SnapshotToolCount  int  `json:"snapshot_tool_count"`
		LocalBaseToolCount int  `json:"local_base_tool_count"`
		RRToolCount        int  `json:"rr_tool_count"`
		RTToolCount        int  `json:"rt_tool_count"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("decode contract audit: %v\n%s", err, stdout.String())
	}
	if !report.Match || report.SnapshotToolCount != 124 || report.LocalBaseToolCount != 124 ||
		report.RRToolCount != 124 || report.RTToolCount != 124 {
		t.Fatalf("report=%+v", report)
	}
}

func TestCLICapabilityStatus(t *testing.T) {
	root, _ := isolatedCLIRoot(t)
	var stdout, stderr bytes.Buffer
	if err := runCLI(context.Background(), root, []string{"capability", "status", "native-static"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	var status struct {
		RouteID  string `json:"route_id"`
		Runnable bool   `json:"runnable"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.RouteID != "native-static" || !status.Runnable {
		t.Fatalf("status=%+v", status)
	}

	stdout.Reset()
	stderr.Reset()
	if err := runCLI(context.Background(), root, []string{"capability", "list"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	var all []map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &all); err != nil {
		t.Fatal(err)
	}
	if len(all) < 10 {
		t.Fatalf("capabilities=%d", len(all))
	}
}

func TestCLIPrepare(t *testing.T) {
	root, _ := isolatedCLIRoot(t)
	var stdout, stderr bytes.Buffer
	if err := runCLI(context.Background(), root, []string{"prepare", "把旧版分兵函数迁移到新版"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Route struct {
			Route struct {
				ID string `json:"id"`
			} `json:"route"`
		} `json:"route"`
		Capability struct {
			RouteID string `json:"route_id"`
		} `json:"capability"`
		Sandbox struct {
			Kind string `json:"kind"`
		} `json:"sandbox"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Route.Route.ID != "binary-diff" || got.Capability.RouteID != "binary-diff" {
		t.Fatalf("prepared=%+v", got)
	}
	if got.Sandbox.Kind != "filesystem" {
		t.Fatalf("sandbox=%+v", got.Sandbox)
	}
}

func TestCLIBinaryDiff(t *testing.T) {
	root, _ := isolatedCLIRoot(t)
	target := filepath.Join(root, "testdata", "mcp-smoke.exe")

	var stdout, stderr bytes.Buffer
	if err := runCLI(context.Background(), root, []string{"diff", "quick", target, target}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	var quick struct {
		ChangeCount int `json:"change_count"`
		Comparison  struct {
			SameContent bool `json:"same_content"`
		} `json:"comparison"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &quick); err != nil {
		t.Fatal(err)
	}
	if !quick.Comparison.SameContent || quick.ChangeCount != 0 {
		t.Fatalf("quick=%+v", quick)
	}

	stdout.Reset()
	stderr.Reset()
	if err := runCLI(context.Background(), root, []string{"diff", "functions", target, target, "--threshold", "70"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	var functions struct {
		Exact   int              `json:"exact"`
		Matches []map[string]any `json:"matches"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &functions); err != nil {
		t.Fatal(err)
	}
	if functions.Exact == 0 || len(functions.Matches) == 0 {
		t.Fatalf("functions=%+v", functions)
	}
}
