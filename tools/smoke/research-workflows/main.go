// research-workflows verifies an exact candidate over real loopback MCP in a
// fresh, owned installation. It never executes the analyzed PE/JS targets.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"reverseresearch/internal/bindiff"
	"reverseresearch/internal/buildversion"
	"reverseresearch/internal/casebook"
	"reverseresearch/internal/die"
	"reverseresearch/internal/migration"
	"reverseresearch/internal/sandbox"
	"reverseresearch/internal/targetidentity"
	"reverseresearch/internal/toolindex"
	"reverseresearch/internal/toolprocess"
)

type bearerTransport struct{ token string }

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	copy := r.Clone(r.Context())
	copy.Header = r.Header.Clone()
	copy.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(copy)
}

type harness struct {
	ctx       context.Context
	session   *mcp.ClientSession
	work      string
	sequence  int
	workflows []map[string]any
}

func (h *harness) call(name string, arguments map[string]any, destination any) (string, error) {
	path, result, err := h.callResult(name, arguments)
	if err != nil {
		return "", err
	}
	if destination != nil {
		body, err := json.Marshal(result.StructuredContent)
		if err != nil {
			return "", err
		}
		if err := json.Unmarshal(body, destination); err != nil {
			return "", err
		}
	}
	return path, nil
}

func (h *harness) callResult(name string, arguments map[string]any) (string, *mcp.CallToolResult, error) {
	r, err := h.session.CallTool(h.ctx, &mcp.CallToolParams{Name: name, Arguments: arguments})
	if err != nil {
		return "", nil, fmt.Errorf("%s: %w", name, err)
	}
	if r == nil {
		return "", nil, fmt.Errorf("%s returned no execution result", name)
	}
	value := r.StructuredContent
	if value == nil {
		// Stdio backends may return text content without structuredContent.
		// Preserve the actual protocol result instead of recording JSON null.
		value = r
	}
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return "", nil, err
	}
	h.sequence++
	path := filepath.Join(h.work, "calls", fmt.Sprintf("%03d-%s.json", h.sequence, name))
	if err := os.WriteFile(path, append(body, '\n'), 0o600); err != nil {
		return "", nil, err
	}
	if r.IsError {
		return path, r, fmt.Errorf("%s returned an execution error: %s", name, body[:min(len(body), 1800)])
	}
	return path, r, nil
}

func main() {
	var root, candidate, compiler, work string
	var androidAPK string
	var androidCodeDEX string
	var goTarget string
	var evmTarget, evmReceipt string
	var radareProfile, ghidraProfile string
	var android androidProducers
	flag.StringVar(&root, "root", ".", "source repository root")
	flag.StringVar(&candidate, "executable", "", "verified candidate executable")
	flag.StringVar(&compiler, "compiler", "", "existing Windows GCC executable for owned fixtures")
	flag.StringVar(&work, "work-dir", "", "new evidence directory; existing directories are refused")
	flag.StringVar(&android.aapt2, "android-aapt2", "", "optional exact AAPT2 producer executable")
	flag.StringVar(&android.r8, "android-r8", "", "optional exact D8/R8 producer jar")
	flag.StringVar(&android.jdk, "android-jdk", "", "optional existing JDK directory for owned Android fixtures")
	flag.StringVar(&androidAPK, "android-apk", "", "existing producer-verified owned APK for native Linux workflow")
	flag.BoolVar(&android.code, "android-code-recovery", false, "also produce and verify owned DEX instructions/JADX recovery")
	flag.StringVar(&androidCodeDEX, "android-code-dex", "", "owned D8-produced DEX for native Linux code recovery")
	flag.StringVar(&goTarget, "go-metadata-target", "", "existing producer-verified owned Go binary; analysis only")
	flag.StringVar(&evmTarget, "evm-target", "", "owned compiler-produced EVM hex carrier; analysis only")
	flag.StringVar(&evmReceipt, "evm-receipt", "", "exact owned EVM producer receipt")
	flag.StringVar(&radareProfile, "radare-profile", "", "optional existing native Linux runtime profile root")
	flag.StringVar(&ghidraProfile, "ghidra-profile", "", "optional existing native Linux Ghidra runtime profile root")
	flag.Parse()
	if runtime.GOOS == "linux" {
		if err := runLinux(root, candidate, work, androidAPK, radareProfile, ghidraProfile, androidCodeDEX, goTarget, evmTarget, evmReceipt); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		count := 1
		if androidCodeDEX != "" {
			count++
		}
		if goTarget != "" {
			count++
		}
		if evmTarget != "" {
			count++
		}
		fmt.Printf("PASS version=%s native=linux workflows=%d receipt=%s\n", buildversion.Version, count, filepath.Join(work, "receipt.json"))
		return
	}
	if err := run(root, candidate, compiler, work, android, goTarget, evmTarget, evmReceipt); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	count := 3
	if android.enabled() {
		count++
	}
	if android.code {
		count++
	}
	if goTarget != "" {
		count++
	}
	if evmTarget != "" {
		count++
	}
	fmt.Printf("PASS version=%s workflows=%d receipt=%s\n", buildversion.Version, count, filepath.Join(work, "receipt.json"))
}

func run(root, candidate, compiler, work string, android androidProducers, goTarget, evmTarget, evmReceipt string) (resultErr error) {
	if candidate == "" || compiler == "" || work == "" {
		return errors.New("executable, compiler and a new work-dir are required")
	}
	for _, path := range []*string{&root, &candidate, &compiler, &work} {
		absolute, err := filepath.Abs(*path)
		if err != nil {
			return err
		}
		*path = absolute
	}
	if err := os.Mkdir(work, 0o700); err != nil {
		return fmt.Errorf("fresh work-dir required; inspect existing evidence rather than replaying mutations: %w", err)
	}
	for _, name := range []string{"calls", "inputs", "bin", "reports"} {
		if err := os.Mkdir(filepath.Join(work, name), 0o700); err != nil {
			return err
		}
	}
	// A copied candidate has the fresh config as its nearest ancestor. This
	// matters because the production CLI deliberately resolves its EXE root first.
	for _, name := range []string{"config", "skills"} {
		if err := os.CopyFS(filepath.Join(work, name), os.DirFS(filepath.Join(root, name))); err != nil {
			return err
		}
	}
	// The owned candidate never needs a cloud tunnel or its credential reference.
	if err := os.Remove(filepath.Join(work, "config", "tunnel.json")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	selected, err := targetidentity.Inspect(candidate)
	if err != nil {
		return err
	}
	body, err := os.ReadFile(candidate)
	if err != nil {
		return err
	}
	clone := filepath.Join(work, "bin", "ReverseResearch-MCP.exe")
	if err := os.WriteFile(clone, body, 0o700); err != nil {
		return err
	}
	cloned, err := targetidentity.Inspect(clone)
	if err != nil {
		return err
	}
	if cloned.SHA256 != selected.SHA256 {
		return errors.New("candidate changed while copying into isolated installation")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	compilerIdentity, err := targetidentity.Inspect(compiler)
	if err != nil {
		return err
	}
	left, right := filepath.Join(work, "inputs", "old.exe"), filepath.Join(work, "inputs", "new.exe")
	for i, output := range []string{left, right} {
		args := []string{"-O0", "-fno-inline", "-g", "-DRR_OFFSET=" + strconv.Itoa(i+1), filepath.Join(root, "tools", "fixtures", "versioned-program", "program.c"), "-o", output}
		r := toolprocess.Run(ctx, compiler, args, 64<<10, 64<<10, work)
		if r.Err != nil || r.Truncated {
			return fmt.Errorf("owned fixture build %d failed: %w: %s", i, r.Err, r.Stderr)
		}
	}
	compilerAfter, err := targetidentity.Inspect(compiler)
	if err != nil {
		return err
	}
	if compilerIdentity.SHA256 != compilerAfter.SHA256 {
		return errors.New("compiler changed while producing fixtures")
	}
	var androidAPK, androidReceipt string
	if android.enabled() {
		androidAPK, androidReceipt, err = buildAndroidFixture(ctx, root, work, android)
		if err != nil {
			return err
		}
	}
	var codeDEX, codeReceipt string
	if android.code {
		codeDEX, codeReceipt, err = buildAndroidCodeFixture(ctx, root, work, android)
		if err != nil {
			return err
		}
		if err := installAndroidRecovery(root, work, android.jdk); err != nil {
			return err
		}
	}
	roots := []string{filepath.Join(root, "runtime", "die")}
	engines, err := filepath.Glob(filepath.Join(root, "runtime", "radare2", "engine", "radare2-*-w64", "bin"))
	if err != nil {
		return err
	}
	roots = append(roots, engines...)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		return err
	}
	logFile, err := os.OpenFile(filepath.Join(work, "server.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, logFile.Close()) }()
	cmd := exec.CommandContext(ctx, clone, "serve", "--listen", address)
	cmd.Dir, cmd.Stdout, cmd.Stderr = work, logFile, logFile
	cmd.Env = append(os.Environ(), "REVERSERESEARCH_TOOLS="+strings.Join(roots, string(os.PathListSeparator)))
	if err := cmd.Start(); err != nil {
		return err
	}
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	var token string
	var session *mcp.ClientSession
	defer func() {
		if session != nil {
			resultErr = errors.Join(resultErr, session.Close())
		}
		if token != "" {
			stopCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
			req, _ := http.NewRequestWithContext(stopCtx, http.MethodPost, "http://"+address+"/control/shutdown", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			response, err := http.DefaultClient.Do(req)
			if err == nil {
				err = response.Body.Close()
			}
			stop()
			resultErr = errors.Join(resultErr, err)
		}
		select {
		case err := <-waited:
			resultErr = errors.Join(resultErr, err)
		case <-time.After(40 * time.Second):
			cancel()
			resultErr = errors.Join(resultErr, errors.New("owned candidate did not gracefully stop"), <-waited)
		}
		// Publish final PASS only after the owned process actually exits.
		receiptPath := filepath.Join(work, "receipt.json")
		if body, err := os.ReadFile(receiptPath); err == nil {
			var receipt map[string]any
			if err := json.Unmarshal(body, &receipt); err != nil {
				resultErr = errors.Join(resultErr, err)
			} else {
				receipt["shutdown_verified"] = resultErr == nil
				if resultErr == nil {
					receipt["status"] = "PASS"
				} else {
					receipt["status"] = "FAILED"
					receipt["failure"] = resultErr.Error()
				}
				resultErr = errors.Join(resultErr, writeJSON(receiptPath, receipt))
			}
		}
	}()
	ready := false
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); {
		select {
		case err := <-waited:
			waited <- err
			return fmt.Errorf("owned candidate exited before readiness: %w", err)
		default:
		}
		requestCtx, done := context.WithTimeout(ctx, time.Second)
		req, _ := http.NewRequestWithContext(requestCtx, http.MethodGet, "http://"+address+"/healthz", nil)
		response, err := http.DefaultClient.Do(req)
		if err == nil {
			var health struct {
				OK      bool   `json:"ok"`
				Version string `json:"version"`
			}
			err = json.NewDecoder(response.Body).Decode(&health)
			_ = response.Body.Close()
			ready = err == nil && health.OK && health.Version == buildversion.Version
		}
		done()
		if ready {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		return errors.New("owned candidate health/version was not accepted")
	}
	tokenBytes, err := os.ReadFile(filepath.Join(work, "state", "auth", "local-mcp.token"))
	if err != nil {
		return err
	}
	token = strings.TrimSpace(string(tokenBytes))
	client := mcp.NewClient(&mcp.Implementation{Name: "research-workflows", Version: buildversion.Version}, nil)
	session, err = client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: "http://" + address + "/mcp", HTTPClient: &http.Client{Transport: bearerTransport{token: token}}, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		return err
	}
	if session.InitializeResult().ServerInfo.Version != buildversion.Version {
		return errors.New("MCP candidate version mismatch")
	}
	var tools []*mcp.Tool
	for cursor := ""; ; {
		listed, err := session.ListTools(ctx, &mcp.ListToolsParams{Cursor: cursor})
		if err != nil {
			return err
		}
		tools = append(tools, listed.Tools...)
		if listed.NextCursor == "" {
			break
		}
		cursor = listed.NextCursor
	}
	if len(tools) != 282 {
		return fmt.Errorf("candidate catalog=%d want=282", len(tools))
	}
	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })
	if err := writeJSON(filepath.Join(work, "candidate-catalog.json"), tools); err != nil {
		return err
	}
	h := harness{ctx: ctx, session: session, work: work}
	if _, err := h.call("playbook_list", map[string]any{}, nil); err != nil {
		return err
	}
	if _, err := h.call("capability_status", map[string]any{"route_id": "native-static"}, nil); err != nil {
		return err
	}
	var toolIndex toolindex.Index
	if _, err := h.call("tool_index_scan", map[string]any{}, &toolIndex); err != nil {
		return err
	}
	radiff, available := toolIndex.ByName("radiff2")
	if !available || !radiff.Available {
		return errors.New("real radiff2 is required")
	}
	producer, err := targetidentity.Inspect(radiff.Path)
	if err != nil {
		return err
	}
	probeCtx, probeCancel := context.WithTimeout(ctx, 10*time.Second)
	banner := toolprocess.Run(probeCtx, producer.Path, []string{"-v"}, 16<<10, 16<<10, work)
	probeCancel()
	if banner.Err != nil {
		return fmt.Errorf("radiff2 version observation: %w", banner.Err)
	}
	if banner.Truncated {
		return errors.New("radiff2 version observation was truncated")
	}
	producerPath := filepath.Join(work, "calls", "radiff2-producer.json")
	if err := writeJSON(producerPath, map[string]any{"identity": producer, "args": []string{"-v"}, "stdout": string(banner.Stdout), "stderr": string(banner.Stderr)}); err != nil {
		return err
	}
	var identity targetidentity.Identity
	identityPath, err := h.call("target_identify", map[string]any{"path": left}, &identity)
	if err != nil {
		return err
	}
	if identity.PE == nil || identity.PE.Bits != 64 {
		return errors.New("owned GCC fixture was not a 64-bit PE")
	}
	var detected die.Report
	diePath, err := h.call("die_scan", map[string]any{"path": left, "timeout_ms": 15000}, &detected)
	if err != nil {
		return err
	}
	if len(detected.Detects) == 0 || detected.Tool.SHA256 == "" {
		return errors.New("real DiE producer evidence missing")
	}
	if err := h.closeCase("Windows PE 静态研究", "分析这个 Windows PE 程序的结构和导入，保留静态证据并生成研究报告", "native-static", []string{left}, []string{identityPath, diePath}, "Observed a 64-bit PE and real DiE producer output. This is static triage, not runtime behavior or completed decompilation."); err != nil {
		return err
	}
	var quick struct {
		Result bindiff.QuickResult `json:"result"`
		Total  int                 `json:"total"`
	}
	quickPath, err := h.call("binary_diff_quick", map[string]any{"left_path": left, "right_path": right}, &quick)
	if err != nil {
		return err
	}
	if quick.Result.Comparison.SameContent || quick.Total == 0 {
		return errors.New("compiled versions did not produce a byte difference")
	}
	var functions struct {
		Result       bindiff.FunctionResult `json:"result"`
		NextOffset   int                    `json:"next_offset"`
		Truncated    bool                   `json:"truncated"`
		ResultSHA256 string                 `json:"result_sha256"`
	}
	var selectedMatch *bindiff.FunctionMatch
	var functionPaths []string
	for offset, revision := 0, ""; ; {
		args := map[string]any{"left_path": left, "right_path": right, "limit": 200}
		if offset > 0 {
			args["offset"], args["expected_result_sha256"] = offset, revision
		}
		p, err := h.call("binary_diff_functions", args, &functions)
		if err != nil {
			return err
		}
		functionPaths = append(functionPaths, p)
		for _, m := range functions.Result.Matches {
			if strings.Contains(m.OldName, "rr_calculate") {
				copy := m
				selectedMatch = &copy
				break
			}
		}
		if selectedMatch != nil || !functions.Truncated {
			break
		}
		offset, revision = functions.NextOffset, functions.ResultSHA256
	}
	if selectedMatch == nil {
		return errors.New("owned exported rr_calculate was absent from function analysis")
	}
	var planned struct {
		Result migration.Result `json:"result"`
	}
	planPath, err := h.call("function_migration_plan", map[string]any{"left_path": left, "right_path": right, "anchors": []migration.Anchor{{Label: "rr_calculate", OldName: selectedMatch.OldName}}}, &planned)
	if err != nil {
		return err
	}
	if planned.Result.Validation != "candidate-only" || planned.Result.RuntimeVerified || planned.Result.Mapped != 1 {
		return errors.New("owned function did not produce one candidate-only mapping")
	}
	entry := planned.Result.Entries[0]
	var preview struct {
		Validation      string `json:"validation"`
		RuntimeVerified bool   `json:"runtime_verified"`
		WritesPerformed bool   `json:"writes_performed"`
		Preserved       int    `json:"preserved"`
	}
	previewPath, err := h.call("semantic_sync_preview", map[string]any{"migration": planned.Result, "source": map[string]any{"functions": []any{map[string]any{"rva": entry.OldRVA, "name": "rr_calculate_reviewed", "name_origin": "user"}}}, "target": map[string]any{"functions": []any{map[string]any{"rva": entry.NewRVA, "name": "manual_target_name", "name_origin": "user"}}}}, &preview)
	if err != nil {
		return err
	}
	if preview.Validation != "preview-only" || preview.WritesPerformed || preview.RuntimeVerified || preview.Preserved < 1 {
		return errors.New("semantic preview did not preserve target user naming")
	}
	paths := append([]string{quickPath, producerPath}, functionPaths...)
	paths = append(paths, planPath, previewPath)
	if err := h.closeCase("跨版本函数候选迁移", "比较两个版本的 Windows PE 程序，找出变化函数，生成迁移候选，并将证据关联到研究案例后输出报告。", "binary-diff", []string{left, right}, paths, "Observed static rr_calculate mapping between two owned builds. The semantic preview preserves a target user name. Candidate-only/runtime_verified=false; no symbol or byte writes were performed."); err != nil {
		return err
	}
	js := filepath.Join(work, "inputs", "app.js")
	if err := os.WriteFile(js, []byte("export function token(value) { return value + 1; }\n//# sourceMappingURL=app.js.map\n"), 0o600); err != nil {
		return err
	}
	sourceMap := filepath.Join(work, "inputs", "app.js.map")
	if err := writeJSON(sourceMap, map[string]any{"version": 3, "file": "app.js", "sources": []string{"src/token.js"}, "sourcesContent": []string{"export function token(value) { return value + 1; }"}, "names": []string{}, "mappings": "AAAA"}); err != nil {
		return err
	}
	har := filepath.Join(work, "inputs", "capture.har")
	if err := writeJSON(har, map[string]any{"log": map[string]any{"version": "1.2", "creator": map[string]any{"name": "owned-workflow-fixture", "version": "1"}, "entries": []any{map[string]any{"startedDateTime": "2026-10-13T00:00:00Z", "time": 1, "request": map[string]any{"method": "POST", "url": "https://example.invalid/api/token", "httpVersion": "HTTP/1.1", "headers": []any{}, "queryString": []any{}, "cookies": []any{}, "headersSize": -1, "bodySize": 0}, "response": map[string]any{"status": 200, "statusText": "OK", "httpVersion": "HTTP/1.1", "headers": []any{}, "cookies": []any{}, "content": map[string]any{"size": 13, "mimeType": "application/json", "text": "{\"token\":123}"}, "redirectURL": "", "headersSize": -1, "bodySize": 13}, "cache": map[string]any{}, "timings": map[string]any{"send": 0, "wait": 1, "receive": 0}}}}}); err != nil {
		return err
	}
	jsPath, err := h.call("app_javascript_inspect", map[string]any{"path": js}, nil)
	if err != nil {
		return err
	}
	mapPath, err := h.call("web_source_map_locate", map[string]any{"path": sourceMap, "line": 0, "column": 0}, nil)
	if err != nil {
		return err
	}
	harPath, err := h.call("web_har_api", map[string]any{"path": har}, nil)
	if err != nil {
		return err
	}
	if err := h.closeCase("JS/SourceMap/HAR 离线研究", "分析 Electron JavaScript 和 SourceMap 的声明，并查看离线 HAR 请求记录", "js-web", []string{js, sourceMap, har}, []string{jsPath, mapPath, harPath}, "Observed JavaScript declarations, a local source-map declaration and an owned historical HAR API group. No browser was launched, no request replayed, and no live server behavior inferred."); err != nil {
		return err
	}
	if androidAPK != "" {
		if err := h.androidCase(androidAPK, androidReceipt); err != nil {
			return err
		}
	}
	if codeDEX != "" {
		if err := h.androidCodeCase(codeDEX, codeReceipt); err != nil {
			return err
		}
	}
	if goTarget != "" {
		if err := h.goMetadataCase(goTarget); err != nil {
			return err
		}
	}
	if evmTarget != "" {
		if err := h.evmInterfaceCase(evmTarget, evmReceipt); err != nil {
			return err
		}
	}
	var status struct {
		Backends []struct{ Name, State string } `json:"backends"`
	}
	if _, err := h.call("reverse_status", map[string]any{}, &status); err != nil {
		return err
	}
	for _, b := range status.Backends {
		if b.State != "idle" {
			return fmt.Errorf("persistent backend unexpectedly started: %s", b.Name)
		}
	}
	producerAfter, err := targetidentity.Inspect(producer.Path)
	if err != nil {
		return err
	}
	if producer.SHA256 != producerAfter.SHA256 || producer.Size != producerAfter.Size {
		return errors.New("radiff2 producer changed during workflow verification")
	}
	if err := writeJSON(filepath.Join(work, "receipt.json"), map[string]any{"status": "ANALYSIS_PASS", "version": buildversion.Version, "candidate": selected, "isolated_candidate": cloned, "compiler": compilerIdentity, "radiff2_producer": producer, "producer_currentness_verified": true, "pid": cmd.Process.Pid, "endpoint": "http://" + address + "/mcp", "tool_count": len(tools), "workflows": h.workflows, "target_execution_performed": false, "persistent_backends": status.Backends}); err != nil {
		return err
	}
	return nil
}

func (h *harness) closeCase(title, text, route string, targets, evidencePaths []string, conclusion string) error {
	var prepared struct {
		Sandbox    sandbox.Plan `json:"sandbox"`
		Capability struct {
			Runnable  bool `json:"runnable"`
			FullReady bool `json:"full_ready"`
		} `json:"capability"`
		Playbook struct {
			ID    string
			Gates []any
		} `json:"playbook"`
		Route struct {
			Route struct {
				ID string `json:"id"`
			} `json:"route"`
		} `json:"route"`
	}
	if _, err := h.call("task_prepare", map[string]any{"text": text}, &prepared); err != nil {
		return err
	}
	if prepared.Route.Route.ID != route {
		return fmt.Errorf("natural task routed to %q, want %q", prepared.Route.Route.ID, route)
	}
	if route == "android-static" && (!prepared.Capability.Runnable || !prepared.Capability.FullReady || !prepared.Sandbox.Ready || prepared.Playbook.ID != "android-static" || len(prepared.Playbook.Gates) != 4) {
		return errors.New("built-in Android offline workflow was not ready without device tools")
	}
	for range 2 {
		var created struct {
			Plan                     sandbox.Plan `json:"plan"`
			IsolationStarted         bool         `json:"isolation_started"`
			TargetExecutionPerformed bool         `json:"target_execution_performed"`
		}
		path, err := h.call("sandbox_create", map[string]any{"plan": prepared.Sandbox}, &created)
		if err != nil {
			return err
		}
		if created.Plan.ID != prepared.Sandbox.ID || created.IsolationStarted || created.TargetExecutionPerformed {
			return errors.New("sandbox plan retry changed identity or claimed an isolation/target effect")
		}
		evidencePaths = append(evidencePaths, path)
	}
	evidencePaths = append(evidencePaths, filepath.Join(prepared.Sandbox.Root, "sandbox.json"))
	var engagement struct {
		ID string `json:"id"`
	}
	if _, err := h.call("engagement_create", map[string]any{"organization": "Owned fixture research", "operator": "research-workflows", "scope": map[string]any{"targets": targets, "allowed_actions": []string{"observe"}, "authorization": map[string]any{"status": "granted", "basis": "owned_fixture", "evidence_refs": targets}, "network_profile": map[string]any{"mode": "authorized_target_only", "notes": "No target network: loopback MCP only"}}}, &engagement); err != nil {
		return err
	}
	caseTargets := make([]map[string]any, 0, len(targets))
	for i, path := range targets {
		caseTargets = append(caseTargets, map[string]any{"id": fmt.Sprintf("fixture_%d", i), "kind": "file", "identity": path})
	}
	var c struct {
		ID string `json:"id"`
	}
	if _, err := h.call("case_create", map[string]any{"title": title, "route": route, "engagement_id": engagement.ID, "targets": caseTargets}, &c); err != nil {
		return err
	}
	if _, err := h.call("case_role_assign", map[string]any{"case_id": c.ID, "role": "lead", "specialist_skill": "seep-reverse-lab"}, nil); err != nil {
		return err
	}
	var work struct {
		ID string `json:"id"`
	}
	if _, err := h.call("case_workitem_add", map[string]any{"case_id": c.ID, "title": "Own fixture analysis and evidence review", "owner_role": "lead"}, &work); err != nil {
		return err
	}
	var ids []string
	for _, path := range append(append([]string{}, targets...), evidencePaths...) {
		var e struct {
			ID string `json:"id"`
		}
		if _, err := h.call("case_evidence_add", map[string]any{"case_id": c.ID, "summary": "Exact owned input or actual MCP producer result", "kind": "static", "source_path": path, "linked_workitem_id": work.ID}, &e); err != nil {
			return err
		}
		ids = append(ids, e.ID)
	}
	var finding struct {
		ID string `json:"id"`
	}
	if _, err := h.call("case_finding_add", map[string]any{"case_id": c.ID, "title": title, "conclusion": conclusion, "strength": "observed", "status": "candidate", "evidence_ids": ids}, &finding); err != nil {
		return err
	}
	if _, err := h.call("case_path_add", map[string]any{"case_id": c.ID, "title": "Bound inputs → static observations → reviewed candidate/report", "details": conclusion, "finding_ids": []string{finding.ID}}, nil); err != nil {
		return err
	}
	if _, err := h.call("case_workitem_update", map[string]any{"case_id": c.ID, "workitem_id": work.ID, "status": "done", "coverage": "Bounded static owned fixture profile", "evidence_ids": ids}, nil); err != nil {
		return err
	}
	if _, err := h.call("case_timeline_add", map[string]any{"case_id": c.ID, "kind": "static-review", "summary": "Static source/result evidence reviewed; runtime conclusions remain unverified", "role": "lead", "workitem_id": work.ID, "evidence_ids": ids}, nil); err != nil {
		return err
	}
	var review casebook.Review
	if _, err := h.call("case_review", map[string]any{"case_id": c.ID}, &review); err != nil {
		return err
	}
	if !review.Ready {
		return fmt.Errorf("strict review failed for %s: %+v", route, review.Issues)
	}
	output := filepath.Join(h.work, "reports", route+"-"+c.ID+".md")
	var report any
	if _, err := h.call("report_render", map[string]any{"case_id": c.ID, "profile": "general", "classification": "internal", "format": "markdown", "status": "final", "output_path": output}, &report); err != nil {
		return err
	}
	var note struct{ ID, Revision string }
	noteArgs := map[string]any{"operation_id": "wf-note-" + c.ID, "title": title, "body": conclusion, "route": route}
	if _, err := h.call("journal_add", noteArgs, &note); err != nil {
		return err
	}
	var repeated struct{ ID, Revision string }
	if _, err := h.call("journal_add", noteArgs, &repeated); err != nil {
		return err
	}
	if note.ID != repeated.ID || note.Revision != repeated.Revision {
		return errors.New("note retry created another research fact")
	}
	if _, err := h.call("journal_get", map[string]any{"id": note.ID}, nil); err != nil {
		return err
	}
	if _, err := h.call("journal_search", map[string]any{"route": route, "origin": "journal"}, nil); err != nil {
		return err
	}
	if _, err := h.call("journal_read", map[string]any{"id": note.ID, "revision": note.Revision}, nil); err != nil {
		return err
	}
	h.workflows = append(h.workflows, map[string]any{"route": route, "case_id": c.ID, "case_sha256": review.CaseSHA256, "strict_review_ready": review.Ready, "report": report, "report_path": output, "note_id": note.ID, "note_revision": note.Revision, "runtime_verified": false})
	return nil
}

func writeJSON(path string, value any) error {
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(body, '\n'), 0o600)
}
