package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
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
	"reverseresearch/internal/buildversion"
	"reverseresearch/internal/targetidentity"
	"reverseresearch/internal/toolprocess"
)

// Linux uses the same harness/Case/report/Journal and server owners. The
// installation is fresh and private; production state/credentials are absent.
func runLinux(root, candidate, work, apk, radareProfile, ghidraProfile, codeDEX, goTarget, evmTarget, evmReceipt string) (resultErr error) {
	if candidate == "" || work == "" || apk == "" {
		return errors.New("native Linux requires exact executable, owned android-apk and fresh work-dir")
	}
	for _, path := range []*string{&root, &candidate, &work, &apk} {
		absolute, err := filepath.Abs(*path)
		if err != nil {
			return err
		}
		*path = absolute
	}
	if err := os.Mkdir(work, 0700); err != nil {
		return fmt.Errorf("fresh native work-dir required: %w", err)
	}
	for _, name := range []string{"bin", "inputs", "calls", "reports"} {
		if err := os.Mkdir(filepath.Join(work, name), 0700); err != nil {
			return err
		}
	}
	if radareProfile != "" || ghidraProfile != "" {
		if err := os.Mkdir(filepath.Join(work, "runtime"), 0700); err != nil {
			return err
		}
	}
	for name, source := range map[string]string{"radare2": radareProfile, "ghidra": ghidraProfile} {
		if source == "" {
			continue
		}
		profile, err := filepath.Abs(source)
		if err != nil {
			return err
		}
		if err := os.Symlink(filepath.Join(profile, "runtime", name), filepath.Join(work, "runtime", name)); err != nil {
			return err
		}
	}
	profiles := []string{"config", "skills"}
	if ghidraProfile != "" {
		profiles = append(profiles, "patches/ghidra")
	}
	if codeDEX != "" {
		if ghidraProfile == "" {
			return errors.New("native JADX acceptance requires the existing full-JDK profile")
		}
		profiles = append(profiles, "patches/jadx")
	}
	for _, name := range profiles {
		err := fs.WalkDir(os.DirFS(filepath.Join(root, name)), ".", func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return errors.New("profile symlink refused")
			}
			if name == "config" && path == "tunnel.json" {
				return nil
			}
			dest := filepath.Join(work, name, path)
			if entry.IsDir() {
				return os.MkdirAll(dest, 0700)
			}
			info, err := entry.Info()
			if err != nil || !info.Mode().IsRegular() || info.Size() > 4<<20 {
				return errors.New("profile member outside regular/size profile")
			}
			body, err := os.ReadFile(filepath.Join(root, name, path))
			if err != nil {
				return err
			}
			return os.WriteFile(dest, body, 0600)
		})
		if err != nil {
			return err
		}
	}
	source, err := targetidentity.Inspect(candidate)
	if err != nil {
		return err
	}
	body, err := os.ReadFile(candidate)
	if err != nil {
		return err
	}
	clone := filepath.Join(work, "bin", "ReverseResearch-MCP")
	if err := os.WriteFile(clone, body, 0700); err != nil {
		return err
	}
	identity, err := targetidentity.Inspect(clone)
	if err != nil {
		return err
	}
	if identity.SHA256 != source.SHA256 || identity.ELF == nil {
		return errors.New("native ELF copy differs")
	}
	inputBefore, err := targetidentity.Inspect(apk)
	if err != nil {
		return err
	}
	elfBefore, err := targetidentity.Inspect("/usr/bin/ls")
	if err != nil {
		return err
	}
	if codeDEX != "" {
		if err := installAndroidRecovery(root, work, ""); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	for _, probe := range []struct {
		name string
		args []string
	}{
		{"version", []string{"--version"}},
		{"manifest-cli", []string{"app", "package", apk, "--family", "android", "--view", "manifest", "--expected-sha256", inputBefore.SHA256}},
		{"dex-cli", []string{"app", "dex", apk, "--entry", "classes.dex", "--view", "methods", "--expected-sha256", inputBefore.SHA256}},
		{"elf-cli", []string{"target", "identify", "/usr/bin/ls"}},
	} {
		r := toolprocess.Run(ctx, clone, probe.args, 64<<10, 64<<10, work)
		if r.Err != nil || r.Truncated {
			return fmt.Errorf("native CLI %s failed: %v: %s", probe.name, r.Err, r.Stderr)
		}
		if err := os.WriteFile(filepath.Join(work, "calls", probe.name+".json"), r.Stdout, 0600); err != nil {
			return err
		}
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		return err
	}
	log, err := os.OpenFile(filepath.Join(work, "server.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, log.Close()) }()
	cmd := exec.CommandContext(ctx, clone, "serve", "--listen", address)
	cmd.Dir, cmd.Stdout, cmd.Stderr = work, log, log
	if err := cmd.Start(); err != nil {
		return err
	}
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	var token string
	var session *mcp.ClientSession
	var engineScopes []string
	defer func() {
		if session != nil {
			resultErr = errors.Join(resultErr, session.Close())
		}
		if token != "" {
			stopCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
			req, _ := http.NewRequestWithContext(stopCtx, http.MethodPost, "http://"+address+"/control/shutdown", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			response, err := http.DefaultClient.Do(req)
			if err == nil {
				err = response.Body.Close()
			}
			stop()
			resultErr = errors.Join(resultErr, err)
		} else {
			cancel()
		}
		select {
		case err := <-waited:
			resultErr = errors.Join(resultErr, err)
		case <-time.After(35 * time.Second):
			cancel()
			resultErr = errors.Join(resultErr, errors.New("native owned server did not gracefully exit"), <-waited)
		}
		for _, path := range engineScopes {
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				resultErr = errors.Join(resultErr, fmt.Errorf("native backend scope removal unverified: %s: %v", path, err))
			}
		}
		if b, err := os.ReadFile(filepath.Join(work, "receipt.json")); err == nil {
			var receipt map[string]any
			if err := json.Unmarshal(b, &receipt); err != nil {
				resultErr = errors.Join(resultErr, err)
			} else {
				receipt["shutdown_verified"] = resultErr == nil
				receipt["backend_scope_cleanup_verified"] = len(engineScopes) > 0 && resultErr == nil
				if resultErr == nil {
					receipt["status"] = "PASS"
				} else {
					receipt["status"] = "FAILED"
					receipt["failure"] = resultErr.Error()
				}
				resultErr = errors.Join(resultErr, writeJSON(filepath.Join(work, "receipt.json"), receipt))
			}
		}
	}()
	ready := false
	for until := time.Now().Add(12 * time.Second); time.Now().Before(until); {
		response, err := (&http.Client{Timeout: time.Second}).Get("http://" + address + "/healthz")
		if err == nil {
			var health struct {
				OK      bool
				Version string
			}
			err = json.NewDecoder(response.Body).Decode(&health)
			_ = response.Body.Close()
			if err == nil && health.OK && health.Version == buildversion.Version {
				ready = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		return errors.New("native health/version not ready")
	}
	secret, err := os.ReadFile(filepath.Join(work, "state", "auth", "local-mcp.token"))
	if err != nil {
		return err
	}
	token = strings.TrimSpace(string(secret))
	client := mcp.NewClient(&mcp.Implementation{Name: "native-linux-verifier", Version: buildversion.Version}, nil)
	session, err = client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: "http://" + address + "/mcp", HTTPClient: &http.Client{Transport: bearerTransport{token}}, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		return err
	}
	if session.InitializeResult().ServerInfo.Version != buildversion.Version {
		return errors.New("native MCP version differs")
	}
	tools, err := session.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		return err
	}
	if len(tools.Tools) != 282 || tools.NextCursor != "" {
		return errors.New("native complete catalog differs")
	}
	if err := writeJSON(filepath.Join(work, "candidate-catalog.json"), tools.Tools); err != nil {
		return err
	}
	h := harness{ctx: ctx, session: session, work: work}
	var elf targetidentity.Identity
	if _, err := h.call("target_identify", map[string]any{"path": "/usr/bin/ls"}, &elf); err != nil {
		return err
	}
	if elf.ELF == nil || elf.Format != "elf" {
		return errors.New("native system ELF not observed")
	}
	if err := h.androidCase(apk, filepath.Join(root, "evidence", "android-research-workflows-20261013-02", "inputs", "android", "producer-receipt.json")); err != nil {
		return err
	}
	if codeDEX != "" {
		if err := h.androidCodeCase(codeDEX, ""); err != nil {
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
	verifiedEngines := []string{}
	if ghidraProfile != "" {
		if err := h.linuxGhidraWorkflow("/usr/bin/ls"); err != nil {
			return err
		}
		verifiedEngines = append(verifiedEngines, "ghidra")
	}
	if radareProfile != "" {
		if err := h.linuxRadareWorkflow("/usr/bin/ls", elfBefore.Size); err != nil {
			return err
		}
		verifiedEngines = append(verifiedEngines, "radare2")
	}
	after, err := targetidentity.Inspect(apk)
	if err != nil {
		return err
	}
	if after.SHA256 != inputBefore.SHA256 {
		return errors.New("native APK input changed")
	}
	elfAfter, err := targetidentity.Inspect("/usr/bin/ls")
	if err != nil || elfAfter.SHA256 != elfBefore.SHA256 {
		return errors.Join(errors.New("native analyzed ELF currentness differs"), err)
	}
	if radareProfile != "" || ghidraProfile != "" {
		engineScopes, err = nativeBackendScopes(cmd.Process.Pid)
		if err != nil {
			return err
		}
		expectedScopes := 0
		for _, profile := range []string{radareProfile, ghidraProfile} {
			if profile != "" {
				expectedScopes++
			}
		}
		if len(engineScopes) != expectedScopes {
			return errors.New("native live backend scope count differs")
		}
	}
	for _, path := range []string{work, filepath.Join(work, "state"), filepath.Join(work, "state", "auth")} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0700 {
			return fmt.Errorf("native private directory mode differs: %s", path)
		}
	}
	var status any
	if _, err := h.call("reverse_status", map[string]any{}, &status); err != nil {
		return err
	}
	return writeJSON(filepath.Join(work, "receipt.json"), map[string]any{"status": "ANALYSIS_PASS", "native_goos": runtime.GOOS, "version": buildversion.Version, "source_executable": source, "candidate": identity, "pid": cmd.Process.Pid, "endpoint": "http://" + address + "/mcp", "tool_count": len(tools.Tools), "workflows": h.workflows, "private_modes_verified": true, "input_currentness_verified": true, "analyzed_elf": elfBefore, "target_execution_performed": false, "verified_external_engines": verifiedEngines, "backend_scopes": engineScopes, "backend_status": status})
}

// Observe the owned server's direct backend children. Cleanup remains in the
// original backend owner; the verifier never kills or reparents these groups.
func nativeBackendScopes(serverPID int) ([]string, error) {
	childrenFiles, err := filepath.Glob(fmt.Sprintf("/proc/%d/task/*/children", serverPID))
	if err != nil {
		return nil, err
	}
	if len(childrenFiles) == 0 || len(childrenFiles) > 512 {
		return nil, errors.New("native server task inventory outside verifier bound")
	}
	children := map[string]bool{}
	for _, path := range childrenFiles {
		body, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		for _, pid := range strings.Fields(string(body)) {
			children[pid] = true
		}
	}
	var scopes []string
	for pid := range children {
		if strings.Trim(pid, "0123456789") != "" {
			return nil, errors.New("invalid native child identity")
		}
		membership, err := os.ReadFile("/proc/" + pid + "/cgroup")
		if err != nil {
			return nil, err
		}
		line := strings.TrimSpace(string(membership))
		if !strings.HasPrefix(line, "0::/") {
			return nil, errors.New("native child has no unified backend group")
		}
		rel := strings.TrimPrefix(line, "0::/")
		if filepath.Clean(rel) != rel || !strings.HasPrefix(filepath.Base(rel), "rr-backend-") {
			return nil, errors.New("native child is outside prepared backend scope")
		}
		path := filepath.Join("/sys/fs/cgroup", rel)
		if _, err := os.Stat(path); err != nil {
			return nil, err
		}
		scopes = append(scopes, path)
	}
	sort.Strings(scopes)
	return scopes, nil
}

func (h *harness) engineObject(name string, arguments map[string]any) (map[string]any, error) {
	_, result, err := h.callResult(name, arguments)
	if err != nil {
		return nil, err
	}
	value, err := engineValue(result)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s did not return an object", name)
	}
	return object, nil
}

func (h *harness) engineText(name string, arguments map[string]any) (string, error) {
	_, result, err := h.callResult(name, arguments)
	if err != nil {
		return "", err
	}
	if len(result.Content) != 1 {
		return "", fmt.Errorf("%s did not return a single text content block", name)
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok || strings.TrimSpace(text.Text) == "" {
		return "", fmt.Errorf("%s did not return actual engine text", name)
	}
	return text.Text, nil
}

func (h *harness) linuxRadareWorkflow(path string, expectedSize int64) error {
	opened, err := h.engineText("r2_open_file", map[string]any{"file_path": path})
	if err != nil {
		return err
	}
	if opened != "File opened successfully." {
		return fmt.Errorf("native radare2 open failed: %s", opened)
	}
	info, err := h.engineText("r2_show_info", map[string]any{})
	if err != nil {
		return err
	}
	fields := map[string]string{}
	for _, line := range strings.Split(info, "\n") {
		words := strings.Fields(line)
		if len(words) == 2 {
			fields[words[0]] = words[1]
		}
	}
	size, err := strconv.ParseInt(fields["size"], 0, 64)
	if err != nil || size != expectedSize || fields["file"] != path || fields["format"] != "elf64" || fields["bits"] != "64" || fields["arch"] != "x86" || fields["endian"] != "little" {
		return fmt.Errorf("native radare2 ELF information differs: %s", info)
	}
	analyzed, err := h.engineText("r2_analyze", map[string]any{"level": 1, "timeout_seconds": 10})
	if err != nil {
		return err
	}
	var functionCount int
	if _, err := fmt.Sscanf(analyzed, "Analysis completed with level 1.\nFound %d functions.", &functionCount); err != nil || functionCount < 3 {
		return fmt.Errorf("native radare2 analysis result differs: %s", analyzed)
	}
	functions, err := h.engineText("r2_list_functions", map[string]any{"max_length": 3})
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimSpace(functions), "\n")
	if len(lines) != 3 {
		return fmt.Errorf("native radare2 function page differs: %s", functions)
	}
	seen := map[uint64]bool{}
	for _, line := range lines {
		words := strings.Fields(line)
		if len(words) != 2 {
			return errors.New("native radare2 function record invalid")
		}
		address, err := strconv.ParseUint(words[0], 0, 64)
		if err != nil || address == 0 || seen[address] {
			return errors.New("native radare2 function address invalid or repeated")
		}
		seen[address] = true
	}
	closed, err := h.engineText("r2_close_file", map[string]any{})
	if err != nil {
		return err
	}
	if closed != "File closed successfully." {
		return fmt.Errorf("native radare2 close failed: %s", closed)
	}
	return nil
}

func engineValue(result *mcp.CallToolResult) (any, error) {
	if result == nil || result.IsError {
		return nil, errors.New("engine protocol error")
	}
	var body []byte
	if result.StructuredContent != nil {
		var err error
		body, err = json.Marshal(result.StructuredContent)
		if err != nil {
			return nil, err
		}
	} else {
		for _, content := range result.Content {
			if text, ok := content.(*mcp.TextContent); ok {
				if body != nil {
					return nil, errors.New("ambiguous multiple engine JSON content blocks")
				}
				body = []byte(text.Text)
			}
		}
	}
	var value any
	if err := json.Unmarshal(body, &value); err != nil {
		return nil, fmt.Errorf("engine JSON content missing or invalid: %w", err)
	}
	if value == nil {
		return nil, errors.New("engine returned no semantic value")
	}
	if object, ok := value.(map[string]any); ok {
		if nested, ok := object["result"].(map[string]any); ok && len(object) == 1 {
			value, object = nested, nested
		}
		if object["success"] == false || object["status"] == "error" || object["status"] == "failed" {
			return nil, errors.New("engine reported a semantic failure")
		}
		if failure, exists := object["error"]; exists && failure != nil && failure != "" {
			return nil, errors.New("engine returned an error payload")
		}
	}
	return value, nil
}

func (h *harness) linuxGhidraWorkflow(path string) error {
	const database = "native_elf"
	opened, err := h.engineObject("ghidra_open_database", map[string]any{"file_path": path, "database_id": database, "run_auto_analysis": true})
	if err != nil {
		return err
	}
	if opened["status"] != "opening" || opened["database"] != database || opened["file_path"] != path || opened["opening"] != true {
		return fmt.Errorf("native Ghidra open result differs: %v", opened)
	}
	ready, err := h.engineObject("ghidra_wait_for_analysis", map[string]any{"database": database})
	if err != nil {
		return err
	}
	if ready["status"] != "ready" || ready["database"] != database || ready["file_path"] != path || ready["bitness"] != float64(64) {
		return fmt.Errorf("native Ghidra analysis completion differs: %v", ready)
	}
	info, err := h.engineObject("ghidra_get_database_info", map[string]any{"database": database})
	if err != nil {
		return err
	}
	if info["bitness"] != float64(64) || info["endian"] != "little" || !strings.Contains(fmt.Sprint(info["file_type"]), "ELF") {
		return fmt.Errorf("native Ghidra ELF information differs: %v", info)
	}
	functions, err := h.engineObject("ghidra_list_functions", map[string]any{"database": database, "limit": 3})
	if err != nil {
		return err
	}
	items, ok := functions["items"].([]any)
	if !ok || len(items) == 0 {
		return fmt.Errorf("native Ghidra functions missing: %v", functions)
	}
	function, ok := items[0].(map[string]any)
	if !ok || function["start"] == nil {
		return errors.New("native Ghidra function address missing")
	}
	decompiled, err := h.engineObject("ghidra_decompile_function", map[string]any{"database": database, "address": function["start"]})
	if err != nil {
		return err
	}
	code, ok := decompiled["decompiled_code"].(string)
	if !ok || strings.TrimSpace(code) == "" || !strings.Contains(code, "{") || decompiled["function_name"] != function["name"] {
		return errors.New("native Ghidra decompiler did not return C pseudocode for the selected function")
	}
	closed, err := h.engineObject("ghidra_close_database", map[string]any{"database": database, "save": false})
	if err != nil {
		return err
	}
	if closed["status"] != "closed" {
		return fmt.Errorf("native Ghidra close result differs: %v", closed)
	}
	return nil
}
