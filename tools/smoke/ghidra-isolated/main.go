package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"reverseresearch/internal/backend"
	"reverseresearch/internal/targetidentity"
)

type report struct {
	CheckedUTC        string                  `json:"checked_utc"`
	Port              int                     `json:"port"`
	StateDir          string                  `json:"state_dir"`
	EvidenceDir       string                  `json:"evidence_dir"`
	OldPath           string                  `json:"old_path"`
	NewPath           string                  `json:"new_path"`
	OldIdentity       targetidentity.Identity `json:"old_identity"`
	NewIdentity       targetidentity.Identity `json:"new_identity"`
	OpenOld           any                     `json:"open_old"`
	OpenNew           any                     `json:"open_new"`
	Databases         any                     `json:"databases"`
	OldInfo           any                     `json:"old_info,omitempty"`
	NewInfo           any                     `json:"new_info,omitempty"`
	OldInfoError      string                  `json:"old_info_error,omitempty"`
	NewInfoError      string                  `json:"new_info_error,omitempty"`
	OldFunctions      any                     `json:"old_functions,omitempty"`
	NewFunctions      any                     `json:"new_functions,omitempty"`
	OldFunctionsError string                  `json:"old_functions_error,omitempty"`
	NewFunctionsError string                  `json:"new_functions_error,omitempty"`
}

func main() {
	var root, workDir, version string
	var port int
	flag.StringVar(&root, "root", ".", "ReverseResearch repository root")
	flag.StringVar(&workDir, "work-dir", "", "isolated work directory; defaults to a removable OS temp directory")
	flag.StringVar(&version, "version", "old", "fixture version to analyze: old or new")
	flag.IntVar(&port, "port", 19196, "isolated Ghidra MCP port")
	flag.Parse()
	if version != "old" && version != "new" {
		die(fmt.Errorf("version must be old or new"))
	}

	absoluteRoot, err := filepath.Abs(root)
	die(err)
	autoWorkDir := false
	if workDir == "" {
		workDir, err = os.MkdirTemp("", "reverseresearch-ghidra-isolated-")
		die(err)
		autoWorkDir = true
	}
	absoluteWork, err := filepath.Abs(workDir)
	die(err)
	if autoWorkDir {
		defer os.RemoveAll(absoluteWork)
	}
	stateDir := filepath.Join(absoluteWork, "状态")
	evidenceDir := filepath.Join(absoluteWork, "证据")
	sampleDir := filepath.Join(absoluteWork, "样本（隔离）")
	die(os.MkdirAll(sampleDir, 0o755))

	source := filepath.Join(absoluteRoot, "testdata", "mcp-smoke.exe")
	oldPath := filepath.Join(sampleDir, "旧版本（测试）.exe")
	newPath := filepath.Join(sampleDir, "新版本（测试）.exe")
	body, err := os.ReadFile(source)
	die(err)
	die(os.WriteFile(oldPath, body, 0o644))
	newBody := append([]byte(nil), body...)
	if len(newBody) < 16 {
		die(fmt.Errorf("fixture is unexpectedly small"))
	}
	newBody[len(newBody)-1] ^= 0x01
	die(os.WriteFile(newPath, newBody, 0o644))

	oldIdentity, err := targetidentity.Inspect(oldPath)
	die(err)
	newIdentity, err := targetidentity.Inspect(newPath)
	die(err)
	if oldIdentity.SHA256 == newIdentity.SHA256 {
		die(fmt.Errorf("isolated old/new fixture hashes must differ"))
	}

	ghidra := backend.NewGhidraIsolated(absoluteRoot, stateDir, evidenceDir, port)
	defer ghidra.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	var openOld, openNew any
	var oldInfo, newInfo any
	var oldFunctions, newFunctions any
	var oldFunctionsErr, newFunctionsErr error
	if version == "old" {
		openOld = call(ctx, ghidra, "open_database", map[string]any{
			"file_path": oldPath, "run_auto_analysis": true, "keep_open": true,
			"database_id": "old_version", "force_new": true,
		})
		oldInfo = waitDatabaseInfo(ctx, ghidra, "old_version", oldPath)
		oldFunctions, oldFunctionsErr = tryCall(ctx, ghidra, "list_functions", map[string]any{"database": "old_version", "offset": 0, "limit": 200})
	} else {
		openNew = call(ctx, ghidra, "open_database", map[string]any{
			"file_path": newPath, "run_auto_analysis": true, "keep_open": true,
			"database_id": "new_version", "force_new": true,
		})
		newInfo = waitDatabaseInfo(ctx, ghidra, "new_version", newPath)
		newFunctions, newFunctionsErr = tryCall(ctx, ghidra, "list_functions", map[string]any{"database": "new_version", "offset": 0, "limit": 200})
	}
	if residues, _ := filepath.Glob(filepath.Join(stateDir, "tmp", "rr-ghidra-import-*")); len(residues) != 0 {
		die(fmt.Errorf("temporary Ghidra import aliases were not cleaned: %v", residues))
	}
	databases := call(ctx, ghidra, "list_databases", map[string]any{})

	result := report{
		CheckedUTC: time.Now().UTC().Format(time.RFC3339Nano),
		Port:       port, StateDir: stateDir, EvidenceDir: evidenceDir,
		OldPath: oldPath, NewPath: newPath,
		OldIdentity: oldIdentity, NewIdentity: newIdentity,
		OpenOld: openOld, OpenNew: openNew, Databases: databases,
		OldInfo: oldInfo, NewInfo: newInfo,
		OldFunctions: oldFunctions, NewFunctions: newFunctions,
		OldFunctionsError: errorText(oldFunctionsErr), NewFunctionsError: errorText(newFunctionsErr),
	}
	encoded, err := json.MarshalIndent(result, "", "  ")
	die(err)
	fmt.Println(string(encoded))
}

func call(ctx context.Context, ghidra *backend.Lazy, tool string, args map[string]any) any {
	value, err := tryCall(ctx, ghidra, tool, args)
	die(err)
	return value
}

func tryCall(ctx context.Context, ghidra *backend.Lazy, tool string, args map[string]any) (any, error) {
	raw, err := json.Marshal(args)
	if err != nil {
		return nil, err
	}
	result, err := ghidra.Call(ctx, tool, raw)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, fmt.Errorf("%s returned no result", tool)
	}
	if result.IsError {
		body, marshalErr := json.Marshal(result.Content)
		if marshalErr != nil {
			return nil, fmt.Errorf("%s returned MCP error: %v", tool, result.Content)
		}
		return nil, fmt.Errorf("%s returned MCP error: %s", tool, body)
	}
	if result.StructuredContent != nil {
		return result.StructuredContent, nil
	}
	return result.Content, nil
}

func waitDatabaseInfo(ctx context.Context, ghidra *backend.Lazy, database, expectedPath string) any {
	deadline := time.Now().Add(90 * time.Second)
	for {
		if _, err := tryCall(ctx, ghidra, "wait_for_analysis", map[string]any{"database": database}); err != nil {
			if !isDatabaseNotReady(err) {
				die(err)
			}
		}
		info, err := tryCall(ctx, ghidra, "get_database_info", map[string]any{"database": database})
		if err == nil {
			requireDatabaseSourcePath(database, info, expectedPath)
			return info
		}
		if !isDatabaseNotReady(err) || time.Now().After(deadline) {
			die(err)
		}
		select {
		case <-ctx.Done():
			die(ctx.Err())
		case <-time.After(150 * time.Millisecond):
		}
	}
}

func isDatabaseNotReady(err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "notready") || strings.Contains(text, "still opening") || strings.Contains(text, "analyzing")
}

func requireDatabaseSourcePath(label string, value any, expected string) {
	object, ok := value.(map[string]any)
	if !ok {
		die(fmt.Errorf("%s database info is not an object: %T", label, value))
	}
	got, _ := object["file_path"].(string)
	normalize := func(path string) string {
		path = strings.TrimSpace(path)
		if len(path) >= 3 && path[0] == '/' && path[2] == ':' {
			path = path[1:]
		}
		return filepath.Clean(filepath.FromSlash(path))
	}
	if !strings.EqualFold(normalize(got), normalize(expected)) {
		die(fmt.Errorf("%s executable path=%q want source=%q", label, got, expected))
	}
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func die(err error) {
	if err != nil {
		panic(err)
	}
}
