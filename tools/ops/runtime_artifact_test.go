package ops

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// The fixture executable only answers the explicit layout query or a launcher
// probe. It never starts a service or accesses the real research state.
var fixtureACLReset func() int

func TestMain(m *testing.M) {
	if fixtureACLReset != nil && strings.EqualFold(filepath.Base(os.Args[0]), "icacls.exe") {
		os.Exit(fixtureACLReset())
	}
	if len(os.Args) == 3 && os.Args[1] == "state-layout" && os.Args[2] == "capabilities" {
		fmt.Print(`{"schema_version":"reverseresearch.state-layout-capabilities.v1","min_supported_layout":1,"max_supported_layout":2,"writes_layout":2}`)
		os.Exit(0)
	}
	if len(os.Args) >= 2 && os.Args[1] == "serve" {
		fmt.Print("fixture launcher probe\n")
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func powershell(t *testing.T, args ...string) ([]byte, error) {
	t.Helper()
	if runtime.GOOS != "windows" {
		t.Skip("Windows deployment contract")
	}
	cmd := exec.Command("powershell.exe", append([]string{"-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass"}, args...)...)
	return cmd.CombinedOutput()
}

func copyArtifactFixture(t *testing.T, destination string, overlay bool) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if overlay {
		body = append(body, 0x42)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, body, 0o700); err != nil {
		t.Fatal(err)
	}
}

func TestSharedArtifactSelectionExcludesCandidatesAndDriftedRollback(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows deployment contract")
	}
	sourceRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "RR space 测试")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	module := filepath.Join(sourceRoot, "tools", "ops", "runtime-artifact.psm1")
	selectionCommand := "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); Import-Module $env:RR_TEST_MODULE; Resolve-RRInstalledArtifact -Root $env:RR_TEST_ROOT"
	cmd := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", selectionCommand)
	cmd.Env = append(os.Environ(), "RR_TEST_MODULE="+module, "RR_TEST_ROOT="+root)
	selected, err := cmd.CombinedOutput()
	if err != nil || strings.TrimSpace(string(selected)) != filepath.Join(root, "dist", "ReverseResearch-MCP.exe") {
		t.Fatalf("empty install selection=%q err=%v", selected, err)
	}
	candidate := filepath.Join(root, "dist", "candidate", "ReverseResearch-MCP.exe")
	installed := filepath.Join(root, "ReverseResearch-MCP.exe")
	copyArtifactFixture(t, candidate, true)
	copyArtifactFixture(t, installed, false)
	cmd = exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", selectionCommand)
	cmd.Env = append(os.Environ(), "RR_TEST_MODULE="+module, "RR_TEST_ROOT="+root)
	selected, err = cmd.CombinedOutput()
	if err != nil || strings.TrimSpace(string(selected)) != installed {
		t.Fatalf("candidate replaced installed selection=%q err=%v", selected, err)
	}
	promotion := filepath.Join(sourceRoot, "tools", "ops", "manage-promotion.ps1")
	task := "RR artifact fixture " + filepath.Base(t.TempDir())
	invoke := func(action string, extra ...string) ([]byte, error) {
		args := []string{"-File", promotion, "-Root", root, "-TaskName", task, "-Action", action}
		return powershell(t, append(args, extra...)...)
	}
	old, _ := os.ReadFile(installed)
	output, err := invoke("Promote", "-Candidate", candidate)
	if err != nil {
		t.Fatalf("staging Promote: %s %v", output, err)
	}
	var promoted struct {
		Production struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		} `json:"production"`
		RollbackAllowed bool `json:"rollback_allowed"`
	}
	if err := json.Unmarshal(output, &promoted); err != nil {
		t.Fatalf("promotion output: %s %v", output, err)
	}
	if promoted.Production.Path != installed || !promoted.RollbackAllowed {
		t.Fatalf("wrong artifact/rollback=%+v", promoted)
	}
	manifestPath := filepath.Join(root, ".tmp", "promotion", "promotion.json")
	before, _ := os.ReadFile(manifestPath)
	output, err = invoke("Promote", "-Candidate", candidate)
	if err != nil {
		t.Fatalf("same candidate: %s %v", output, err)
	}
	after, _ := os.ReadFile(manifestPath)
	if !bytes.Equal(before, after) {
		t.Fatal("same candidate destroyed rollback provenance")
	}
	// A prepared receipt is an unresolved release, including when publication
	// already happened. A retry must not overwrite it or report it committed.
	var receipt map[string]any
	if err := json.Unmarshal(before, &receipt); err != nil {
		t.Fatal(err)
	}
	receipt["promotion_state"] = "prepared"
	prepared, _ := json.Marshal(receipt)
	if err := os.WriteFile(manifestPath, prepared, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"Promote", "Rollback"} {
		output, err = invoke(action, "-Candidate", candidate)
		if err == nil || !strings.Contains(string(output), "prepared") {
			t.Fatalf("uncommitted %s accepted: %s %v", action, output, err)
		}
		current, _ := os.ReadFile(manifestPath)
		if !bytes.Equal(current, prepared) {
			t.Fatal("uncommitted receipt was overwritten")
		}
	}
	if err := os.WriteFile(manifestPath, before, 0o600); err != nil {
		t.Fatal(err)
	}
	installedBody, _ := os.ReadFile(installed)
	if err := os.WriteFile(installed, append(append([]byte{}, installedBody...), 0x43), 0o700); err != nil {
		t.Fatal(err)
	}
	output, err = invoke("Rollback")
	if err == nil || !strings.Contains(string(output), "unrelated artifact") {
		t.Fatalf("rollback overwrote a replaced install: %s %v", output, err)
	}
	if err := os.WriteFile(installed, installedBody, 0o700); err != nil {
		t.Fatal(err)
	}
	assertConcurrentReleaseRefused(t, root, func() ([]byte, error) { return invoke("Promote", "-Candidate", candidate) })
	output, err = invoke("Rollback")
	if err != nil {
		t.Fatalf("staging Rollback: %s %v", output, err)
	}
	rolledBack, _ := os.ReadFile(installed)
	if !bytes.Equal(old, rolledBack) {
		t.Fatal("rollback did not restore exact previous bytes")
	}
	// A new higher-priority file is a different destination. A historical receipt
	// must never authorize overwriting it with an unrelated previous executable.
	dist := filepath.Join(root, "dist", "ReverseResearch-MCP.exe")
	copyArtifactFixture(t, dist, true)
	output, err = invoke("Rollback")
	if err == nil || !strings.Contains(string(output), "selection changed") {
		t.Fatalf("rollback accepted artifact drift: %s %v", output, err)
	}
}

func assertConcurrentReleaseRefused(t *testing.T, root string, invoke func() ([]byte, error)) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ready := filepath.Join(root, ".tmp", "promotion", "lock-ready")
	lock := filepath.Join(root, ".tmp", "promotion", ".promotion.lock")
	command := "$f=[System.IO.File]::Open($env:RR_TEST_LOCK,[System.IO.FileMode]::OpenOrCreate,[System.IO.FileAccess]::ReadWrite,[System.IO.FileShare]::ReadWrite); try { $f.Lock(0,1); [System.IO.File]::WriteAllText($env:RR_TEST_READY,'ready'); [Console]::ReadLine() | Out-Null } finally { $f.Unlock(0,1); $f.Dispose() }"
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-Command", command)
	cmd.Env = append(os.Environ(), "RR_TEST_LOCK="+lock, "RR_TEST_READY="+ready)
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = in.Close()
		if err := cmd.Wait(); err != nil {
			t.Errorf("release lock fixture: %s %v", output.Bytes(), err)
		}
	}()
	deadline := time.Now().Add(8 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("release lock fixture did not become ready")
		}
		time.Sleep(25 * time.Millisecond)
	}
	result, err := invoke()
	if err == nil || !strings.Contains(string(result), "another release owns") {
		t.Fatalf("concurrent release accepted: %s %v", result, err)
	}
}

func TestActualLauncherUsesSharedInstalledSelection(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows launcher")
	}
	sourceRoot, _ := filepath.Abs(filepath.Join("..", ".."))
	root := t.TempDir()
	for _, relative := range []string{"一键启动MCP.bat", filepath.Join("tools", "ops", "runtime-artifact.psm1")} {
		body, err := os.ReadFile(filepath.Join(sourceRoot, relative))
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, relative)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	installed := filepath.Join(root, "ReverseResearch-MCP.exe")
	copyArtifactFixture(t, installed, false)
	copyArtifactFixture(t, filepath.Join(root, "dist", "candidate", "ReverseResearch-MCP.exe"), true)
	cmd := exec.Command("cmd.exe", "/d", "/c", filepath.Join(root, "一键启动MCP.bat"), "--probe")
	cmd.Stdin = strings.NewReader("\r\n")
	output, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(output), installed) || !strings.Contains(string(output), "fixture launcher probe") {
		t.Fatalf("launcher=%s err=%v", output, err)
	}
	if strings.Contains(string(output), "dist\\candidate") {
		t.Fatal("launcher selected a candidate")
	}
}
