//go:build windows

package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/sys/windows"

	"reverseresearch/internal/modules"
	"reverseresearch/internal/processcontrol"
)

const (
	initialValue = uint32(0x11223344)
	writtenValue = uint32(0xA1B2C3D4)
	x32Port      = 19095
)

type fixtureHello struct {
	PID     int    `json:"pid"`
	Address string `json:"address"`
	Value   uint32 `json:"value"`
}

type report struct {
	CheckedUTC             string                  `json:"checked_utc"`
	Validation             string                  `json:"validation"`
	RuntimeVerified        bool                    `json:"runtime_verified"`
	Port                   int                     `json:"port"`
	PreflightPortFree      bool                    `json:"preflight_port_free"`
	PreflightNoDebugger    bool                    `json:"preflight_no_debugger_process"`
	FixturePath            string                  `json:"fixture_path"`
	FixturePID             uint32                  `json:"fixture_pid"`
	FixtureAddress         string                  `json:"fixture_address"`
	FixtureIdentity        processcontrol.Identity `json:"fixture_identity"`
	LeaseID                string                  `json:"lease_id"`
	AttachOperationID      string                  `json:"attach_operation_id"`
	PauseOperationID       string                  `json:"pause_operation_id"`
	WriteOperationID       string                  `json:"write_operation_id"`
	StopOperationID        string                  `json:"stop_operation_id"`
	InitialValue           string                  `json:"initial_value"`
	AfterGuardedWrite      string                  `json:"after_guarded_write"`
	AfterExternalReset     string                  `json:"after_external_reset"`
	AfterCompletedReplay   string                  `json:"after_completed_replay"`
	ReplayResultDigestSame bool                    `json:"replay_result_digest_same"`
	ConflictingReuseReject bool                    `json:"conflicting_reuse_rejected"`
	SessionBindingRemoved  bool                    `json:"session_binding_removed"`
	PortReleased           bool                    `json:"port_released"`
}

func main() {
	var root string
	flag.StringVar(&root, "root", ".", "ReverseResearch repository root")
	flag.Parse()

	absoluteRoot, err := filepath.Abs(root)
	die(err)
	if err := requirePortFree(x32Port); err != nil {
		die(err)
	}
	if names, err := debuggerProcesses(); err != nil {
		die(err)
	} else if len(names) != 0 {
		die(fmt.Errorf("existing debugger/headless process detected: %s", strings.Join(names, ", ")))
	}

	sandbox, err := os.MkdirTemp("", "rr-x32-effect-")
	die(err)
	runtimeLink := filepath.Join(sandbox, "runtime", "x32dbg")
	die(os.MkdirAll(filepath.Dir(runtimeLink), 0o755))
	targetRuntime := filepath.Join(absoluteRoot, "runtime", "x32dbg")
	die(createJunction(runtimeLink, targetRuntime))
	defer func() {
		cleanupWarn("remove runtime junction", os.Remove(runtimeLink))
		cleanupWarn("remove smoke sandbox", os.RemoveAll(sandbox))
	}()

	fixturePath := filepath.Join(sandbox, "x32-effect-fixture.exe")
	die(buildFixture(absoluteRoot, fixturePath))

	cmd := exec.Command(fixturePath)
	stdout, err := cmd.StdoutPipe()
	die(err)
	cmd.Stderr = os.Stderr
	die(cmd.Start())
	waitDone := make(chan error, 1)
	go func() { waitDone <- cmd.Wait() }()
	defer func() {
		if cmd.Process != nil {
			if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				cleanupWarn("kill smoke fixture", err)
			}
		}
		select {
		case err := <-waitDone:
			if err != nil {
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) {
					cleanupWarn("wait smoke fixture", err)
				}
			}
		case <-time.After(2 * time.Second):
			cleanupWarn("wait smoke fixture", errors.New("fixture did not exit within cleanup timeout"))
		}
	}()

	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() {
		die(fmt.Errorf("fixture did not publish identity: %s", scanner.Err()))
	}
	var hello fixtureHello
	die(json.Unmarshal(scanner.Bytes(), &hello))
	if hello.PID <= 0 || hello.Value != initialValue {
		die(fmt.Errorf("unexpected fixture hello: %+v", hello))
	}
	address64, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimPrefix(hello.Address, "0x"), "0X"), 16, 64)
	die(err)
	if address64 == 0 || address64 > 0xffffffff {
		die(fmt.Errorf("fixture address is not 32-bit: 0x%X", address64))
	}
	pid := uint32(hello.PID)

	identity, err := processcontrol.Inspect(pid)
	die(err)
	if identity.Image.PE == nil || identity.Image.PE.Bits != 32 {
		die(fmt.Errorf("fixture is not a 32-bit PE: %+v", identity.Image.PE))
	}
	store, err := processcontrol.NewLeaseStore(filepath.Join(sandbox, "state", "process-control"))
	die(err)
	const owner = "f04-x32-effect-smoke"
	lease, err := store.Acquire(processcontrol.AcquireRequest{Expected: identity, Owner: owner})
	die(err)
	defer func() {
		cleanupWarn("release process lease", store.Release(processcontrol.ReleaseRequest{
			PID: pid, ProcessKey: identity.Key, Owner: owner, LeaseID: lease.LeaseID,
		}))
	}()

	handle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_OPERATION,
		false,
		pid,
	)
	die(err)
	defer func() { cleanupWarn("close process handle", windows.CloseHandle(handle)) }()
	address := uintptr(address64)

	before, err := readUint32(handle, address)
	die(err)
	if before != initialValue {
		die(fmt.Errorf("fixture memory before attach=0x%08X want=0x%08X", before, initialValue))
	}

	runtime := modules.New(sandbox)
	runtimeClosed := false
	defer func() {
		if !runtimeClosed {
			cleanupWarn("close x32 runtime", runtime.Close())
		}
	}()

	baseOp := fmt.Sprintf("f04-x32-effect-%d-%d", pid, time.Now().UTC().UnixNano())
	attachOp := baseOp + ".attach"
	pauseOp := baseOp + ".pause"
	writeOp := baseOp + ".write"
	stopOp := baseOp + ".stop"

	ctx, cancel := context.WithTimeout(context.Background(), 55*time.Second)
	defer cancel()
	attachArgs := guarded(pid, identity.Key, owner, lease.LeaseID, attachOp, map[string]any{"pid": pid})
	_ = callOK(ctx, runtime, "AttachProcess", attachArgs)
	pauseArgs := guarded(pid, identity.Key, owner, lease.LeaseID, pauseOp, map[string]any{})
	_ = callOK(ctx, runtime, "PauseDebug", pauseArgs)
	_ = callOK(ctx, runtime, "WaitForPause", map[string]any{"timeoutMs": 15000})

	writeArgs := guarded(pid, identity.Key, owner, lease.LeaseID, writeOp, map[string]any{
		"address":    strings.ToUpper(hello.Address),
		"byteString": "D4 C3 B2 A1",
	})
	firstWrite := callOK(ctx, runtime, "WriteMemToAddress", writeArgs)
	afterWrite, err := readUint32(handle, address)
	die(err)
	if afterWrite != writtenValue {
		die(fmt.Errorf("guarded write effect=0x%08X want=0x%08X", afterWrite, writtenValue))
	}

	die(writeUint32(handle, address, initialValue))
	afterReset, err := readUint32(handle, address)
	die(err)
	if afterReset != initialValue {
		die(fmt.Errorf("external reset=0x%08X want=0x%08X", afterReset, initialValue))
	}

	replayed := callOK(ctx, runtime, "WriteMemToAddress", writeArgs)
	afterReplay, err := readUint32(handle, address)
	die(err)
	if afterReplay != initialValue {
		die(fmt.Errorf("completed operation replay re-executed the write: got 0x%08X", afterReplay))
	}
	firstDigest := resultDigest(firstWrite)
	replayDigest := resultDigest(replayed)
	if firstDigest != replayDigest {
		die(fmt.Errorf("completed replay result changed: first=%s replay=%s", firstDigest, replayDigest))
	}

	conflictArgs := guarded(pid, identity.Key, owner, lease.LeaseID, writeOp, map[string]any{
		"address":    strings.ToUpper(hello.Address),
		"byteString": "EF BE AD DE",
	})
	_, conflictErr := runtime.Call(ctx, "x32dbg", "WriteMemToAddress", conflictArgs)
	if conflictErr == nil || !strings.Contains(conflictErr.Error(), "already used for a different guarded request") {
		die(fmt.Errorf("conflicting operation_id reuse was not rejected: %v", conflictErr))
	}
	afterConflict, err := readUint32(handle, address)
	die(err)
	if afterConflict != initialValue {
		die(fmt.Errorf("conflicting operation_id reuse changed memory: 0x%08X", afterConflict))
	}

	stopArgs := guarded(pid, identity.Key, owner, lease.LeaseID, stopOp, map[string]any{})
	_ = callOK(ctx, runtime, "StopDebug", stopArgs)
	die(runtime.Close())
	runtimeClosed = true

	die(store.Release(processcontrol.ReleaseRequest{
		PID: pid, ProcessKey: identity.Key, Owner: owner, LeaseID: lease.LeaseID,
	}))
	bindingPath := filepath.Join(sandbox, "state", "x32dbg-guard", "session.json")
	_, bindingErr := os.Stat(bindingPath)
	bindingRemoved := errors.Is(bindingErr, os.ErrNotExist)
	if !bindingRemoved {
		die(fmt.Errorf("x32dbg session binding still exists: %v", bindingErr))
	}
	portReleased := waitPortFree(x32Port, 5*time.Second)
	if !portReleased {
		die(fmt.Errorf("x32dbg MCP port %d remained in use after cleanup", x32Port))
	}

	out := report{
		CheckedUTC:             time.Now().UTC().Format(time.RFC3339Nano),
		Validation:             "isolated-real-x32-effect",
		RuntimeVerified:        true,
		Port:                   x32Port,
		PreflightPortFree:      true,
		PreflightNoDebugger:    true,
		FixturePath:            fixturePath,
		FixturePID:             pid,
		FixtureAddress:         "0x" + strings.ToUpper(hello.Address),
		FixtureIdentity:        identity,
		LeaseID:                lease.LeaseID,
		AttachOperationID:      attachOp,
		PauseOperationID:       pauseOp,
		WriteOperationID:       writeOp,
		StopOperationID:        stopOp,
		InitialValue:           fmt.Sprintf("0x%08X", before),
		AfterGuardedWrite:      fmt.Sprintf("0x%08X", afterWrite),
		AfterExternalReset:     fmt.Sprintf("0x%08X", afterReset),
		AfterCompletedReplay:   fmt.Sprintf("0x%08X", afterReplay),
		ReplayResultDigestSame: firstDigest == replayDigest,
		ConflictingReuseReject: conflictErr != nil,
		SessionBindingRemoved:  bindingRemoved,
		PortReleased:           portReleased,
	}
	body, err := json.MarshalIndent(out, "", "  ")
	die(err)
	fmt.Println(string(body))
}

func buildFixture(root, output string) error {
	cmd := exec.Command("go.exe", "build", "-trimpath", "-o", output, "./tools/fixtures/x32-effect")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH=386", "CGO_ENABLED=0")
	body, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("build 32-bit effect fixture: %w: %s", err, strings.TrimSpace(string(body)))
	}
	return nil
}

func createJunction(link, target string) error {
	cmd := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", link, target)
	body, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("create x32dbg runtime junction: %w: %s", err, strings.TrimSpace(string(body)))
	}
	return nil
}

func debuggerProcesses() ([]string, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer func() { cleanupWarn("close process snapshot", windows.CloseHandle(snapshot)) }()
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snapshot, &entry); err != nil {
		return nil, err
	}
	blocked := map[string]bool{"x32dbg.exe": true, "x64dbg.exe": true, "headless.exe": true}
	var found []string
	for {
		name := strings.ToLower(windows.UTF16ToString(entry.ExeFile[:]))
		if blocked[name] {
			found = append(found, fmt.Sprintf("%s(pid=%d)", name, entry.ProcessID))
		}
		entry.Size = uint32(unsafe.Sizeof(entry))
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
				break
			}
			return nil, err
		}
	}
	return found, nil
}

func guarded(pid uint32, processKey, owner, leaseID, operationID string, values map[string]any) map[string]any {
	result := make(map[string]any, len(values)+1)
	for key, value := range values {
		result[key] = value
	}
	result[modules.X32GuardArgument] = map[string]any{
		"pid": pid, "process_key": processKey, "owner": owner,
		"lease_id": leaseID, "operation_id": operationID,
	}
	return result
}

func callOK(ctx context.Context, runtime *modules.Runtime, tool string, args map[string]any) *mcp.CallToolResult {
	result, err := runtime.Call(ctx, "x32dbg", tool, args)
	die(err)
	if result == nil {
		die(fmt.Errorf("%s returned no result", tool))
	}
	if result.IsError {
		body, _ := json.Marshal(result.Content)
		die(fmt.Errorf("%s returned MCP error: %s", tool, body))
	}
	return result
}

func resultDigest(result *mcp.CallToolResult) string {
	payload := struct {
		Structured any      `json:"structured,omitempty"`
		Text       []string `json:"text,omitempty"`
	}{Structured: result.StructuredContent}
	for _, item := range result.Content {
		if text, ok := item.(*mcp.TextContent); ok {
			payload.Text = append(payload.Text, text.Text)
		}
	}
	body, err := json.Marshal(payload)
	die(err)
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func readUint32(handle windows.Handle, address uintptr) (uint32, error) {
	var body [4]byte
	var read uintptr
	if err := windows.ReadProcessMemory(handle, address, &body[0], uintptr(len(body)), &read); err != nil {
		return 0, err
	}
	if read != uintptr(len(body)) {
		return 0, fmt.Errorf("short ReadProcessMemory: got %d want %d", read, len(body))
	}
	return binary.LittleEndian.Uint32(body[:]), nil
}

func writeUint32(handle windows.Handle, address uintptr, value uint32) error {
	var body [4]byte
	binary.LittleEndian.PutUint32(body[:], value)
	var written uintptr
	if err := windows.WriteProcessMemory(handle, address, &body[0], uintptr(len(body)), &written); err != nil {
		return err
	}
	if written != uintptr(len(body)) {
		return fmt.Errorf("short WriteProcessMemory: got %d want %d", written, len(body))
	}
	return nil
}

func requirePortFree(port int) error {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 250*time.Millisecond)
	if err == nil {
		cleanupWarn("close port probe", conn.Close())
		return fmt.Errorf("x32dbg MCP port %d is already in use", port)
	}
	return nil
}

func waitPortFree(port int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if requirePortFree(port) == nil {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return requirePortFree(port) == nil
}

func cleanupWarn(action string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "cleanup warning: %s: %v\n", action, err)
	}
}

func die(err error) {
	if err != nil {
		panic(err)
	}
}
