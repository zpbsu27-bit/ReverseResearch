package androidinspect

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"reverseresearch/internal/recordio"
	"reverseresearch/internal/toolindex"
)

const (
	DefaultTimeout = 8 * time.Second
	MaxTimeout     = 30 * time.Second
	maxOutputBytes = 16 << 20
)

var operationIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$`)

type ToolStatus struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
	Path      string `json:"path,omitempty"`
	Source    string `json:"source"`
}

type RuntimeStatus struct {
	ADB   ToolStatus `json:"adb"`
	Frida ToolStatus `json:"frida"`
}

func Status(index toolindex.Index) RuntimeStatus {
	return RuntimeStatus{ADB: status(index, "adb"), Frida: status(index, "frida")}
}

func status(index toolindex.Index, name string) ToolStatus {
	tool, _ := index.ByName(name)
	return ToolStatus{Name: name, Available: tool.Available, Path: tool.Path, Source: tool.Source}
}

type Device struct {
	Serial     string            `json:"serial"`
	State      string            `json:"state"`
	Authorized bool              `json:"authorized"`
	Details    map[string]string `json:"details,omitempty"`
}

type DeviceProbe struct {
	SerialSHA256 string `json:"serial_sha256"`
	State        string `json:"state"`
	Manufacturer string `json:"manufacturer,omitempty"`
	Model        string `json:"model,omitempty"`
	Android      string `json:"android,omitempty"`
	SDK          string `json:"sdk,omitempty"`
	ABI          string `json:"abi,omitempty"`
	ShellUID     string `json:"shell_uid,omitempty"`
	RootShell    bool   `json:"root_shell"`
}

type Workspace struct {
	DeviceSHA256                string `json:"device_sha256"`
	Path                        string `json:"path"`
	EvidencePath                string `json:"evidence_path"`
	CertPath                    string `json:"certificate_path"`
	OperationPath               string `json:"operation_path"`
	DeviceAuthorizationRequired bool   `json:"device_authorization_required"`
}

type Snapshot struct {
	ID               string `json:"id"`
	DeviceSHA256     string `json:"device_sha256"`
	UIPath           string `json:"ui_path"`
	UISHA256         string `json:"ui_sha256"`
	ScreenshotPath   string `json:"screenshot_path"`
	ScreenshotSHA256 string `json:"screenshot_sha256"`
	CapturedUTC      string `json:"captured_utc"`
}

type Selector struct {
	ResourceID  string `json:"resource_id,omitempty"`
	Text        string `json:"text,omitempty"`
	ContentDesc string `json:"content_desc,omitempty"`
}

type TapRequest struct {
	Serial           string   `json:"serial"`
	SnapshotID       string   `json:"snapshot_id"`
	ExpectedUISHA256 string   `json:"expected_ui_sha256"`
	Selector         Selector `json:"selector"`
	OperationID      string   `json:"operation_id"`
}

type TapReceipt struct {
	OperationID  string `json:"operation_id"`
	DeviceSHA256 string `json:"device_sha256"`
	SnapshotID   string `json:"snapshot_id"`
	UISHA256     string `json:"ui_sha256"`
	SelectorKind string `json:"selector_kind"`
	SelectorHash string `json:"selector_hash,omitempty"`
	X            int    `json:"x"`
	Y            int    `json:"y"`
	State        string `json:"state"`
	CreatedUTC   string `json:"created_utc"`
	AppliedUTC   string `json:"applied_utc,omitempty"`
	Error        string `json:"error,omitempty"`
}

type runResult struct {
	Stdout []byte
	Stderr []byte
	Err    error
}

type runner func(context.Context, string, []string) runResult

type Manager struct {
	root    string
	adbPath string
	run     runner
	now     func() time.Time
}

func New(root, adbPath string) (*Manager, error) {
	if strings.TrimSpace(adbPath) == "" {
		return nil, errors.New("adb executable path is required")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	return &Manager{root: absolute, adbPath: filepath.Clean(adbPath), run: runCommand, now: time.Now}, nil
}

func newManager(root, adbPath string, run runner, now func() time.Time) *Manager {
	return &Manager{root: root, adbPath: adbPath, run: run, now: now}
}

func (m *Manager) Devices(ctx context.Context) ([]Device, error) {
	result := m.runWithTimeout(ctx, []string{"devices", "-l"})
	if result.Err != nil {
		return nil, commandError("adb devices", result)
	}
	lines := strings.Split(strings.ReplaceAll(string(result.Stdout), "\r\n", "\n"), "\n")
	var out []Device
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "List of devices attached") || strings.HasPrefix(line, "* daemon") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		d := Device{Serial: fields[0], State: fields[1], Authorized: fields[1] == "device", Details: map[string]string{}}
		for _, field := range fields[2:] {
			if idx := strings.IndexByte(field, ':'); idx > 0 {
				d.Details[field[:idx]] = field[idx+1:]
			}
		}
		out = append(out, d)
	}
	return out, nil
}

func (m *Manager) requireAuthorized(ctx context.Context, serial string) (Device, error) {
	serial = strings.TrimSpace(serial)
	if serial == "" {
		return Device{}, errors.New("device serial is required")
	}
	devices, err := m.Devices(ctx)
	if err != nil {
		return Device{}, err
	}
	for _, device := range devices {
		if device.Serial == serial {
			if !device.Authorized {
				return Device{}, fmt.Errorf("device %q is not authorized: state=%s; authorize it on the device first", serial, device.State)
			}
			return device, nil
		}
	}
	return Device{}, fmt.Errorf("device %q is not connected", serial)
}

func (m *Manager) Probe(ctx context.Context, serial string) (DeviceProbe, error) {
	device, err := m.requireAuthorized(ctx, serial)
	if err != nil {
		return DeviceProbe{}, err
	}
	values := map[string]string{}
	for key, prop := range map[string]string{
		"manufacturer": "ro.product.manufacturer",
		"model":        "ro.product.model",
		"android":      "ro.build.version.release",
		"sdk":          "ro.build.version.sdk",
		"abi":          "ro.product.cpu.abi",
	} {
		result := m.runWithTimeout(ctx, []string{"-s", serial, "shell", "getprop", prop})
		if result.Err != nil {
			return DeviceProbe{}, commandError("adb getprop "+prop, result)
		}
		values[key] = strings.TrimSpace(string(result.Stdout))
	}
	idResult := m.runWithTimeout(ctx, []string{"-s", serial, "shell", "id"})
	if idResult.Err != nil {
		return DeviceProbe{}, commandError("adb shell id", idResult)
	}
	uid := strings.TrimSpace(string(idResult.Stdout))
	return DeviceProbe{
		SerialSHA256: hashString(serial), State: device.State,
		Manufacturer: values["manufacturer"], Model: values["model"], Android: values["android"],
		SDK: values["sdk"], ABI: values["abi"], ShellUID: uid, RootShell: strings.Contains(uid, "uid=0("),
	}, nil
}

func PrepareWorkspace(root, serial string) (Workspace, error) {
	serial = strings.TrimSpace(serial)
	if serial == "" {
		return Workspace{}, errors.New("device serial is required")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return Workspace{}, fmt.Errorf("resolve project root: %w", err)
	}
	deviceHash := hashString(serial)
	base := filepath.Join(absolute, "state", "android", deviceHash)
	evidence := filepath.Join(base, "evidence")
	certs := filepath.Join(base, "certificates")
	operations := filepath.Join(base, "operations")
	for _, path := range []string{evidence, certs, operations} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return Workspace{}, err
		}
	}
	return Workspace{
		DeviceSHA256: deviceHash, Path: base, EvidencePath: evidence, CertPath: certs,
		OperationPath: operations, DeviceAuthorizationRequired: true,
	}, nil
}

func (m *Manager) PrepareWorkspace(serial string) (Workspace, error) {
	return PrepareWorkspace(m.root, serial)
}

func (m *Manager) Snapshot(ctx context.Context, serial string) (Snapshot, error) {
	if _, err := m.requireAuthorized(ctx, serial); err != nil {
		return Snapshot{}, err
	}
	workspace, err := m.PrepareWorkspace(serial)
	if err != nil {
		return Snapshot{}, err
	}
	uiResult := m.runWithTimeout(ctx, []string{"-s", serial, "exec-out", "uiautomator", "dump", "/dev/tty"})
	if uiResult.Err != nil {
		return Snapshot{}, commandError("uiautomator dump", uiResult)
	}
	uiBody, err := extractHierarchy(uiResult.Stdout)
	if err != nil {
		return Snapshot{}, err
	}
	screenResult := m.runWithTimeout(ctx, []string{"-s", serial, "exec-out", "screencap", "-p"})
	if screenResult.Err != nil {
		return Snapshot{}, commandError("screencap", screenResult)
	}
	now := m.now().UTC()
	id := now.Format("20060102T150405.000000000Z")
	uiPath := filepath.Join(workspace.EvidencePath, id+".xml")
	pngPath := filepath.Join(workspace.EvidencePath, id+".png")
	if err := recordio.WriteFile(uiPath, uiBody, 0o600); err != nil {
		return Snapshot{}, err
	}
	if err := recordio.WriteFile(pngPath, screenResult.Stdout, 0o600); err != nil {
		return Snapshot{}, err
	}
	return Snapshot{
		ID: id, DeviceSHA256: workspace.DeviceSHA256, UIPath: uiPath, UISHA256: hashBytes(uiBody),
		ScreenshotPath: pngPath, ScreenshotSHA256: hashBytes(screenResult.Stdout), CapturedUTC: now.Format(time.RFC3339Nano),
	}, nil
}

func (m *Manager) Tap(ctx context.Context, request TapRequest) (TapReceipt, error) {
	if !operationIDPattern.MatchString(strings.TrimSpace(request.OperationID)) {
		return TapReceipt{}, errors.New("operation_id is required and contains unsupported characters")
	}
	workspace, err := m.PrepareWorkspace(request.Serial)
	if err != nil {
		return TapReceipt{}, err
	}
	receiptPath := filepath.Join(workspace.OperationPath, request.OperationID+".json")
	if body, err := os.ReadFile(receiptPath); err == nil {
		var receipt TapReceipt
		if json.Unmarshal(body, &receipt) == nil {
			if receipt.State == "applied" || receipt.State == "prepared" || receipt.State == "failed" {
				return receipt, nil
			}
		}
		return TapReceipt{}, errors.New("existing operation receipt is unreadable; refusing replay")
	} else if !errors.Is(err, os.ErrNotExist) {
		return TapReceipt{}, err
	}
	if _, err := m.requireAuthorized(ctx, request.Serial); err != nil {
		return TapReceipt{}, err
	}
	currentResult := m.runWithTimeout(ctx, []string{"-s", request.Serial, "exec-out", "uiautomator", "dump", "/dev/tty"})
	if currentResult.Err != nil {
		return TapReceipt{}, commandError("uiautomator currentness dump", currentResult)
	}
	uiBody, err := extractHierarchy(currentResult.Stdout)
	if err != nil {
		return TapReceipt{}, err
	}
	currentHash := hashBytes(uiBody)
	if !strings.EqualFold(strings.TrimSpace(request.ExpectedUISHA256), currentHash) {
		return TapReceipt{}, fmt.Errorf("UI currentness mismatch: got %s want %s", currentHash, strings.TrimSpace(request.ExpectedUISHA256))
	}
	x, y, kind, selectorHash, err := resolveSelector(uiBody, request.Selector)
	if err != nil {
		return TapReceipt{}, err
	}
	created := m.now().UTC()
	receipt := TapReceipt{
		OperationID: request.OperationID, DeviceSHA256: workspace.DeviceSHA256, SnapshotID: request.SnapshotID,
		UISHA256: currentHash, SelectorKind: kind, SelectorHash: selectorHash, X: x, Y: y,
		State: "prepared", CreatedUTC: created.Format(time.RFC3339Nano),
	}
	if err := writeReceiptExclusive(receiptPath, receipt); err != nil {
		return TapReceipt{}, err
	}
	result := m.runWithTimeout(ctx, []string{"-s", request.Serial, "shell", "input", "tap", strconv.Itoa(x), strconv.Itoa(y)})
	if result.Err != nil {
		receipt.State = "failed"
		receipt.Error = strings.TrimSpace(string(result.Stderr))
		_ = writeReceipt(receiptPath, receipt)
		return receipt, commandError("adb input tap", result)
	}
	receipt.State = "applied"
	receipt.AppliedUTC = m.now().UTC().Format(time.RFC3339Nano)
	if err := writeReceipt(receiptPath, receipt); err != nil {
		return TapReceipt{}, fmt.Errorf("tap may have applied but receipt finalization failed; do not replay operation %s: %w", request.OperationID, err)
	}
	return receipt, nil
}

type hierarchy struct {
	Nodes []node `xml:"node"`
}

type node struct {
	ResourceID  string `xml:"resource-id,attr"`
	Text        string `xml:"text,attr"`
	ContentDesc string `xml:"content-desc,attr"`
	Bounds      string `xml:"bounds,attr"`
	Nodes       []node `xml:"node"`
}

var boundsPattern = regexp.MustCompile(`^\[(\d+),(\d+)\]\[(\d+),(\d+)\]$`)

func resolveSelector(body []byte, selector Selector) (int, int, string, string, error) {
	type candidate struct {
		kind  string
		value string
	}
	var candidates []candidate
	if value := strings.TrimSpace(selector.ResourceID); value != "" {
		candidates = append(candidates, candidate{kind: "resource_id", value: value})
	}
	if value := strings.TrimSpace(selector.ContentDesc); value != "" {
		candidates = append(candidates, candidate{kind: "content_desc", value: value})
	}
	if value := strings.TrimSpace(selector.Text); value != "" {
		candidates = append(candidates, candidate{kind: "text", value: value})
	}
	if len(candidates) != 1 {
		return 0, 0, "", "", fmt.Errorf("exactly one selector field is required; got %d", len(candidates))
	}
	kind, value := candidates[0].kind, candidates[0].value
	var root hierarchy
	if err := xml.Unmarshal(body, &root); err != nil {
		return 0, 0, "", "", fmt.Errorf("decode UI hierarchy: %w", err)
	}
	var matches []node
	var walk func([]node)
	walk = func(nodes []node) {
		for _, n := range nodes {
			var candidate string
			switch kind {
			case "resource_id":
				candidate = n.ResourceID
			case "content_desc":
				candidate = n.ContentDesc
			case "text":
				candidate = n.Text
			}
			if candidate == value {
				matches = append(matches, n)
			}
			walk(n.Nodes)
		}
	}
	walk(root.Nodes)
	if len(matches) != 1 {
		return 0, 0, "", "", fmt.Errorf("selector matched %d nodes; exactly one is required", len(matches))
	}
	parts := boundsPattern.FindStringSubmatch(matches[0].Bounds)
	if len(parts) != 5 {
		return 0, 0, "", "", fmt.Errorf("invalid node bounds %q", matches[0].Bounds)
	}
	x1, _ := strconv.Atoi(parts[1])
	y1, _ := strconv.Atoi(parts[2])
	x2, _ := strconv.Atoi(parts[3])
	y2, _ := strconv.Atoi(parts[4])
	if x2 <= x1 || y2 <= y1 {
		return 0, 0, "", "", errors.New("selector node has empty bounds")
	}
	return (x1 + x2) / 2, (y1 + y2) / 2, kind, hashString(value), nil
}

func extractHierarchy(body []byte) ([]byte, error) {
	idx := bytes.Index(body, []byte("<hierarchy"))
	if idx < 0 {
		return nil, errors.New("uiautomator output did not contain a hierarchy")
	}
	value := bytes.TrimSpace(body[idx:])
	var parsed hierarchy
	if err := xml.Unmarshal(value, &parsed); err != nil {
		return nil, fmt.Errorf("decode uiautomator hierarchy: %w", err)
	}
	return value, nil
}

func writeReceiptExclusive(path string, receipt TapReceipt) error {
	body, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return errors.New("operation receipt already exists; refusing replay")
		}
		return err
	}
	defer file.Close()
	_, err = file.Write(body)
	return err
}

func writeReceipt(path string, receipt TapReceipt) error {
	body, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	return recordio.WriteFile(path, body, 0o600)
}

func (m *Manager) runWithTimeout(parent context.Context, args []string) runResult {
	ctx, cancel := context.WithTimeout(parent, DefaultTimeout)
	defer cancel()
	return m.run(ctx, m.adbPath, args)
}

func runCommand(ctx context.Context, executable string, args []string) runResult {
	cmd := exec.CommandContext(ctx, executable, args...)
	var stdout, stderr limitedBuffer
	stdout.limit = maxOutputBytes
	stderr.limit = 64 << 10
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if stdout.truncated || stderr.truncated {
		return runResult{Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), Err: errors.New("adb output limit exceeded")}
	}
	return runResult{Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), Err: err}
}

func commandError(phase string, result runResult) error {
	detail := strings.TrimSpace(string(result.Stderr))
	if detail == "" && result.Err != nil {
		detail = result.Err.Error()
	}
	return fmt.Errorf("%s failed: %s", phase, detail)
}

type limitedBuffer struct {
	bytes.Buffer
	limit     int
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	original := len(p)
	remaining := b.limit - b.Len()
	if remaining > 0 {
		if remaining > len(p) {
			remaining = len(p)
		}
		_, _ = b.Buffer.Write(p[:remaining])
	}
	if original > remaining {
		b.truncated = true
	}
	return original, nil
}

func hashString(value string) string {
	return hashBytes([]byte(value))
}

func hashBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
