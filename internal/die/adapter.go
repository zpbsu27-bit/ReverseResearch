package die

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"reverseresearch/internal/targetidentity"
	"reverseresearch/internal/toolprocess"
)

const (
	PinnedVersion          = "3.21"
	PinnedLicense          = "MIT"
	PinnedArchiveSHA256    = "078f2934f267392247f9c7b759a1c2457a48bc2000b25b80c2f129955ee4a3b9"
	PinnedExecutableSHA256 = "dda171a904f6dc3a2c414e99e9d718c8d7500bc26c3dcdc1a72ec0e7d718cfe7"
	DefaultTimeout         = 15 * time.Second
	MaxTimeout             = 2 * time.Minute
	maxOutputBytes         = 8 << 20
	maxStderrBytes         = 64 << 10
)

var (
	ErrUnavailable     = errors.New("detect it easy runtime is unavailable")
	ErrVersionMismatch = errors.New("detect it easy version mismatch")
	ErrRuntimeMismatch = errors.New("detect it easy runtime identity mismatch")
	ErrTimeout         = errors.New("detect it easy scan timed out")
	ErrOutputLimit     = errors.New("detect it easy output exceeded limit")
)

type ScanOptions struct {
	Timeout   time.Duration `json:"-"`
	Verbose   bool          `json:"verbose,omitempty"`
	Deep      bool          `json:"deep,omitempty"`
	Heuristic bool          `json:"heuristic,omitempty"`
	AllTypes  bool          `json:"all_types,omitempty"`
	Entropy   bool          `json:"entropy,omitempty"`
	Info      bool          `json:"info,omitempty"`
}

type ToolIdentity struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	License       string `json:"license"`
	Executable    string `json:"executable"`
	SHA256        string `json:"sha256"`
	ArchiveSHA256 string `json:"archive_sha256"`
}

type Value struct {
	Info    string `json:"info"`
	Name    string `json:"name"`
	String  string `json:"string"`
	Type    string `json:"type"`
	Version string `json:"version"`
}

type Detection struct {
	FileType       string  `json:"filetype"`
	Info           string  `json:"info"`
	Offset         string  `json:"offset"`
	ParentFilePart string  `json:"parentfilepart"`
	Size           string  `json:"size"`
	Values         []Value `json:"values"`
}

type Report struct {
	Tool       ToolIdentity            `json:"tool"`
	Target     targetidentity.Identity `json:"target"`
	Detects    []Detection             `json:"detects"`
	Options    ScanOptions             `json:"options"`
	DurationMS int64                   `json:"duration_ms"`
}

type Adapter struct {
	executable   string
	version      string
	expectedHash string
	run          runFunc
}

type runFunc func(context.Context, string, []string) runResult

type runResult = toolprocess.Result

func New(root string) *Adapter {
	absolute, err := filepath.Abs(root)
	if err != nil {
		absolute = filepath.Clean(root)
	}
	executable := filepath.Join(absolute, "runtime", "die", "diec.exe")
	if found, ok := findRuntimeExecutable(absolute); ok {
		executable = found
	}
	return newAdapter(
		executable,
		PinnedVersion,
		PinnedExecutableSHA256,
		runCommand,
	)
}

func findRuntimeExecutable(start string) (string, bool) {
	for dir := filepath.Clean(start); ; dir = filepath.Dir(dir) {
		candidate := filepath.Join(dir, "runtime", "die", "diec.exe")
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			return candidate, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
	}
}

func newAdapter(executable, version, expectedHash string, run runFunc) *Adapter {
	return &Adapter{
		executable:   filepath.Clean(executable),
		version:      strings.TrimSpace(version),
		expectedHash: strings.ToLower(strings.TrimSpace(expectedHash)),
		run:          run,
	}
}

func (a *Adapter) Scan(parent context.Context, path string, options ScanOptions) (Report, error) {
	if a == nil || a.run == nil {
		return Report{}, errors.New("detect it easy adapter is not initialized")
	}
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if timeout > MaxTimeout {
		return Report{}, fmt.Errorf("detect it easy timeout %s exceeds maximum %s", timeout, MaxTimeout)
	}
	options.Timeout = 0

	before, err := targetidentity.InspectContext(parent, path)
	if err != nil {
		return Report{}, err
	}
	tool, err := a.validateRuntime()
	if err != nil {
		return Report{}, err
	}

	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	started := time.Now()

	versionResult := a.run(ctx, a.executable, []string{"-v"})
	if err := commandError(ctx, "version probe", versionResult); err != nil {
		return Report{}, err
	}
	gotVersion := strings.TrimSpace(string(versionResult.Stdout))
	wantVersion := "die " + a.version
	if gotVersion != wantVersion {
		return Report{}, fmt.Errorf("%w: got %q want %q", ErrVersionMismatch, gotVersion, wantVersion)
	}

	args := []string{"-j"}
	if options.Verbose {
		args = append(args, "-b")
	}
	if options.Deep {
		args = append(args, "-d")
	}
	if options.Heuristic {
		args = append(args, "-u")
	}
	if options.AllTypes {
		args = append(args, "-a")
	}
	if options.Entropy {
		args = append(args, "-e")
	}
	if options.Info {
		args = append(args, "-i")
	}
	args = append(args, before.Path)

	result := a.run(ctx, a.executable, args)
	if err := commandError(ctx, "scan", result); err != nil {
		return Report{}, err
	}
	var payload struct {
		Detects []Detection `json:"detects"`
	}
	body := bytes.TrimSpace(result.Stdout)
	if len(body) == 0 {
		return Report{}, errors.New("detect it easy returned empty JSON output")
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return Report{}, fmt.Errorf("decode detect it easy JSON: %w", err)
	}

	after, err := targetidentity.InspectContext(parent, before.Path)
	if err != nil {
		return Report{}, fmt.Errorf("reinspect target after DiE scan: %w", err)
	}
	if before.SHA256 != after.SHA256 || before.Size != after.Size || !samePath(before.Path, after.Path) {
		return Report{}, errors.New("target changed during DiE scan")
	}

	return Report{
		Tool:       tool,
		Target:     before,
		Detects:    payload.Detects,
		Options:    options,
		DurationMS: time.Since(started).Milliseconds(),
	}, nil
}

func (a *Adapter) validateRuntime() (ToolIdentity, error) {
	info, err := os.Stat(a.executable)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ToolIdentity{}, fmt.Errorf("%w: %s", ErrUnavailable, a.executable)
		}
		return ToolIdentity{}, fmt.Errorf("stat detect it easy runtime: %w", err)
	}
	if !info.Mode().IsRegular() {
		return ToolIdentity{}, fmt.Errorf("%w: runtime is not a regular file", ErrUnavailable)
	}
	identity, err := targetidentity.Inspect(a.executable)
	if err != nil {
		return ToolIdentity{}, fmt.Errorf("inspect detect it easy runtime: %w", err)
	}
	if a.expectedHash != "" && !strings.EqualFold(identity.SHA256, a.expectedHash) {
		return ToolIdentity{}, fmt.Errorf("%w: sha256=%s want=%s", ErrRuntimeMismatch, identity.SHA256, a.expectedHash)
	}
	return ToolIdentity{
		Name:          "Detect It Easy",
		Version:       a.version,
		License:       PinnedLicense,
		Executable:    identity.Path,
		SHA256:        strings.ToLower(identity.SHA256),
		ArchiveSHA256: PinnedArchiveSHA256,
	}, nil
}

func commandError(ctx context.Context, phase string, result runResult) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(result.Err, context.DeadlineExceeded) {
		return fmt.Errorf("%w during %s", ErrTimeout, phase)
	}
	if result.Truncated {
		return fmt.Errorf("%w during %s", ErrOutputLimit, phase)
	}
	if result.ExitCode != 0 {
		detail := strings.TrimSpace(string(result.Stderr))
		if detail == "" && result.Err != nil {
			detail = result.Err.Error()
		}
		return fmt.Errorf("detect it easy %s failed with exit code %d: %s", phase, result.ExitCode, detail)
	}
	if result.Err != nil {
		return fmt.Errorf("detect it easy %s failed: %w", phase, result.Err)
	}
	return nil
}

func runCommand(ctx context.Context, executable string, args []string) runResult {
	return toolprocess.Run(ctx, executable, args, maxOutputBytes, maxStderrBytes, "")
}

func samePath(left, right string) bool {
	return strings.EqualFold(filepath.Clean(left), filepath.Clean(right))
}
