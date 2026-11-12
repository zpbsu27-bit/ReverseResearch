package webinspect

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"reverseresearch/internal/securefile"
	"reverseresearch/internal/targetidentity"
	"reverseresearch/internal/toolindex"
	"reverseresearch/internal/toolprocess"
)

const WABTVersion = "1.0.42"
const maxWABTInput = 8 << 20
const maxWABTOutput = 16 << 20
const maxWABTDiagnostic = 64 << 10

type WASMOptions struct {
	UseWABT              bool   `json:"use_wabt,omitempty"`
	View                 string `json:"view,omitempty"`
	Offset               int    `json:"offset,omitempty"`
	Limit                int    `json:"limit,omitempty"`
	ExpectedSHA256       string `json:"expected_sha256,omitempty"`
	ExpectedOutputSHA256 string `json:"expected_output_sha256,omitempty"`
}

type WABTTool struct {
	Name          string `json:"name"`
	Path          string `json:"path"`
	SHA256        string `json:"sha256"`
	VersionBanner string `json:"version_banner"`
}

type WABTCommand struct {
	Tool        string   `json:"tool"`
	Arguments   []string `json:"arguments"`
	ExitCode    int      `json:"exit_code"`
	Diagnostics string   `json:"diagnostics,omitempty"`
}

type WABTReport struct {
	Status                   string        `json:"status"`
	Validated                bool          `json:"validated"`
	TargetExecutionPerformed bool          `json:"target_execution_performed"`
	Profile                  string        `json:"profile"`
	FeaturePolicy            string        `json:"feature_policy"`
	CanonicalSource          string        `json:"canonical_source"`
	SourceCommit             string        `json:"source_commit"`
	License                  string        `json:"license"`
	Tools                    []WABTTool    `json:"tools"`
	Commands                 []WABTCommand `json:"commands"`
	View                     string        `json:"view"`
	OutputSHA256             string        `json:"output_sha256,omitempty"`
	TotalOutputBytes         int           `json:"total_output_bytes"`
	Offset                   int           `json:"offset"`
	NextOffset               int           `json:"next_offset"`
	Output                   string        `json:"output"`
	OutputComplete           bool          `json:"output_complete"`
	TemporaryCopyDisposed    bool          `json:"temporary_copy_disposed"`
	Limits                   []string      `json:"limits"`
}

type wabtRunFunc func(context.Context, string, []string, string) toolprocess.Result

func InspectWASMWithOptions(ctx context.Context, root, path string, options WASMOptions) (WASMReport, error) {
	if !options.UseWABT {
		if options.View != "" || options.Offset != 0 || options.Limit != 0 || options.ExpectedOutputSHA256 != "" {
			return WASMReport{}, errors.New("WASM output options require use_wabt")
		}
		report, err := InspectWASM(path)
		if err == nil {
			err = checkWABTDigest(options.ExpectedSHA256, report.SHA256, "WASM input")
		}
		return report, err
	}
	tools, err := toolindex.DiscoverWABT(root)
	if err != nil {
		return WASMReport{}, err
	}
	return inspectWABT(ctx, path, options, tools, func(ctx context.Context, executable string, args []string, dir string) toolprocess.Result {
		return toolprocess.Run(ctx, executable, args, maxWABTOutput, maxWABTDiagnostic, dir)
	}, disposeWABTWorkspace)
}

func inspectWABT(ctx context.Context, path string, o WASMOptions, tools []toolindex.Tool, run wabtRunFunc, cleanup func(string) error) (report WASMReport, err error) {
	if o.View == "" {
		o.View = "validation"
	}
	if o.View != "validation" && o.View != "wat" && o.View != "details" {
		return report, errors.New("WASM WABT view must be validation, wat or details")
	}
	if o.Offset < 0 || o.Offset > maxWABTOutput || o.Limit < 0 || o.Limit > 32768 {
		return report, errors.New("WASM WABT output offset/limit exceeds budget")
	}
	if o.Limit == 0 {
		o.Limit = 8192
	}
	if o.View == "validation" && (o.Offset != 0 || o.ExpectedOutputSHA256 != "") {
		return report, errors.New("validation has no pageable output")
	}
	body, absolute, digest, err := targetidentity.CaptureFile(path, maxWABTInput)
	if err != nil {
		return report, err
	}
	if err = checkWABTDigest(o.ExpectedSHA256, digest, "WASM input"); err != nil {
		return report, err
	}
	report, err = wasmEnvelope(body, absolute, digest)
	if err != nil {
		return report, err
	}
	report.WABT = &WABTReport{Status: "checking", Profile: "wabt-" + WABTVersion, FeaturePolicy: "--enable-all",
		CanonicalSource: "https://github.com/WebAssembly/wabt/releases/tag/1.0.42", SourceCommit: "ff0ef7e0009402740c805a9744c09b05be063e48", License: "Apache-2.0", View: o.View,
		Limits: []string{"8 MiB input; 4096 sections; 16 MiB stdout plus 64 KiB stderr per command; 30 seconds per command and 90 seconds overall",
			"Caller-supplied trusted programs; recorded SHA/version is not publisher authentication or an OS sandbox",
			"WAT is a decoded representation, not original source, original layout, byte round-trip identity or runtime behavior",
			"Section ranges come from the shared byte envelope; legacy import/export summaries are not derived for this feature profile",
			"Only the direct child is owned and cancelled; no process-tree claim"}}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	byName := map[string]WABTTool{}
	for _, name := range []string{"wasm-validate", "wasm-objdump", "wasm2wat"} {
		var candidate toolindex.Tool
		for _, tool := range tools {
			if tool.Name == name {
				candidate = tool
				break
			}
		}
		if !candidate.Available {
			return report, fmt.Errorf("WABT %s unavailable; supply WABT %s through REVERSERESEARCH_TOOLS or runtime/wabt/wabt-%s/bin", name, WABTVersion, WABTVersion)
		}
		_, toolPath, sha, captureErr := targetidentity.CaptureFile(candidate.Path, 64<<20)
		if captureErr != nil {
			return report, fmt.Errorf("WABT %s: %w", name, captureErr)
		}
		if candidate.ExecutableIdentity.SHA256 != "" && candidate.ExecutableIdentity.SHA256 != sha {
			return report, errors.New("WABT tool changed since discovery")
		}
		byName[name] = WABTTool{Name: name, Path: toolPath, SHA256: sha}
	}
	workspace, err := os.MkdirTemp("", "rr-wabt-")
	if err != nil {
		return report, err
	}
	defer func() {
		cleanupErr := cleanup(workspace)
		if cleanupErr != nil {
			err = errors.Join(err, fmt.Errorf("WABT workspace cleanup failed at %s: %w", workspace, cleanupErr))
		} else {
			report.WABT.TemporaryCopyDisposed = true
		}
	}()
	if err = securefile.RestrictDir(workspace); err != nil {
		return report, err
	}
	copyPath := filepath.Join(workspace, "module.wasm")
	if err = os.WriteFile(copyPath, body, 0o400); err != nil {
		return report, err
	}
	if err = securefile.RestrictFile(copyPath); err != nil {
		return report, err
	}
	// Validate the observed source/copy/tool identities around every command.
	check := func(tool WABTTool) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		for _, item := range []struct {
			path, sha string
			limit     int64
		}{{tool.Path, tool.SHA256, 64 << 20}, {copyPath, digest, maxWABTInput}, {absolute, digest, maxWABTInput}} {
			_, _, got, e := targetidentity.CaptureFile(item.path, item.limit)
			if e != nil {
				return e
			}
			if got != item.sha {
				return fmt.Errorf("WABT input/tool changed: %s", item.path)
			}
		}
		return nil
	}
	command := func(name string, args []string) (toolprocess.Result, error) {
		tool := byName[name]
		if e := check(tool); e != nil {
			return toolprocess.Result{}, e
		}
		commandCtx, stop := context.WithTimeout(ctx, 30*time.Second)
		defer stop()
		result := run(commandCtx, tool.Path, args, workspace)
		if commandCtx.Err() != nil {
			return result, commandCtx.Err()
		}
		if result.Truncated {
			return result, errors.New("WABT output exceeded budget; truncated result rejected")
		}
		if len(result.Stdout) > maxWABTOutput || len(result.Stderr) > maxWABTDiagnostic || !utf8.Valid(result.Stdout) || !utf8.Valid(result.Stderr) {
			return result, errors.New("WABT output is oversized or not UTF-8")
		}
		if e := check(tool); e != nil {
			return result, e
		}
		if result.ExitCode < 0 {
			return result, fmt.Errorf("WABT %s process could not complete: %w", name, result.Err)
		}
		if result.ExitCode == 0 && result.Err != nil {
			return result, result.Err
		}
		report.WABT.Commands = append(report.WABT.Commands, WABTCommand{Tool: name, Arguments: args, ExitCode: result.ExitCode, Diagnostics: string(result.Stderr)})
		return result, nil
	}
	for _, name := range []string{"wasm-validate", "wasm-objdump", "wasm2wat"} {
		version, e := command(name, []string{"--version"})
		if e != nil {
			return report, e
		}
		if version.ExitCode != 0 || strings.TrimSpace(string(version.Stdout)) != WABTVersion {
			return report, fmt.Errorf("WABT %s version mismatch; require %s", name, WABTVersion)
		}
		tool := byName[name]
		tool.VersionBanner = string(version.Stdout)
		byName[name] = tool
		report.WABT.Tools = append(report.WABT.Tools, tool)
	}
	validation, err := command("wasm-validate", []string{"--enable-all", "module.wasm"})
	if err != nil {
		return report, err
	}
	if validation.ExitCode != 0 {
		if validation.ExitCode != 1 {
			return report, fmt.Errorf("WABT validation process failed: exit %d", validation.ExitCode)
		}
		report.WABT.Status = "invalid-module"
		return report, nil
	}
	report.WABT.Validated, report.WABT.Status = true, "validated"
	if o.View == "validation" {
		report.WABT.OutputComplete = true
		return report, nil
	}
	name, args := "wasm2wat", []string{"--enable-all", "module.wasm"}
	if o.View == "details" {
		name, args = "wasm-objdump", []string{"-h", "-x", "module.wasm"}
	}
	result, err := command(name, args)
	if err != nil {
		return report, err
	}
	if result.ExitCode != 0 {
		return report, fmt.Errorf("WABT %s failed after validation: exit %d", name, result.ExitCode)
	}
	outputSHA := sha256.Sum256(result.Stdout)
	report.WABT.OutputSHA256 = hex.EncodeToString(outputSHA[:])
	if err = checkWABTDigest(o.ExpectedOutputSHA256, report.WABT.OutputSHA256, "WABT output"); err != nil {
		return report, err
	}
	if o.Offset > len(result.Stdout) || (o.Offset < len(result.Stdout) && !utf8.RuneStart(result.Stdout[o.Offset])) {
		return report, errors.New("WABT offset exceeds output or splits a UTF-8 rune")
	}
	end := min(o.Offset+o.Limit, len(result.Stdout))
	for end > o.Offset && end < len(result.Stdout) && !utf8.RuneStart(result.Stdout[end]) {
		end--
	}
	if end == o.Offset && end < len(result.Stdout) {
		return report, errors.New("WABT limit is too small for the next UTF-8 rune")
	}
	report.WABT.TotalOutputBytes = len(result.Stdout)
	report.WABT.Offset, report.WABT.NextOffset = o.Offset, end
	report.WABT.Output = string(result.Stdout[o.Offset:end])
	report.WABT.OutputComplete = end == len(result.Stdout)
	return report, nil
}

func checkWABTDigest(expected, actual, label string) error {
	if expected == "" {
		return nil
	}
	decoded, err := hex.DecodeString(expected)
	if err != nil || len(decoded) != 32 {
		return fmt.Errorf("%s expected SHA-256 must contain 64 hex characters", label)
	}
	if !strings.EqualFold(expected, actual) {
		return fmt.Errorf("%s SHA-256 mismatch", label)
	}
	return nil
}

func disposeWABTWorkspace(workspace string) error {
	// Only this adapter's freshly created, fixed-name copy is made writable.
	copyPath := filepath.Join(workspace, "module.wasm")
	if info, err := os.Lstat(copyPath); err == nil && info.Mode().IsRegular() {
		if err := os.Chmod(copyPath, 0o600); err != nil {
			return err
		}
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.RemoveAll(workspace)
}
