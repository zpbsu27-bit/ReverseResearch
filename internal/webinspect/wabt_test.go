package webinspect

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"reverseresearch/internal/toolindex"
	"reverseresearch/internal/toolprocess"
)

func wabtFixture(t *testing.T) (string, []toolindex.Tool) {
	t.Helper()
	dir := t.TempDir()
	input := filepath.Join(dir, "input.wasm")
	if err := os.WriteFile(input, []byte{0, 97, 115, 109, 1, 0, 0, 0}, 0o600); err != nil {
		t.Fatal(err)
	}
	var tools []toolindex.Tool
	for _, name := range []string{"wasm-validate", "wasm-objdump", "wasm2wat"} {
		path := filepath.Join(dir, name+".exe")
		if err := os.WriteFile(path, []byte("inert-tool-"+name), 0o600); err != nil {
			t.Fatal(err)
		}
		tools = append(tools, toolindex.Tool{Name: name, Available: true, Path: path})
	}
	return input, tools
}

func wabtFakeOutput(output string) wabtRunFunc {
	return func(_ context.Context, _ string, args []string, _ string) toolprocess.Result {
		if len(args) == 1 && args[0] == "--version" {
			return toolprocess.Result{Stdout: []byte(WABTVersion + "\n")}
		}
		if len(args) > 0 && args[0] == "--enable-all" && !strings.Contains(output, "wat") {
			return toolprocess.Result{Stdout: []byte(output)}
		}
		return toolprocess.Result{Stdout: []byte(output)}
	}
}

func TestWABTIdentityPaginationAndPrivateCopy(t *testing.T) {
	path, tools := wabtFixture(t)
	var workspace string
	run := func(ctx context.Context, exe string, args []string, dir string) toolprocess.Result {
		workspace = dir
		if filepath.Base(exe) == "wasm2wat.exe" && len(args) > 1 && args[0] == "--enable-all" {
			b, err := os.ReadFile(filepath.Join(dir, "module.wasm"))
			if err != nil || !bytes.Equal(b, []byte{0, 97, 115, 109, 1, 0, 0, 0}) {
				t.Fatalf("snapshot copy: %v", err)
			}
			if args[1] != "module.wasm" || dir == filepath.Dir(path) {
				t.Fatal("target path sent to tool instead of private copy")
			}
			return toolprocess.Result{Stdout: []byte("a€wat\n")}
		}
		return wabtFakeOutput("")(ctx, exe, args, dir)
	}
	report, err := inspectWABT(context.Background(), path, WASMOptions{UseWABT: true, View: "wat", Limit: 4}, tools, run, disposeWABTWorkspace)
	if err != nil {
		t.Fatal(err)
	}
	if !report.WABT.Validated || report.WABT.Output != "a€" || report.WABT.NextOffset != 4 || report.WABT.OutputComplete || !report.WABT.TemporaryCopyDisposed || len(report.WABT.Tools) != 3 || len(report.WABT.Commands) != 5 {
		t.Fatalf("report=%+v", report.WABT)
	}
	if _, err := os.Stat(workspace); !os.IsNotExist(err) {
		t.Fatalf("workspace not disposed: %v", err)
	}
	second, err := inspectWABT(context.Background(), path, WASMOptions{UseWABT: true, View: "wat", Offset: 4, Limit: 3, ExpectedSHA256: report.SHA256, ExpectedOutputSHA256: report.WABT.OutputSHA256}, tools, run, disposeWABTWorkspace)
	if err != nil || second.WABT.Output != "wat" || second.WABT.OutputComplete {
		t.Fatalf("page=%+v err=%v", second.WABT, err)
	}
	for _, options := range []WASMOptions{{UseWABT: true, View: "wat", Offset: 2}, {UseWABT: true, View: "wat", Offset: 1, Limit: 1}, {UseWABT: true, View: "wat", ExpectedSHA256: strings.Repeat("0", 64)}, {UseWABT: true, View: "wat", ExpectedOutputSHA256: strings.Repeat("0", 64)}, {UseWABT: true, View: "wat", ExpectedSHA256: "bad"}} {
		if _, err := inspectWABT(context.Background(), path, options, tools, run, disposeWABTWorkspace); err == nil {
			t.Fatalf("accepted bad page: %+v", options)
		}
	}
}

func TestWABTFailureSemantics(t *testing.T) {
	for _, name := range []string{"missing", "version", "truncation", "timeout", "tool-drift", "copy-drift", "source-drift", "utf8", "cleanup", "invalid"} {
		t.Run(name, func(t *testing.T) {
			path, tools := wabtFixture(t)
			calls := 0
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if name == "missing" {
				tools = tools[:1]
			}
			run := func(ctx context.Context, exe string, args []string, dir string) toolprocess.Result {
				calls++
				result := wabtFakeOutput("(module)\n")(ctx, exe, args, dir)
				if calls != 1 && name != "invalid" {
					return result
				}
				switch name {
				case "version":
					result.Stdout = []byte("1.0.41\n")
				case "truncation":
					result.Truncated = true
				case "timeout":
					cancel()
				case "tool-drift":
					if err := os.WriteFile(exe, []byte("changed tool"), 0o600); err != nil {
						t.Fatal(err)
					}
				case "copy-drift":
					copy := filepath.Join(dir, "module.wasm")
					if err := os.Chmod(copy, 0o600); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(copy, []byte("changed copy"), 0o600); err != nil {
						t.Fatal(err)
					}
				case "source-drift":
					if err := os.WriteFile(path, []byte("changed source"), 0o600); err != nil {
						t.Fatal(err)
					}
				case "utf8":
					result.Stdout = []byte{0xff}
				case "invalid":
					if calls == 4 {
						result.ExitCode = 1
						result.Stderr = []byte("error: invalid module\n")
					}
				}
				return result
			}
			cleanup := disposeWABTWorkspace
			if name == "cleanup" {
				cleanup = func(dir string) error { defer disposeWABTWorkspace(dir); return errors.New("injected cleanup failure") }
			}
			report, err := inspectWABT(ctx, path, WASMOptions{UseWABT: true, View: "wat"}, tools, run, cleanup)
			if name == "invalid" {
				if err != nil || report.WABT.Validated || report.WABT.Status != "invalid-module" || calls != 4 || !report.WABT.TemporaryCopyDisposed {
					t.Fatalf("invalid=%+v err=%v calls=%d", report.WABT, err, calls)
				}
			} else if err == nil {
				t.Fatal("failure was accepted")
			}
			if name == "cleanup" && (!strings.Contains(err.Error(), "cleanup failed at") || report.WABT.TemporaryCopyDisposed) {
				t.Fatalf("cleanup=%v", err)
			}
			if name == "missing" && calls != 0 {
				t.Fatal("executed incomplete toolchain")
			}
		})
	}
}

func TestWASMEnvelopeBudgets(t *testing.T) {
	for _, tail := range [][]byte{{0, 0xff, 0xff, 0xff, 0xff, 0x1f}, bytes.Repeat([]byte{0, 0}, 4097)} {
		if _, err := wasmEnvelope(append([]byte{0, 97, 115, 109, 1, 0, 0, 0}, tail...), "fixture", "sha"); err == nil {
			t.Fatal("accepted overflow/budget")
		}
	}
	if _, err := parseImports([]byte{0xff, 0xff, 0xff, 0xff, 0x0f}); err == nil {
		t.Fatal("unbounded import allocation")
	}
	if _, err := parseExports([]byte{0xff, 0xff, 0xff, 0xff, 0x0f}); err == nil {
		t.Fatal("unbounded export allocation")
	}
}

func TestOfficialWindowsWABTProfile(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	tools, err := toolindex.DiscoverWABT(root)
	if err != nil {
		t.Fatal(err)
	}
	var compiler toolindex.Tool
	for _, tool := range tools {
		if tool.Name == "wat2wasm" {
			compiler = tool
		}
	}
	if !compiler.Available {
		t.Skip("WABT producer is not configured")
	}
	ctx := context.Background()
	banner := toolprocess.Run(ctx, compiler.Path, []string{"--version"}, 1024, 1024, "")
	if banner.Err != nil || string(banner.Stdout) != WABTVersion+"\n" {
		t.Fatalf("producer banner=%q err=%v", banner.Stdout, banner.Err)
	}
	wat := filepath.Join(root, "testdata", "rea-wasm-module.wat")
	output := filepath.Join(t.TempDir(), "produced.wasm")
	compiled := toolprocess.Run(ctx, compiler.Path, []string{wat, "-o", output}, 1024, 1024, "")
	if compiled.Err != nil {
		t.Fatalf("producer: %v %s", compiled.Err, compiled.Stderr)
	}
	for _, view := range []string{"wat", "details", "validation"} {
		report, err := InspectWASMWithOptions(ctx, root, output, WASMOptions{UseWABT: true, View: view, Limit: 32768})
		if err != nil || !report.WABT.Validated || !report.WABT.TemporaryCopyDisposed || !report.WABT.OutputComplete {
			t.Fatalf("%s: %+v err=%v", view, report.WABT, err)
		}
		if view == "validation" {
			continue
		}
		name, args := "wasm2wat", []string{"--enable-all", output}
		if view == "details" {
			name, args = "wasm-objdump", []string{"-h", "-x", output}
		}
		var exe string
		for _, tool := range tools {
			if tool.Name == name {
				exe = tool.Path
			}
		}
		direct := toolprocess.Run(ctx, exe, args, maxWABTOutput, maxWABTDiagnostic, "")
		direct.Stdout = bytes.ReplaceAll(direct.Stdout, []byte("produced.wasm"), []byte("module.wasm"))
		if direct.Err != nil || !bytes.Equal(direct.Stdout, []byte(report.WABT.Output)) {
			t.Fatalf("%s producer output differs: %v\n%s\n%s", view, direct.Err, direct.Stdout, report.WABT.Output)
		}
	}
	// This corrupts code semantics while keeping all section byte ranges intact.
	body, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	body[len(body)-1] = 1
	if err := os.WriteFile(output, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectWASM(output); err != nil {
		t.Fatalf("fixture no longer distinguishes structural/semantic checks: %v", err)
	}
	rejected, err := InspectWASMWithOptions(ctx, root, output, WASMOptions{UseWABT: true, View: "wat"})
	if err != nil || rejected.WABT.Validated || rejected.WABT.Status != "invalid-module" {
		t.Fatalf("invalid producer bytes: %+v err=%v", rejected.WABT, err)
	}
}
