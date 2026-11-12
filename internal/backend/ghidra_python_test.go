//go:build windows

package backend

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGhidraPythonPreflightPreservesCallerCancellation(t *testing.T) {
	program, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := validateGhidraPython(cancelled, program, t.TempDir()); !errors.Is(err, context.Canceled) {
		t.Fatalf("caller cancellation lost: %v", err)
	}
	expired, stop := context.WithTimeout(context.Background(), time.Nanosecond)
	defer stop()
	<-expired.Done()
	if err := validateGhidraPython(expired, program, t.TempDir()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("caller deadline lost: %v", err)
	}
}

func TestGhidraPythonResolverUsesSingleUCRT64Runtime(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	python, err := resolveGhidraPython(root)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Clean("C:\\msys64\\ucrt64\\bin\\python.exe")
	if filepath.Clean(python) != want {
		t.Fatalf("ghidra python=%q want=%q", python, want)
	}
	sitePackages := filepath.Join(root, "runtime", "ghidra", "python-packages")
	if err := validateGhidraPython(t.Context(), python, sitePackages); err != nil {
		t.Fatal(err)
	}
}

func TestGhidraUnicodeSourceNameUsesStableInternalAlias(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if err := syncGhidraRuntimeSources(root); err != nil {
		t.Fatal(err)
	}
	python, err := resolveGhidraPython(root)
	if err != nil {
		t.Fatal(err)
	}
	sitePackages := filepath.Join(root, "runtime", "ghidra", "python-packages")
	fixture := filepath.Join(root, "testdata", "mcp-smoke.exe")
	script := strings.Join([]string{
		"import hashlib,os,shutil,sys",
		"sys.path.append(sys.argv[1])",
		"from re_mcp_ghidra.session import _ghidra_import_path,_ghidra_item_name_valid,_ghidra_program_name",
		"cn=chr(0x4e2d)+chr(0x6587)",
		"d=os.path.join(sys.argv[2],'sample-'+cn)",
		"os.makedirs(d,exist_ok=True)",
		"src=os.path.join(d,cn+'.exe')",
		"shutil.copy2(sys.argv[3],src)",
		"name=_ghidra_program_name(src)",
		"assert not _ghidra_item_name_valid(os.path.basename(src))",
		"assert _ghidra_item_name_valid(name)",
		"assert name.startswith('rr_') and name.endswith('.exe')",
		"assert _ghidra_program_name(src)==name",
		"with _ghidra_import_path(src,name) as alias:",
		"    assert os.path.basename(alias)==name",
		"    assert open(src,'rb').read()==open(alias,'rb').read()",
		"    alias_dir=os.path.dirname(alias)",
		"assert not os.path.exists(alias_dir)",
		"print('rr-ghidra-unicode-alias-ok:'+name)",
	}, "\n")
	cmd := exec.Command(python, "-I", "-c", script, sitePackages, t.TempDir(), fixture)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("unicode alias regression failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "rr-ghidra-unicode-alias-ok:rr_") {
		t.Fatalf("unexpected unicode alias output: %s", output)
	}
}

func TestGhidraWorkerEnvironmentPrefersUCRT64SystemSiteThenBundle(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	python, err := resolveGhidraPython(root)
	if err != nil {
		t.Fatal(err)
	}
	sitePackages := filepath.Join(root, "runtime", "ghidra", "python-packages")
	cmd := exec.Command(python, "-c", "import jpype,re_mcp_ghidra,re_mcp,mcp; print(jpype.__file__); print(re_mcp_ghidra.__file__); print('rr-ghidra-worker-import-ok')")
	cmd.Env = ghidraWorkerEnvironment(os.Environ(), python, sitePackages)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("worker interpreter cannot import runtime: %v\n%s", err, output)
	}
	// MSYS2 CPython reports module files with forward slashes, so both sides must
	// be normalized before comparison; a raw filepath.Join never matched output.
	text := strings.ToLower(filepath.ToSlash(string(output)))
	systemJPype := strings.ToLower(filepath.ToSlash(filepath.Join(ghidraSystemSitePackages(python), "jpype")))
	if !strings.Contains(text, systemJPype) {
		t.Fatalf("worker must prefer UCRT64 system JPype, got:\n%s", output)
	}
	if !strings.Contains(text, strings.ToLower(filepath.ToSlash(filepath.Clean(sitePackages)))) {
		t.Fatalf("worker must load re_mcp_ghidra from bundle, got:\n%s", output)
	}
	if !strings.Contains(text, "rr-ghidra-worker-import-ok") {
		t.Fatalf("unexpected worker import output: %s", output)
	}
}
