package toolindex

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestScanFindsProjectOwnedCoreTools(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	index, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"x32dbg", "x64dbg", "ghidra", "radare2", "radiff2"} {
		tool, ok := index.ByName(name)
		if !ok {
			t.Fatalf("tool %s missing from index", name)
		}
		if !tool.Available || tool.Path == "" {
			t.Fatalf("tool %s=%+v", name, tool)
		}
	}
	for _, name := range []string{"die", "nmap", "burp", "gdb", "jadx", "apktool", "wireshark", "docker", "winget"} {
		if _, ok := index.ByName(name); !ok {
			t.Fatalf("catalog entry %s should exist even when unavailable", name)
		}
	}
}

func TestScanFindsConfiguredOffPathTools(t *testing.T) {
	root := t.TempDir()
	configured := t.TempDir()
	fakeADB := filepath.Join(configured, "adb.exe")
	fakeR2 := filepath.Join(configured, "radare2.exe")
	fakeRadiff2 := filepath.Join(configured, "radiff2.exe")
	fakeX32 := filepath.Join(configured, "x32dbg.exe")
	fakeX64 := filepath.Join(configured, "x64dbg.exe")
	fakeGhidra := filepath.Join(configured, "ghidraRun.bat")
	fakeR2MCP := filepath.Join(configured, "r2mcp.exe")
	fakeAWS := filepath.Join(configured, "aws.exe")
	for _, path := range []string{fakeADB, fakeR2, fakeRadiff2, fakeX32, fakeX64, fakeGhidra, fakeR2MCP, fakeAWS} {
		if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("REVERSERESEARCH_TOOLS", configured+string(os.PathListSeparator)+configured)
	index, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	for name, wantPath := range map[string]string{
		"adb": fakeADB, "radare2": fakeR2, "radiff2": fakeRadiff2,
		"x32dbg": fakeX32, "x64dbg": fakeX64, "ghidra": fakeGhidra, "r2mcp": fakeR2MCP,
		"aws": fakeAWS,
	} {
		tool, ok := index.ByName(name)
		if !ok || !tool.Available || tool.Source != "configured" || filepath.Clean(tool.Path) != filepath.Clean(wantPath) {
			t.Fatalf("configured %s=%+v", name, tool)
		}
	}
}

func TestSaveAndLoad(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	index, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "tool-index.json")
	if err := Save(path, index); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Tools) != len(index.Tools) {
		t.Fatalf("loaded=%d original=%d", len(loaded.Tools), len(index.Tools))
	}
}

func TestConcurrentSaveKeepsValidIndex(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	base, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "tool-index.json")
	var wg sync.WaitGroup
	errCh := make(chan error, 24)
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(iteration int) {
			defer wg.Done()
			value := base
			value.GeneratedUTC = base.GeneratedUTC + "-" + string(rune('a'+iteration%26))
			if err := Save(path, value); err != nil {
				errCh <- err
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Tools) != len(base.Tools) || loaded.Root != base.Root {
		t.Fatalf("loaded=%+v", loaded)
	}
}

func TestScanUsesSingleUCRT64PythonRuntime(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	index, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := index.ByName("python312"); ok {
		t.Fatal("legacy python312 tool entry must be removed")
	}
	ucrt, ok := index.ByName("python-ucrt64")
	if !ok {
		t.Fatal("python-ucrt64 tool entry missing")
	}
	want := filepath.Clean(`C:\msys64\ucrt64\bin\python.exe`)
	if !ucrt.Available || filepath.Clean(ucrt.Path) != want {
		t.Fatalf("python-ucrt64=%+v want=%q", ucrt, want)
	}
}

func TestToolIndexV2CarriesIdentityAndPolicyMetadata(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	index, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range index.Tools {
		if tool.Version == "" || tool.Architecture == "" || tool.Provider == "" || tool.CanonicalSource == "" ||
			tool.License == "" || tool.InstallScope == "" || tool.TrustStatus == "" || tool.HealthStatus == "" {
			t.Fatalf("incomplete ToolIndex v2 metadata: %+v", tool)
		}
		if tool.Available {
			switch tool.HealthStatus {
			case "runtime-profile-present":
				if tool.Name != "jadx-headless" || tool.RuntimeKind != "java-source-bridge" || tool.InterpreterPath == "" || len(tool.RuntimeArtifacts) != 4 || tool.ExecutableIdentity.SHA256 != "" {
					t.Fatalf("interpreted profile lacks explicit runtime identity: %+v", tool)
				}
				roles := map[string]bool{}
				for _, artifact := range tool.RuntimeArtifacts {
					if roles[artifact.Role] || len(artifact.SHA256) != 64 || artifact.Size <= 0 || !filepath.IsAbs(artifact.Path) {
						t.Fatalf("invalid runtime artifact: %+v", artifact)
					}
					roles[artifact.Role] = true
					if artifact.Role == "engine" && artifact.SHA256 != JADXEngineSHA256 {
						t.Fatal("JADX engine pin drift")
					}
				}
				for _, role := range []string{"engine", "bridge", "java", "source-compiler"} {
					if !roles[role] {
						t.Fatalf("runtime role missing: %s", role)
					}
				}
			case "identity-verified":
				if len(tool.ExecutableIdentity.SHA256) != 64 || tool.ExecutableIdentity.Size < 0 || tool.ExecutableIdentity.ModifiedUTC == "" {
					t.Fatalf("verified tool lacks stable executable identity: %+v", tool)
				}
			case "identity-unverified":
				if tool.Path == "" || tool.IdentityError == "" {
					t.Fatalf("unverified tool lacks explicit identity error: %+v", tool)
				}
			default:
				t.Fatalf("available tool has invalid health status: %+v", tool)
			}
		} else if tool.HealthStatus != "unavailable" {
			t.Fatalf("unavailable tool health=%q", tool.HealthStatus)
		}
	}
	ghidra, ok := index.ByName("ghidra")
	if !ok || ghidra.Provider != "project" || ghidra.TrustStatus != "project-owned" || len(ghidra.Capabilities) == 0 {
		t.Fatalf("ghidra v2 metadata=%+v", ghidra)
	}
}

func TestP2ToolIndexCoverage(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	index, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	required := []string{
		"atomic-red-team", "aws", "az", "binwalk", "bloodhound", "caldera", "certipy", "curl",
		"frida", "gcloud", "ghidra", "impacket", "kube-bench", "kubectl", "kubescape", "lldb",
		"masscan", "misp", "netexec", "nmap", "opencti", "osquery", "prowler", "qemu", "scoutsuite",
		"sharphound", "sigma", "sqlmap", "steampipe", "taxii", "trivy", "zeek",
	}
	for _, name := range required {
		tool, ok := index.ByName(name)
		if !ok {
			t.Fatalf("P2 tool missing from ToolIndex discovery catalog: %s", name)
		}
		if tool.Provider == "" || tool.CanonicalSource == "" || tool.License == "" || tool.InstallScope == "" || tool.TrustStatus == "" {
			t.Fatalf("P2 tool lacks policy metadata: %+v", tool)
		}
	}
}
