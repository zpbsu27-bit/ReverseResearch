package toolindex

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"reverseresearch/internal/recordio"
)

const maxToolIndexBytes = int64(8 << 20)

type ExecutableIdentity struct {
	SHA256      string `json:"sha256,omitempty"`
	Size        int64  `json:"size,omitempty"`
	ModifiedUTC string `json:"modified_utc,omitempty"`
}

type Tool struct {
	Name               string             `json:"name"`
	Available          bool               `json:"available"`
	Path               string             `json:"path,omitempty"`
	Source             string             `json:"source"`
	Version            string             `json:"version"`
	Architecture       string             `json:"architecture"`
	Provider           string             `json:"provider"`
	CanonicalSource    string             `json:"canonical_source"`
	License            string             `json:"license"`
	InstallScope       string             `json:"install_scope"`
	TrustStatus        string             `json:"trust_status"`
	ExecutableIdentity ExecutableIdentity `json:"executable_identity"`
	Capabilities       []string           `json:"capabilities"`
	RequiresAdmin      bool               `json:"requires_admin"`
	RequiresNetwork    bool               `json:"requires_network"`
	MutatesTarget      bool               `json:"mutates_target"`
	Commercial         bool               `json:"commercial"`
	Redistributable    bool               `json:"redistributable"`
	HealthStatus       string             `json:"health_status"`
	IdentityError      string             `json:"identity_error,omitempty"`
	RuntimeKind        string             `json:"runtime_kind,omitempty"`
	InterpreterPath    string             `json:"interpreter_path,omitempty"`
	RuntimeArtifacts   []RuntimeArtifact  `json:"runtime_artifacts,omitempty"`
}

type Index struct {
	GeneratedUTC string `json:"generated_utc"`
	Root         string `json:"root"`
	Tools        []Tool `json:"tools"`
}

func (index Index) ByName(name string) (Tool, bool) {
	for _, tool := range index.Tools {
		if tool.Name == name {
			return tool, true
		}
	}
	return Tool{}, false
}

func Scan(root string) (Index, error) {
	absolute, err := filepath.Abs(root)
	if err != nil {
		return Index{}, fmt.Errorf("resolve project root: %w", err)
	}
	tools := []Tool{
		firstAvailableTool("x32dbg",
			projectTool("x32dbg", filepath.Join(absolute, "runtime", "x32dbg", "release", "x32", "x32dbg.exe")),
			firstTool("x32dbg", []string{"x32dbg.exe"}),
		),
		firstAvailableTool("x64dbg",
			projectTool("x64dbg", filepath.Join(absolute, "runtime", "x32dbg", "release", "x64", "x64dbg.exe")),
			firstTool("x64dbg", []string{"x64dbg.exe"}),
		),
		firstAvailableTool("ghidra",
			projectTool("ghidra", filepath.Join(absolute, "runtime", "ghidra", "app", "ghidraRun.bat")),
			projectTool("ghidra", filepath.Join(absolute, "runtime", "ghidra", "app", "ghidraRun")),
			firstTool("ghidra", []string{"ghidraRun.bat"}),
		),
		firstAvailableTool("radare2",
			globTool("radare2", filepath.Join(absolute, "runtime", "radare2", "engine", "radare2-*-w64", "bin", "radare2.exe")),
			projectTool("radare2", filepath.Join(absolute, "runtime", "radare2", "engine", "usr", "bin", "radare2")),
			projectTool("radare2", filepath.Join(absolute, "runtime", "radare2", "engine", "bin", "radare2")),
			firstTool("radare2", []string{"radare2.exe", "radare2"}),
		),
		firstAvailableTool("radiff2",
			globTool("radiff2", filepath.Join(absolute, "runtime", "radare2", "engine", "radare2-*-w64", "bin", "radiff2.exe")),
			projectTool("radiff2", filepath.Join(absolute, "runtime", "radare2", "engine", "usr", "bin", "radiff2")),
			projectTool("radiff2", filepath.Join(absolute, "runtime", "radare2", "engine", "bin", "radiff2")),
			firstTool("radiff2", []string{"radiff2.exe", "radiff2"}),
		),
		firstAvailableTool("r2mcp",
			projectTool("r2mcp", filepath.Join(absolute, "runtime", "radare2", "mcp", "r2mcp.exe")),
			projectTool("r2mcp", filepath.Join(absolute, "runtime", "radare2", "mcp", "r2mcp")),
			projectTool("r2mcp", filepath.Join(absolute, "runtime", "radare2", "mcp", "usr", "bin", "r2mcp")),
			projectTool("r2mcp", filepath.Join(absolute, "runtime", "radare2", "mcp", "usr", "local", "bin", "r2mcp")),
			firstTool("r2mcp", []string{"r2mcp.exe", "r2mcp"}),
		),
		firstTool("die", []string{
			filepath.Join(absolute, "runtime", "die", "diec.exe"),
			"diec.exe",
			"diec",
		}),
		firstTool("pe-bear", []string{
			filepath.Join(absolute, "runtime", "pe-bear", "PE-bear.exe"),
			"PE-bear.exe",
			"PE-bear",
		}),
		firstTool("frida", []string{"frida.exe", "frida"}),
		configuredTool("aws", []string{"aws.exe", "aws"}),
		configuredTool("az", []string{"az.cmd", "az.exe", "az"}),
		configuredTool("gcloud", []string{"gcloud.cmd", "gcloud.exe", "gcloud"}),
		configuredTool("bloodhound", []string{"BloodHound.exe", "bloodhound.exe", "bloodhound"}),
		configuredTool("sharphound", []string{"SharpHound.exe", "sharphound.exe", "sharphound"}),
		configuredTool("impacket", []string{"impacket-smbclient.exe", "impacket-smbclient", "secretsdump.py"}),
		configuredTool("netexec", []string{"nxc.exe", "nxc", "netexec.exe", "netexec"}),
		configuredTool("certipy", []string{"certipy.exe", "certipy"}),
		configuredTool("kubectl", []string{"kubectl.exe", "kubectl"}),
		configuredTool("kubescape", []string{"kubescape.exe", "kubescape"}),
		configuredTool("kube-bench", []string{"kube-bench.exe", "kube-bench"}),
		configuredTool("prowler", []string{"prowler.exe", "prowler"}),
		configuredTool("scoutsuite", []string{"scout.exe", "scout"}),
		configuredTool("steampipe", []string{"steampipe.exe", "steampipe"}),
		configuredTool("osquery", []string{"osqueryi.exe", "osqueryi"}),
		configuredTool("atomic-red-team", []string{"Invoke-AtomicRedTeam.psd1", "Invoke-AtomicRedTeam.psm1"}),
		configuredTool("caldera", []string{"caldera.exe", "caldera", "server.py"}),
		configuredTool("misp", []string{"misp.exe", "misp", "misp-cli.exe", "misp-cli"}),
		configuredTool("opencti", []string{"opencti.exe", "opencti", "opencti-worker"}),
		configuredTool("taxii", []string{"taxii.exe", "taxii", "taxii2-client"}),
		firstTool("nmap", []string{"nmap.exe", "nmap"}),
		firstTool("sqlmap", []string{"sqlmap.py", "sqlmap.exe", "sqlmap"}),
		firstTool("masscan", []string{"masscan.exe", "masscan"}),
		firstTool("burp", []string{"BurpSuitePro.exe", "BurpSuiteCommunity.exe", "burpsuite.exe", "burpsuite"}),
		firstTool("mitmproxy", []string{"mitmproxy.exe", "mitmproxy"}),
		firstTool("wireshark", []string{"Wireshark.exe", "wireshark"}),
		firstTool("tshark", []string{"tshark.exe", "tshark"}),
		firstTool("yara", []string{"yara64.exe", "yara.exe", "yara"}),
		firstTool("gdb", []string{"gdb.exe", "gdb"}),
		firstTool("pwndbg", []string{"pwndbg.exe", "pwndbg"}),
		firstTool("checksec", []string{"checksec.exe", "checksec"}),
		firstTool("qemu", []string{"qemu-system-x86_64.exe", "qemu-system-x86_64"}),
		firstTool("docker", []string{"docker.exe", "docker"}),
		firstTool("wsl", []string{"wsl.exe", "wsl"}),
		firstTool("jadx", []string{"jadx-gui.exe", "jadx.exe", "jadx"}),
		firstTool("apktool", []string{"apktool.bat", "apktool.exe", "apktool"}),
		firstTool("adb", []string{"adb.exe", "adb"}),
		firstTool("lldb", []string{"lldb.exe", "lldb"}),
		firstTool("dotnet", []string{"dotnet.exe", "dotnet"}),
		firstTool("ilspy", []string{"ILSpy.exe", "ilspycmd.exe", "ilspycmd"}),
		firstTool("dnspy", []string{"dnSpy.exe", "dnSpy-x86.exe"}),
		firstTool("binwalk", []string{"binwalk.exe", "binwalk"}),
		firstTool("emba", []string{"emba", "emba.sh"}),
		firstTool("firmae", []string{"run.sh", "firmae"}),
		firstTool("node", []string{"node.exe", "node"}),
		firstTool("chrome", browserCandidates("chrome")),
		firstTool("msedge", browserCandidates("msedge")),
		firstTool("curl", []string{"curl.exe", "curl"}),
		firstTool("procmon", []string{"Procmon64.exe", "Procmon.exe"}),
		firstTool("process-explorer", []string{"procexp64.exe", "procexp.exe"}),
		firstTool("windbg", []string{"WinDbgX.exe", "windbg.exe", "cdb.exe"}),
		firstTool("powershell", []string{"pwsh.exe", "powershell.exe"}),
		firstTool("rr", []string{"rr.exe", "rr"}),
		firstTool("perf", []string{"perf.exe", "perf"}),
		firstTool("bpftrace", []string{"bpftrace.exe", "bpftrace"}),
		firstTool("libfuzzer", []string{"libfuzzer.exe", "libfuzzer"}),
		firstTool("afl++", []string{"afl-fuzz.exe", "afl-fuzz"}),
		firstTool("winafl", []string{"afl-fuzz.exe", "afl-fuzz"}),
		firstTool("jazzer", []string{"jazzer_driver.exe", "jazzer.exe", "jazzer"}),
		firstTool("volatility3", []string{"vol.exe", "vol.py", "volatility3.exe", "volatility3"}),
		firstTool("memprocfs", []string{"MemProcFS.exe", "memprocfs"}),
		firstTool("hayabusa", []string{"hayabusa.exe", "hayabusa"}),
		firstTool("chainsaw", []string{"chainsaw.exe", "chainsaw"}),
		firstTool("kape", []string{"kape.exe", "gkape.exe"}),
		firstTool("plaso", []string{"log2timeline.exe", "log2timeline.py", "log2timeline"}),
		firstTool("zeek", []string{"zeek.exe", "zeek"}),
		firstTool("scapy", []string{"scapy.exe", "scapy"}),
		firstTool("kaitai", []string{"ksc.exe", "kaitai-struct-compiler.bat", "kaitai-struct-compiler"}),
		firstTool("semgrep", []string{"semgrep.exe", "semgrep"}),
		firstTool("codeql", []string{"codeql.exe", "codeql"}),
		firstTool("joern", []string{"joern.bat", "joern"}),
		firstTool("syft", []string{"syft.exe", "syft"}),
		firstTool("grype", []string{"grype.exe", "grype"}),
		firstTool("trivy", []string{"trivy.exe", "trivy"}),
		firstTool("osv-scanner", []string{"osv-scanner.exe", "osv-scanner"}),
		firstTool("gitleaks", []string{"gitleaks.exe", "gitleaks"}),
		firstTool("sigma", []string{"sigma.exe", "sigma"}),
		firstTool("suricata", []string{"suricata.exe", "suricata"}),
		firstTool("winget", []string{"winget.exe", "winget"}),
	}
	tools = append(tools,
		firstAvailableTool("java21",
			globTool("java21", filepath.Join(absolute, "runtime", "ghidra", "java", "*", "bin", "java.exe")),
			projectTool("java21", filepath.Join(absolute, "runtime", "ghidra", "java", "native", "bin", "java")),
		),
		projectTool("python-ucrt64", filepath.Clean(`C:\msys64\ucrt64\bin\python.exe`)),
		firstTool("python", []string{"python.exe", "python3.exe", "python", "python3"}),
	)
	tools = append(tools, discoverWABT(absolute)...)

	tools, err = enrichTools(absolute, tools)
	if err != nil {
		return Index{}, err
	}
	tools = append(tools, discoverJADX(absolute, tools))
	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })
	return Index{
		GeneratedUTC: time.Now().UTC().Format(time.RFC3339Nano),
		Root:         absolute,
		Tools:        tools,
	}, nil
}

// DiscoverWABT uses the same discovery and identity owner as Scan, without
// rescanning unrelated tools for each static WASM query.
func DiscoverWABT(root string) ([]Tool, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	return enrichTools(abs, discoverWABT(abs))
}

func discoverWABT(root string) []Tool {
	var tools []Tool
	for _, name := range []string{"wasm-validate", "wasm-objdump", "wasm2wat", "wat2wasm"} {
		tools = append(tools, firstAvailableTool(name,
			configuredTool(name, []string{name + ".exe", name}),
			firstTool(name, []string{filepath.Join(root, "runtime", "wabt", "wabt-1.0.42", "bin", name+".exe"),
				filepath.Join(root, "runtime", "wabt", "wabt-1.0.42", "bin", name), name + ".exe", name}),
		))
	}
	return tools
}

func browserCandidates(name string) []string {
	var candidates []string
	switch name {
	case "chrome":
		candidates = []string{
			filepath.Join(os.Getenv("PROGRAMFILES"), "Google", "Chrome", "Application", "chrome.exe"),
			filepath.Join(os.Getenv("PROGRAMFILES(X86)"), "Google", "Chrome", "Application", "chrome.exe"),
			filepath.Join(os.Getenv("LOCALAPPDATA"), "Google", "Chrome", "Application", "chrome.exe"),
			"chrome.exe", "chrome",
		}
	case "msedge":
		candidates = []string{
			filepath.Join(os.Getenv("PROGRAMFILES"), "Microsoft", "Edge", "Application", "msedge.exe"),
			filepath.Join(os.Getenv("PROGRAMFILES(X86)"), "Microsoft", "Edge", "Application", "msedge.exe"),
			filepath.Join(os.Getenv("LOCALAPPDATA"), "Microsoft", "Edge", "Application", "msedge.exe"),
			"msedge.exe", "msedge",
		}
	}
	filtered := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if strings.TrimSpace(candidate) == "" || candidate == "." {
			continue
		}
		filtered = append(filtered, candidate)
	}
	return filtered
}

func Save(path string, index Index) (err error) {
	body, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return fmt.Errorf("encode tool index: %w", err)
	}
	body = append(body, '\n')
	if int64(len(body)) > maxToolIndexBytes {
		return fmt.Errorf("tool index exceeds durable size limit: %d > %d", len(body), maxToolIndexBytes)
	}
	release, err := recordio.Acquire(filepath.Join(filepath.Dir(path), ".tool-index.lock"), 10*time.Second)
	if err != nil {
		return fmt.Errorf("lock tool index: %w", err)
	}
	defer func() { err = errors.Join(err, release()) }()
	if err := recordio.WriteFile(path, body, 0o600); err != nil {
		return fmt.Errorf("publish tool index: %w", err)
	}
	return nil
}

func Load(path string) (Index, error) {
	body, err := recordio.ReadFileLimit(path, maxToolIndexBytes)
	if err != nil {
		return Index{}, fmt.Errorf("read tool index: %w", err)
	}
	var index Index
	if err := json.Unmarshal(body, &index); err != nil {
		return Index{}, fmt.Errorf("decode tool index: %w", err)
	}
	return index, nil
}

func projectTool(name, path string) Tool {
	return fileTool(name, path, "project")
}

func globTool(name, pattern string) Tool {
	matches, _ := filepath.Glob(pattern)
	sort.Strings(matches)
	for _, match := range matches {
		if tool := projectTool(name, match); tool.Available {
			return tool
		}
	}
	return Tool{Name: name, Source: "missing"}
}

func firstTool(name string, candidates []string) Tool {
	configuredRoots := configuredToolRoots()
	for _, candidate := range candidates {
		if !hostCandidate(candidate) {
			continue
		}
		if filepath.IsAbs(candidate) || strings.ContainsAny(candidate, `/\`) {
			if tool := projectTool(name, candidate); tool.Available {
				return tool
			}
			continue
		}
		for _, root := range configuredRoots {
			if tool := fileTool(name, filepath.Join(root, candidate), "configured"); tool.Available {
				return tool
			}
		}
		if resolved, err := exec.LookPath(candidate); err == nil {
			absolute, _ := filepath.Abs(resolved)
			return Tool{Name: name, Available: true, Path: filepath.Clean(absolute), Source: "path"}
		}
	}
	return Tool{Name: name, Source: "missing"}
}

func configuredTool(name string, candidates []string) Tool {
	roots := configuredToolRoots()
	for _, candidate := range candidates {
		if !hostCandidate(candidate) {
			continue
		}
		if filepath.IsAbs(candidate) || strings.ContainsAny(candidate, `/\\`) {
			if tool := fileTool(name, candidate, "configured"); tool.Available {
				return tool
			}
			continue
		}
		for _, root := range roots {
			if tool := fileTool(name, filepath.Join(root, candidate), "configured"); tool.Available {
				return tool
			}
		}
	}
	return Tool{Name: name, Source: "missing"}
}

func firstAvailableTool(name string, candidates ...Tool) Tool {
	for _, candidate := range candidates {
		if candidate.Available {
			return candidate
		}
	}
	return Tool{Name: name, Source: "missing"}
}

func configuredToolRoots() []string {
	raw := strings.TrimSpace(os.Getenv("REVERSERESEARCH_TOOLS"))
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, string(os.PathListSeparator))
	seen := map[string]bool{}
	roots := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		absolute, err := filepath.Abs(part)
		if err != nil {
			continue
		}
		absolute = filepath.Clean(absolute)
		key := strings.ToLower(absolute)
		if seen[key] {
			continue
		}
		seen[key] = true
		roots = append(roots, absolute)
	}
	return roots
}

func fileTool(name, path, source string) Tool {
	if !hostCandidate(path) {
		return Tool{Name: name, Source: "unsupported-host"}
	}
	info, err := os.Stat(path)
	if err == nil && !info.IsDir() && (runtime.GOOS == "windows" || info.Mode().Perm()&0111 != 0) {
		absolute, _ := filepath.Abs(path)
		return Tool{Name: name, Available: true, Path: filepath.Clean(absolute), Source: source}
	}
	return Tool{Name: name, Source: "missing"}
}

func hostCandidate(path string) bool {
	if runtime.GOOS == "windows" {
		return true
	}
	ext := strings.ToLower(filepath.Ext(path))
	return ext != ".exe" && ext != ".bat" && ext != ".cmd"
}
