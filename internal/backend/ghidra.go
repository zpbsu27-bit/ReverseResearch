package backend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"reverseresearch/internal/securefile"
)

type ghidraDaemonState struct {
	PID   int    `json:"pid"`
	Host  string `json:"host"`
	Port  int    `json:"port"`
	Token string `json:"token"`
}

const (
	ghidraPythonABI    = "3.14"
	ghidraUCRT64Python = `C:\msys64\ucrt64\bin\python.exe`
	defaultGhidraPort  = 19096
)

type GhidraLaunchOptions struct {
	Port        int
	StateDir    string
	EvidenceDir string
}

func resolveGhidraLaunchOptions(root string, options GhidraLaunchOptions) (GhidraLaunchOptions, error) {
	if options.Port == 0 {
		options.Port = defaultGhidraPort
	}
	if options.Port < 1024 || options.Port > 65535 {
		return GhidraLaunchOptions{}, fmt.Errorf("ghidra MCP port must be between 1024 and 65535")
	}
	if strings.TrimSpace(options.StateDir) == "" {
		options.StateDir = filepath.Join(root, "state")
	} else {
		absolute, err := filepath.Abs(options.StateDir)
		if err != nil {
			return GhidraLaunchOptions{}, fmt.Errorf("resolve ghidra state directory: %w", err)
		}
		options.StateDir = absolute
	}
	if hasDotPrefixedPathElement(options.StateDir) {
		return GhidraLaunchOptions{}, fmt.Errorf("ghidra project state path cannot contain a dot-prefixed path element: %s", options.StateDir)
	}
	if strings.TrimSpace(options.EvidenceDir) == "" {
		options.EvidenceDir = filepath.Join(root, "evidence")
	} else {
		absolute, err := filepath.Abs(options.EvidenceDir)
		if err != nil {
			return GhidraLaunchOptions{}, fmt.Errorf("resolve ghidra evidence directory: %w", err)
		}
		options.EvidenceDir = absolute
	}
	return options, nil
}

func hasDotPrefixedPathElement(path string) bool {
	cleaned := filepath.Clean(path)
	volume := filepath.VolumeName(cleaned)
	if volume != "" {
		cleaned = strings.TrimPrefix(cleaned, volume)
	}
	parts := strings.FieldsFunc(cleaned, func(r rune) bool { return r == '/' || r == '\\' })
	for _, part := range parts {
		if strings.HasPrefix(part, ".") {
			return true
		}
	}
	return false
}

func ghidraPythonCandidates(root string) []string {
	if runtime.GOOS == "linux" {
		return []string{filepath.Join(root, "runtime", "ghidra", "python-env", "bin", "python"), "/usr/bin/python3"}
	}
	return []string{filepath.Clean(ghidraUCRT64Python)}
}

func ghidraHostPythonABI() string {
	if runtime.GOOS == "linux" {
		return "3.13"
	}
	return ghidraPythonABI
}

func ghidraSystemSitePackages(python string) string {
	prefix := filepath.Dir(filepath.Dir(filepath.Clean(python)))
	return filepath.Join(prefix, "lib", "python"+ghidraHostPythonABI(), "site-packages")
}

func resolveGhidraPython(root string) (string, error) {
	for _, candidate := range ghidraPythonCandidates(root) {
		info, err := os.Stat(candidate)
		if err != nil || info.IsDir() {
			continue
		}
		probe := exec.Command(candidate, "-I", "-c", "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
		output, err := probe.Output()
		if err == nil && strings.TrimSpace(string(output)) == ghidraHostPythonABI() {
			return filepath.Clean(candidate), nil
		}
	}
	if runtime.GOOS == "linux" {
		return "", fmt.Errorf("native Linux Ghidra profile requires CPython %s", ghidraHostPythonABI())
	}
	return "", fmt.Errorf("ghidra requires MSYS2 UCRT64 CPython %s at %s", ghidraPythonABI, ghidraUCRT64Python)
}

func ghidraPythonPrelude(sitePackages string) string {
	bundle := filepath.ToSlash(sitePackages)
	if runtime.GOOS == "linux" {
		return fmt.Sprintf("import sys,pathlib,sysconfig; assert sys.platform=='linux' and sys.version_info[:2]==(3,13), 'native Linux Ghidra Python ABI mismatch'; soabi=sysconfig.get_config_var('SOABI') or ''; assert 'x86_64-linux-gnu' in soabi, 'Ghidra requires native Linux Python'; p=pathlib.Path(%q).resolve(); sys.path.append(str(p)); import mcp,re_mcp,re_mcp_ghidra,jpype,pyghidra,_jpype; bundled=(mcp,re_mcp,re_mcp_ghidra,pyghidra,jpype,_jpype); bad=[m.__name__ for m in bundled if p not in pathlib.Path(m.__file__).resolve().parents]; assert not bad, 'native bundled package origin mismatch: '+','.join(bad); ", bundle)
	}
	return fmt.Sprintf("import sys,pathlib,sysconfig; assert sys.version_info[:2]==(3,14), 'Ghidra Python ABI mismatch'; soabi=sysconfig.get_config_var('SOABI') or ''; assert 'mingw_x86_64_ucrt_gnu' in soabi, 'Ghidra requires MSYS2 UCRT64 Python'; p=pathlib.Path(%q).resolve(); sys.path.append(str(p)); import mcp,re_mcp,re_mcp_ghidra,jpype,pyghidra,_jpype; bundled=(mcp,re_mcp,re_mcp_ghidra,pyghidra); bad=[m.__name__ for m in bundled if p not in pathlib.Path(m.__file__).resolve().parents]; assert not bad, 'bundled package origin mismatch: '+','.join(bad); assert p not in pathlib.Path(jpype.__file__).resolve().parents, 'JPype must come from UCRT64 system site'; ", bundle)
}

func ghidraWorkerEnvironment(env []string, python, sitePackages string) []string {
	value := "PYTHONPATH=" + ghidraSystemSitePackages(python) + string(os.PathListSeparator) + sitePackages
	for i, item := range env {
		if strings.HasPrefix(strings.ToUpper(item), "PYTHONPATH=") {
			env[i] = value
			return env
		}
	}
	return append(env, value)
}

func validateGhidraPython(ctx context.Context, python, sitePackages string) error {
	// Cold bytecode caches and concurrent local tools can make trusted imports
	// slower. Keep the probe bounded and always respect an earlier caller limit.
	probeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(probeCtx, python, "-I", "-c", ghidraPythonPrelude(sitePackages)+"print('rr-ghidra-python-ok')")
	output, err := cmd.CombinedOutput()
	if err != nil {
		if probeCtx.Err() != nil {
			err = probeCtx.Err()
		}
		return fmt.Errorf("ghidra Python preflight failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	if !strings.Contains(string(output), "rr-ghidra-python-ok") {
		return fmt.Errorf("ghidra Python preflight returned unexpected output: %s", strings.TrimSpace(string(output)))
	}
	return nil
}

func NewGhidra(root string) *Lazy {
	return NewGhidraWithOptions(root, GhidraLaunchOptions{})
}

func NewGhidraIsolated(root, stateDir, evidenceDir string, port int) *Lazy {
	return NewGhidraWithOptions(root, GhidraLaunchOptions{
		Port: port, StateDir: stateDir, EvidenceDir: evidenceDir,
	})
}

func connectExistingGhidraDaemon(ctx context.Context, stateDir string, port int) (*mcp.ClientSession, error) {
	stateFile := filepath.Join(stateDir, "re-mcp-ghidra", "daemon.json")
	stateRoot := filepath.Dir(stateFile)
	if err := securefile.RestrictDir(stateRoot); err != nil {
		return nil, fmt.Errorf("restrict existing ghidra daemon state directory: %w", err)
	}
	if err := securefile.RestrictFile(stateFile); err != nil {
		return nil, fmt.Errorf("restrict existing ghidra daemon state: %w", err)
	}
	body, err := os.ReadFile(stateFile)
	if err != nil {
		return nil, fmt.Errorf("read existing ghidra daemon state: %w", err)
	}
	var daemon ghidraDaemonState
	if err := json.Unmarshal(body, &daemon); err != nil {
		return nil, fmt.Errorf("decode existing ghidra daemon state: %w", err)
	}
	if daemon.PID <= 0 || daemon.Host != "127.0.0.1" || daemon.Port != port || strings.TrimSpace(daemon.Token) == "" {
		return nil, errors.New("existing ghidra daemon state does not match the occupied loopback endpoint")
	}
	address := fmt.Sprintf("%s:%d", daemon.Host, daemon.Port)
	client := mcp.NewClient(&mcp.Implementation{
		Name: "reverse-research-ghidra-adopter", Version: "0.1.0",
	}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:             "http://" + address + "/mcp",
		HTTPClient:           bearerClient(daemon.Token),
		DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("authenticate existing ghidra daemon: %w", err)
	}
	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("probe existing ghidra daemon tools: %w", err), session.Close())
	}
	required := map[string]bool{"list_databases": false, "get_database_info": false}
	for _, tool := range tools.Tools {
		if _, ok := required[tool.Name]; ok {
			required[tool.Name] = true
		}
	}
	for name, present := range required {
		if !present {
			return nil, errors.Join(
				fmt.Errorf("existing ghidra daemon is missing required tool %q", name),
				session.Close(),
			)
		}
	}
	return session, nil
}
func NewGhidraWithOptions(root string, launchOptions GhidraLaunchOptions) *Lazy {
	return NewLazy("ghidra", func(ctx context.Context) (*mcp.ClientSession, func() error, error) {
		options, err := resolveGhidraLaunchOptions(root, launchOptions)
		if err != nil {
			return nil, nil, err
		}
		if err := syncGhidraRuntimeSources(root); err != nil {
			return nil, nil, err
		}
		runtimeRoot := filepath.Join(root, "runtime", "ghidra")
		sitePackages := filepath.Join(runtimeRoot, "python-packages")
		ghidraHome := filepath.Join(runtimeRoot, "app")
		javaHome := filepath.Join(runtimeRoot, "java", "jdk-21.0.12.1+1")
		if runtime.GOOS == "linux" {
			javaHome = filepath.Join(runtimeRoot, "java", "native")
			for _, name := range []string{"java", "javac"} {
				info, err := os.Stat(filepath.Join(javaHome, "bin", name))
				if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
					return nil, nil, fmt.Errorf("native Linux Ghidra requires an executable JDK profile: runtime/ghidra/java/native/bin/%s", name)
				}
			}
		}
		python, err := resolveGhidraPython(root)
		if err != nil {
			return nil, nil, err
		}
		if err := validateGhidraPython(ctx, python, sitePackages); err != nil {
			return nil, nil, err
		}

		port := options.Port
		address := fmt.Sprintf("127.0.0.1:%d", port)
		stateDir := options.StateDir
		if conn, dialErr := net.DialTimeout("tcp", address, 250*time.Millisecond); dialErr == nil {
			if closeErr := conn.Close(); closeErr != nil {
				return nil, nil, fmt.Errorf("close Ghidra port probe: %w", closeErr)
			}
			session, adoptErr := connectExistingGhidraDaemon(ctx, stateDir, port)
			if adoptErr != nil {
				return nil, nil, fmt.Errorf("ghidra MCP port %s is already in use and existing daemon adoption failed: %w", address, adoptErr)
			}
			// The adopted daemon is intentionally not process-owned by this Runtime.
			// Closing this client session must not terminate a daemon that may still
			// carry open analysis databases from a previous ReverseResearch process.
			return session, func() error { return nil }, nil
		}

		tempDir := filepath.Join(stateDir, "tmp")
		projectDir := filepath.Join(stateDir, "ghidra", "projects")
		logDir := filepath.Join(options.EvidenceDir, "ghidra")
		for _, dir := range []string{stateDir, tempDir, projectDir, logDir} {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return nil, nil, err
			}
		}

		bootstrap := ghidraPythonPrelude(sitePackages) + "from re_mcp_ghidra._cli import main; main()"
		cmd := hiddenCommand(
			python,
			"-I", "-c", bootstrap,
			"--backend", "ghidra",
			"serve",
			"--host", "127.0.0.1",
			"--port", fmt.Sprint(port),
			"--idle-timeout", "0",
		)
		cmd.Dir = root
		env := os.Environ()
		env = append(env,
			"GHIDRA_INSTALL_DIR="+ghidraHome,
			"JAVA_HOME="+javaHome,
			"JAVA_TOOL_OPTIONS=-Duser.home="+filepath.ToSlash(stateDir)+" -Djava.io.tmpdir="+filepath.ToSlash(tempDir),
			"TEMP="+tempDir,
			"TMP="+tempDir,
			"LOCALAPPDATA="+stateDir,
			"RE_MCP_LOG_DIR="+logDir,
			"RE_MCP_GHIDRA_PROJECT_ROOT="+projectDir,
			"PYTHONDONTWRITEBYTECODE=1",
			"PYTHONUTF8=1",
		)
		if runtime.GOOS == "linux" {
			env = append(env, "XDG_STATE_HOME="+stateDir, "XDG_CACHE_HOME="+filepath.Join(stateDir, "cache"), "TMPDIR="+tempDir)
		}
		// The parent runs with -I and therefore ignores PYTHONPATH. Worker
		// subprocesses do not use -I; they need the bundled package root in
		// their inherited environment so "python -m re_mcp_ghidra.server"
		// resolves the same verified bundle.
		env = ghidraWorkerEnvironment(env, python, sitePackages)
		cmd.Env = prependPath(env, filepath.Join(javaHome, "bin"))
		logFile, err := openLogAt(options.EvidenceDir, "ghidra.log")
		if err != nil {
			return nil, nil, err
		}
		cmd.Stdout = logFile
		cmd.Stderr = logFile
		scope, err := prepareBackendProcess(cmd)
		if err != nil {
			return nil, nil, errors.Join(err, logFile.Close())
		}
		if err := cmd.Start(); err != nil {
			return nil, nil, errors.Join(fmt.Errorf("start ghidra backend: %w", err), scope.abort(logFile, false))
		}
		cleanup, err := scope.claim(logFile, true)
		if err != nil {
			return nil, nil, fmt.Errorf("own ghidra backend process tree: %w", err)
		}
		if err := waitTCP(ctx, address, 30*time.Second, cmd); err != nil {
			return nil, nil, errors.Join(err, cleanup())
		}

		stateFile := filepath.Join(stateDir, "re-mcp-ghidra", "daemon.json")
		var daemon ghidraDaemonState
		stateDeadline := time.Now().Add(5 * time.Second)
		for {
			stateBody, readErr := os.ReadFile(stateFile)
			if readErr == nil {
				var candidate ghidraDaemonState
				if json.Unmarshal(stateBody, &candidate) == nil &&
					candidate.Host == "127.0.0.1" &&
					candidate.Port == port &&
					candidate.Token != "" &&
					candidate.PID == cmd.Process.Pid {
					daemon = candidate
					break
				}
			}
			if time.Now().After(stateDeadline) {
				return nil, nil, errors.Join(
					fmt.Errorf("ghidra daemon state did not converge to the current process"),
					cleanup(),
				)
			}
			timer := time.NewTimer(50 * time.Millisecond)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				return nil, nil, errors.Join(ctx.Err(), cleanup())
			case <-timer.C:
			}
		}

		if err := securefile.RestrictDir(filepath.Dir(stateFile)); err != nil {
			return nil, nil, errors.Join(fmt.Errorf("restrict ghidra daemon state directory: %w", err), cleanup())
		}
		if err := securefile.RestrictFile(stateFile); err != nil {
			return nil, nil, errors.Join(fmt.Errorf("restrict ghidra daemon state: %w", err), cleanup())
		}

		client := mcp.NewClient(&mcp.Implementation{
			Name: "reverse-research-ghidra-client", Version: "0.1.0",
		}, nil)
		session, err := client.Connect(ctx, &mcp.StreamableClientTransport{
			Endpoint:             "http://" + address + "/mcp",
			HTTPClient:           bearerClient(daemon.Token),
			DisableStandaloneSSE: true,
		}, nil)
		if err != nil {
			return nil, nil, errors.Join(fmt.Errorf("connect ghidra MCP: %w", err), cleanup())
		}
		return session, cleanup, nil
	})
}
