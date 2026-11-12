package backend

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"reverseresearch/internal/toolindex"
)

func NewRadare2(root string) *Lazy {
	return NewLazy("radare2", func(ctx context.Context) (*mcp.ClientSession, func() error, error) {
		runtimeRoot := filepath.Join(root, "runtime", "radare2")
		exe := filepath.Join(runtimeRoot, "mcp", "r2mcp.exe")
		engineDir := filepath.Join(runtimeRoot, "engine", "radare2-6.2.2-w64", "bin")
		if runtime.GOOS == "linux" {
			index, err := toolindex.Scan(root)
			if err != nil {
				return nil, nil, err
			}
			mcpTool, mcpFound := index.ByName("r2mcp")
			engine, engineFound := index.ByName("radare2")
			if !mcpFound || !engineFound || !mcpTool.Available || !engine.Available {
				return nil, nil, errors.New("native Linux radare2/r2mcp not available in canonical ToolIndex")
			}
			exe, engineDir = mcpTool.Path, filepath.Dir(engine.Path)
		}
		args := []string{"-n", "-N", "-C", "structured"}
		for _, tool := range []string{
			"open_file", "close_file", "show_info", "analyze", "list_exports",
			"list_functions", "list_strings", "disassemble", "disassemble_function", "decompile_function", "xrefs_to",
		} {
			args = append(args, "-e", tool)
		}
		cmd := exec.Command(exe, args...)
		cmd.Dir = root
		cmd.Env = prependPath(os.Environ(), engineDir)
		if runtime.GOOS == "linux" {
			lib := filepath.Join(runtimeRoot, "engine", "usr", "lib")
			cmd.Env = append(cmd.Env, "LD_LIBRARY_PATH="+lib+":"+filepath.Join(lib, "radare2", "6.2.2"))
		}
		// stdout/stdout are the MCP channel, so only stderr can be captured.
		// Without this the child inherits ReverseResearch's own stderr, which is
		// never rotated and can block the child on a full, unread pipe.
		logFile, err := openLog(root, "radare2.log")
		if err != nil {
			return nil, nil, fmt.Errorf("open radare2 backend log: %w", err)
		}
		cmd.Stderr = logFile
		scope, err := prepareBackendProcess(cmd)
		if err != nil {
			return nil, nil, errors.Join(err, logFile.Close())
		}

		client := mcp.NewClient(&mcp.Implementation{
			Name: "reverse-research-radare2-client", Version: "0.1.0",
		}, nil)
		session, err := client.Connect(ctx, &r2PaginationTransport{Transport: &mcp.CommandTransport{
			Command:           cmd,
			TerminateDuration: 5 * time.Second,
		}}, nil)
		if err != nil {
			// The transport starts the child before the handshake, so a failed
			// Connect can leave a live process nobody owns yet.
			return nil, nil, errors.Join(fmt.Errorf("connect radare2 backend: %w", err), scope.abort(logFile, cmd.Process != nil))
		}
		// Windows attaches its Job after Connect; Linux was contained before
		// Start. In both cases the transport retains sole Wait ownership.
		cleanup, err := scope.claim(logFile, false)
		if err != nil {
			return nil, nil, errors.Join(fmt.Errorf("own radare2 backend process tree: %w", err), session.Close())
		}
		return session, cleanup, nil
	})
}
