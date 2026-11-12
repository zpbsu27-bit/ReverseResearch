package backend

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"reverseresearch/internal/recordio"
	"reverseresearch/internal/securefile"
)

type xdbgConfig struct {
	IPAddress string `json:"IpAddress"`
	Port      int    `json:"Port"`
	AutoStart bool   `json:"AutoStart"`
	AuthToken string `json:"AuthToken"`
}

type xdbgRuntimeSpec struct {
	Bits       int
	Name       string
	Base       string
	PluginPath string
	StateDir   string
	LogName    string
}

func NewX32DBG(root string) *Lazy {
	return NewXDBG(root, 32)
}

func NewXDBG(root string, bits int) *Lazy {
	spec, specErr := xdbgSpec(root, bits)
	name := "xdbg"
	if specErr == nil {
		name = spec.Name
	}
	return NewLazy(name, func(ctx context.Context) (*mcp.ClientSession, func() error, error) {
		if err := xdbgHostError(); err != nil {
			return nil, nil, err
		}
		if specErr != nil {
			return nil, nil, specErr
		}
		cfg, err := ensureXDBGConfig(root, spec)
		if err != nil {
			return nil, nil, err
		}

		address := fmt.Sprintf("127.0.0.1:%d", cfg.Port)
		if conn, dialErr := net.DialTimeout("tcp", address, 250*time.Millisecond); dialErr == nil {
			closeErr := conn.Close()
			return nil, nil, errors.Join(fmt.Errorf("%s MCP port %s is already in use", spec.Name, address), closeErr)
		}

		tempDir := filepath.Join(root, "state", "tmp")
		if err := os.MkdirAll(spec.StateDir, 0o755); err != nil {
			return nil, nil, err
		}
		if err := os.MkdirAll(tempDir, 0o755); err != nil {
			return nil, nil, err
		}
		logFile, err := openLog(root, spec.LogName)
		if err != nil {
			return nil, nil, err
		}
		cmd := hiddenCommand(
			filepath.Join(spec.Base, "headless.exe"),
			"-userdir", spec.StateDir,
			"-plugin", spec.PluginPath,
		)
		cmd.Dir = spec.Base
		cmd.Env = append(os.Environ(), "TEMP="+tempDir, "TMP="+tempDir)
		cmd.Stdout = logFile
		cmd.Stderr = logFile
		scope, err := prepareBackendProcess(cmd)
		if err != nil {
			return nil, nil, errors.Join(err, logFile.Close())
		}
		stdinReader, stdinWriter := io.Pipe()
		cmd.Stdin = stdinReader
		if err := cmd.Start(); err != nil {
			cleanupErr := errors.Join(stdinReader.Close(), stdinWriter.Close(), scope.abort(logFile, false))
			return nil, nil, errors.Join(fmt.Errorf("start %s backend: %w", spec.Name, err), cleanupErr)
		}
		processStop, err := scope.claim(logFile, true)
		if err != nil {
			return nil, nil, errors.Join(
				fmt.Errorf("own %s backend process tree: %w", spec.Name, err),
				stdinWriter.Close(), stdinReader.Close(),
			)
		}
		cleanup := func() error {
			return errors.Join(stdinWriter.Close(), stdinReader.Close(), processStop())
		}
		if err := waitTCP(ctx, address, 12*time.Second, cmd); err != nil {
			return nil, nil, errors.Join(err, cleanup())
		}

		client := mcp.NewClient(&mcp.Implementation{
			Name: "reverse-research-xdbg-client", Version: "0.1.0",
		}, nil)
		session, err := client.Connect(ctx, &mcp.StreamableClientTransport{
			Endpoint:             "http://" + address + "/mcp",
			HTTPClient:           bearerClient(cfg.AuthToken),
			DisableStandaloneSSE: true,
		}, nil)
		if err != nil {
			return nil, nil, errors.Join(fmt.Errorf("connect %s MCP: %w", spec.Name, err), cleanup())
		}
		return session, cleanup, nil
	})
}

func xdbgSpec(root string, bits int) (xdbgRuntimeSpec, error) {
	var dir, name, plugin, stateDir, logName string
	switch bits {
	case 32:
		dir = "x32"
		name = "x32dbg"
		plugin = "x64dbg-MCP-Server.dp32"
		stateDir = filepath.Join(root, "state", "x32dbg")
		logName = "x32dbg.log"
	case 64:
		dir = "x64"
		name = "x64dbg"
		plugin = "x64dbg-MCP-Server.dp64"
		stateDir = filepath.Join(root, "state", "x64dbg")
		logName = "x64dbg.log"
	default:
		return xdbgRuntimeSpec{}, fmt.Errorf("unsupported xdbg architecture width %d", bits)
	}
	base := filepath.Join(root, "runtime", "x32dbg", "release", dir)
	return xdbgRuntimeSpec{
		Bits: bits, Name: name, Base: base,
		PluginPath: filepath.Join(base, "plugins", plugin),
		StateDir:   stateDir, LogName: logName,
	}, nil
}

func ensureXDBGConfig(root string, spec xdbgRuntimeSpec) (xdbgConfig, error) {
	path := filepath.Join(spec.Base, "mcp_config.json")
	body, err := os.ReadFile(path)
	if err == nil {
		if err := securefile.RestrictFile(path); err != nil {
			return xdbgConfig{}, fmt.Errorf("restrict %s MCP config: %w", spec.Name, err)
		}
		cfg, err := decodeXDBGConfig(body)
		if err != nil {
			return xdbgConfig{}, fmt.Errorf("decode %s MCP config: %w", spec.Name, err)
		}
		if spec.Bits == 64 {
			if err := ensureDistinctXDBGPort(root, cfg.Port); err != nil {
				return xdbgConfig{}, err
			}
		}
		return cfg, nil
	}
	if !errors.Is(err, os.ErrNotExist) || spec.Bits != 64 {
		return xdbgConfig{}, fmt.Errorf("read %s MCP config: %w", spec.Name, err)
	}

	x32Spec, err := xdbgSpec(root, 32)
	if err != nil {
		return xdbgConfig{}, err
	}
	x32Path := filepath.Join(x32Spec.Base, "mcp_config.json")
	x32Body, err := os.ReadFile(x32Path)
	if err != nil {
		return xdbgConfig{}, fmt.Errorf("read x32dbg MCP config for x64 derivation: %w", err)
	}
	if err := securefile.RestrictFile(x32Path); err != nil {
		return xdbgConfig{}, fmt.Errorf("restrict x32dbg MCP config for x64 derivation: %w", err)
	}
	cfg, err := decodeXDBGConfig(x32Body)
	if err != nil {
		return xdbgConfig{}, fmt.Errorf("decode x32dbg MCP config for x64 derivation: %w", err)
	}
	if cfg.Port >= 65535 {
		return xdbgConfig{}, errors.New("cannot derive a distinct x64dbg MCP port")
	}
	cfg.Port++
	cfg.AutoStart = true
	tokenHash := sha256.Sum256([]byte("ReverseResearch:x64dbg:" + cfg.AuthToken))
	cfg.AuthToken = hex.EncodeToString(tokenHash[:])
	body, err = json.Marshal(cfg)
	if err != nil {
		return xdbgConfig{}, err
	}
	body = append(body, '\n')
	if err := recordio.WriteFile(path, body, 0o600); err != nil {
		return xdbgConfig{}, fmt.Errorf("write derived x64dbg MCP config: %w", err)
	}
	return cfg, nil
}

func ensureDistinctXDBGPort(root string, x64Port int) error {
	x32Spec, err := xdbgSpec(root, 32)
	if err != nil {
		return err
	}
	body, err := os.ReadFile(filepath.Join(x32Spec.Base, "mcp_config.json"))
	if err != nil {
		return fmt.Errorf("read x32dbg MCP config for port comparison: %w", err)
	}
	cfg, err := decodeXDBGConfig(body)
	if err != nil {
		return fmt.Errorf("decode x32dbg MCP config for port comparison: %w", err)
	}
	if cfg.Port == x64Port {
		return errors.New("x32dbg and x64dbg MCP ports must be distinct")
	}
	return nil
}

func decodeXDBGConfig(body []byte) (xdbgConfig, error) {
	var cfg xdbgConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		return xdbgConfig{}, err
	}
	if cfg.IPAddress != "127.0.0.1" || cfg.Port <= 0 || cfg.Port > 65535 || len(cfg.AuthToken) < 32 {
		return xdbgConfig{}, errors.New("xdbg MCP must use authenticated loopback with a valid port")
	}
	return cfg, nil
}
