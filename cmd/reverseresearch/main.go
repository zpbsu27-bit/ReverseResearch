package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	tunnelclient "github.com/openai/tunnel-client"

	"reverseresearch/internal/consolelog"
	reverseserver "reverseresearch/internal/server"
)

const (
	tunnelIDEnv      = "REVERSE_TUNNEL_ID"
	tunnelKeyEnv     = "CONTROL_PLANE_API_KEY"
	tunnelKeyFileEnv = "REVERSE_TUNNEL_API_KEY_FILE"
)

type tunnelFileConfig struct {
	TunnelID   string `json:"tunnel_id"`
	APIKeyFile string `json:"api_key_file"`
}

func main() {
	consolelog.SetTitle("ReverseResearch")
	cleanupStaleBuildBackup()
	args := startupArguments(os.Args[0], os.Args[1:])
	if err := runMain(context.Background(), discoverRoot(), args, os.Stdout, os.Stderr); err != nil {
		consolelog.SetTitle("ReverseResearch | ERROR")
		consolelog.Eventf(consolelog.ColorRed, "服务", "%v", err)
		os.Exit(1)
	}
}

func startupArguments(program string, args []string) []string {
	if len(args) == 0 && strings.EqualFold(filepath.Base(program), "ReverseResearch-MCP.exe") {
		return []string{"serve"}
	}
	return args
}

func runMain(ctx context.Context, root string, args []string, stdout, stderr io.Writer) error {
	return runCLI(ctx, root, args, stdout, stderr)
}

func runServe(parent context.Context, root string, args []string) (resultErr error) {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	var listen string
	var tunnelEnabled bool
	var tunnelID string
	flags.StringVar(&listen, "listen", "127.0.0.1:19100", "local MCP listen address")
	flags.BoolVar(&tunnelEnabled, "tunnel", false, "enable OpenAI Secure MCP Tunnel")
	flags.StringVar(&tunnelID, "tunnel-id", "", "OpenAI Secure MCP tunnel ID")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected serve arguments: %s", strings.Join(flags.Args(), " "))
	}
	if err := validateLoopbackListen(listen); err != nil {
		return err
	}
	if !tunnelEnabled && strings.TrimSpace(tunnelID) != "" {
		return errors.New("--tunnel-id requires --tunnel")
	}

	absolute, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	root = absolute

	var apiKey string
	if tunnelEnabled {
		tunnelID, apiKey, err = loadTunnelCredential(root, tunnelID)
		if err != nil {
			return err
		}
		if tunnelID == "" {
			return fmt.Errorf("--tunnel requires a tunnel ID via config/tunnel.json, %s, or --tunnel-id", tunnelIDEnv)
		}
		if apiKey == "" {
			return fmt.Errorf("%s or a configured API key file is required for tunnel %s", tunnelKeyEnv, tunnelID)
		}
	}

	ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer stop()

	consolelog.Eventf(consolelog.ColorStatus, "启动", "ReverseResearch MCP | PID %d | 正在初始化", os.Getpid())
	runtime, err := reverseserver.New(root)
	if err != nil {
		return err
	}
	listening := false
	defer func() {
		// Match Runtime.Close/backendCloseTimeout so the outer process does not
		// cut off the drain budget before the backends can use it.
		closeCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if listening {
			consolelog.Event(consolelog.ColorStatus, "停止", "正在关闭惰性后端，最多等待 30 秒")
		}
		resultErr = errors.Join(resultErr, runtime.CloseContext(closeCtx))
		if listening && resultErr == nil {
			consolelog.SetTitle("ReverseResearch MCP | STOPPED")
			consolelog.Event(consolelog.ColorGreen, "停止", "HTTP 服务与后端已关闭")
		}
	}()

	consolelog.Event(consolelog.ColorWhite, "MCP", "x32dbg + Ghidra + radare2 + Core | 后端按需启动")
	consolelog.Eventf(consolelog.ColorWhite, "AUTH", "本地 bearer 令牌文件：%s", runtime.LocalAuthPath())
	consolelog.Event(consolelog.ColorWhite, "日志", "窗口实时显示请求、工具排队/执行/返回和耗时；每 30 秒显示运行摘要")
	consolelog.Event(consolelog.ColorWhite, "操作", "按 Ctrl+C 停止；使用 serve --tunnel 启用已配置的 ChatGPT 隧道")

	var tunnel *tunnelclient.Client
	var tunnelLog *consolelog.TunnelLog
	if tunnelEnabled {
		network := newTunnelNetwork(func(route string) {
			consolelog.Eventf(consolelog.ColorStatus, "TUNNEL", "当前连接路径：%s", route)
		})
		tunnelLog = consolelog.TunnelWriter()
		serverTransport, tunnelTransport := mcp.NewInMemoryTransports()
		go func() {
			if err := runtime.Run(ctx, serverTransport); err != nil && ctx.Err() == nil {
				consolelog.Eventf(consolelog.ColorRed, "MCP", "内嵌 MCP 服务异常停止：%v", err)
				stop()
			}
		}()

		tunnel, err = tunnelclient.New(tunnelclient.Config{
			TunnelID:                         tunnelID,
			APIKey:                           apiKey,
			PollTimeout:                      15 * time.Second,
			LogWriter:                        tunnelLog,
			ControlPlaneHTTPTransportAdapter: network.adapt,
		}, tunnelTransport)
		if err != nil {
			return fmt.Errorf("configure Secure MCP Tunnel: %w", err)
		}
		if err := tunnel.Start(ctx); err != nil {
			return fmt.Errorf("start Secure MCP Tunnel: %w", err)
		}
		defer func() {
			shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			resultErr = errors.Join(resultErr, tunnel.Stop(shutdown))
		}()
		consolelog.Eventf(consolelog.ColorStatus, "TUNNEL", "正在启动 Secure MCP Tunnel：%s", tunnelID)
		go func() {
			select {
			case <-tunnel.Ready():
				tunnelLog.ObserveReady()
				consolelog.Eventf(consolelog.ColorGreen, "TUNNEL", "Secure MCP Tunnel 首次轮询成功：%s；后续连接观测见隧道日志", tunnelID)
			case <-ctx.Done():
			}
		}()
	} else {
		consolelog.Event(consolelog.ColorDim, "TUNNEL", "未启用；当前提供本地 MCP")
	}

	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	listening = true

	httpServer := &http.Server{
		Handler:           runtime.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog:          log.New(consolelog.Writer("HTTP", consolelog.ColorRed), "", 0),
	}
	httpErr := make(chan error, 1)
	consolelog.SetTitle("ReverseResearch MCP | RUNNING | " + listener.Addr().String())
	consolelog.Eventf(consolelog.ColorGreen, "MCP", "Local endpoint ready: http://%s/mcp", listener.Addr())
	consolelog.Event(consolelog.ColorDim, "运行", "本地监听已就绪，等待客户端请求；绿色工具返回只表示协议层成功")
	go func() {
		if err := httpServer.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			httpErr <- err
			return
		}
		httpErr <- nil
	}()

	started := time.Now()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
serveLoop:
	for {
		select {
		case <-ctx.Done():
			consolelog.Event(consolelog.ColorStatus, "停止", "收到退出信号，正在停止 HTTP 服务")
			break serveLoop
		case <-runtime.ShutdownRequested():
			consolelog.Event(consolelog.ColorStatus, "停止", "收到已认证的关闭请求，正在停止 HTTP 服务")
			stop()
			break serveLoop
		case err := <-httpErr:
			if err != nil {
				return fmt.Errorf("local MCP server: %w", err)
			}
			break serveLoop
		case <-ticker.C:
			activity := runtime.Activity()
			tunnelSummary := "隧道：未启用"
			if tunnelLog != nil {
				tunnelSummary = tunnelLog.Snapshot().Summary()
			}
			consolelog.Eventf(consolelog.ColorDim, "运行",
				"进程运行 %s | HTTP %d（处理中 %d）| 工具 %d（排队 %d / 执行 %d）| 协议成功 %d / 错误 %d / 取消 %d | %s",
				time.Since(started).Round(time.Second), activity.Requests, activity.HTTPActive,
				activity.Calls, activity.Queued, activity.Running, activity.Succeeded, activity.Failed, activity.Cancelled, tunnelSummary)
		}
	}

	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdown); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("shutdown local MCP server: %w", err)
	}
	return nil
}

func validateLoopbackListen(value string) error {
	host, _, err := net.SplitHostPort(strings.TrimSpace(value))
	if err != nil {
		return fmt.Errorf("invalid --listen address %q: %w", value, err)
	}
	host = strings.TrimSpace(host)
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("--listen must use a loopback address; got %q", value)
	}
	return nil
}

func loadTunnelCredential(root, explicitTunnelID string) (string, string, error) {
	tunnelID := strings.TrimSpace(explicitTunnelID)
	if tunnelID == "" {
		tunnelID = strings.TrimSpace(os.Getenv(tunnelIDEnv))
	}
	apiKey := strings.TrimSpace(os.Getenv(tunnelKeyEnv))
	apiKeyFile := strings.TrimSpace(os.Getenv(tunnelKeyFileEnv))

	configPath := filepath.Join(root, "config", "tunnel.json")
	if body, err := os.ReadFile(configPath); err == nil {
		var cfg tunnelFileConfig
		if err := json.Unmarshal(body, &cfg); err != nil {
			return "", "", fmt.Errorf("decode %s: %w", configPath, err)
		}
		if tunnelID == "" {
			tunnelID = strings.TrimSpace(cfg.TunnelID)
		}
		if apiKeyFile == "" {
			apiKeyFile = strings.TrimSpace(cfg.APIKeyFile)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", "", fmt.Errorf("read %s: %w", configPath, err)
	}

	if apiKey == "" && apiKeyFile != "" {
		expanded := os.ExpandEnv(apiKeyFile)
		body, err := os.ReadFile(expanded)
		if err != nil {
			return "", "", fmt.Errorf("read tunnel API key file %s: %w", expanded, err)
		}
		apiKey = strings.TrimSpace(string(body))
	}
	return tunnelID, apiKey, nil
}

func cleanupStaleBuildBackup() {
	executable, err := os.Executable()
	if err != nil {
		return
	}
	_ = os.Remove(executable + "~")
}

func discoverRoot() string {
	exe, err := os.Executable()
	if err == nil {
		if root := rootFromExecutable(exe); root != "" {
			return root
		}
	}
	if cwd, err := os.Getwd(); err == nil {
		return cwd
	}
	return "."
}

func rootFromExecutable(exe string) string {
	for dir := filepath.Dir(exe); ; dir = filepath.Dir(dir) {
		if info, err := os.Stat(filepath.Join(dir, "config", "routes.json")); err == nil && info.Mode().IsRegular() {
			return dir
		}
		if filepath.Dir(dir) == dir {
			return ""
		}
	}
}
