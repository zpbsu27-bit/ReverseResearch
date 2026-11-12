package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/sync/semaphore"

	"reverseresearch/internal/backend"
	"reverseresearch/internal/buildversion"
	"reverseresearch/internal/catalog"
	researchcore "reverseresearch/internal/core"
	"reverseresearch/internal/modules"
)

const globalResourceCapacity int64 = 16

type Runtime struct {
	server         *mcp.Server
	resourceGate   *semaphore.Weighted
	modules        *modules.Runtime
	core           *researchcore.Service
	localToken     string
	localTokenPath string
	shutdownOnce   sync.Once
	shutdown       chan struct{}
	activity       runtimeActivity
}

func New(root string) (*Runtime, error) {
	service, err := researchcore.New(root)
	if err != nil {
		return nil, err
	}
	localToken, localTokenPath, err := loadOrCreateLocalToken(root)
	if err != nil {
		return nil, err
	}
	r := &Runtime{
		server: mcp.NewServer(&mcp.Implementation{
			Name:        "reverse-research",
			Title:       "Reverse Research",
			Description: "Optional MCP adapter for the local-first ReverseResearch Core and lazy x32dbg, Ghidra, and radare2 backends.",
			Version:     buildversion.Version,
		}, nil),
		resourceGate:   semaphore.NewWeighted(globalResourceCapacity),
		modules:        modules.New(root),
		core:           service,
		localToken:     localToken,
		localTokenPath: localTokenPath,
		shutdown:       make(chan struct{}),
	}
	r.addStatusTool()
	r.addHostTools()
	r.addP0Tools()
	r.addP0ExtendedTools()
	r.addP0KnowledgeTools()
	r.addResearchWorkflowTools()
	r.addP1SecurityTools()
	r.addP1ResearchTools()
	r.addP2SecurityTools()
	r.addP3ProductTools()
	r.addWebTools()
	r.addApplicationTools()
	r.addAndroidTools()
	for _, spec := range []struct {
		catalog string
		prefix  string
		backend string
	}{
		{"x32dbg", "x32dbg_", "x32dbg"},
		{"ghidra", "ghidra_", "ghidra"},
		{"r2", "r2_", "r2"},
	} {
		if err := r.addBackendTools(spec.catalog, spec.prefix, spec.backend); err != nil {
			return nil, err
		}
	}
	return r, nil
}

func (r *Runtime) addTool(tool *mcp.Tool, handler func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error)) {
	weight := resourceWeight(tool.Name)
	r.server.AddTool(tool, func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return r.callObservedTool(ctx, tool.Name, weight, request, handler)
	})
}

func resourceWeight(name string) int64 {
	name = strings.ToLower(strings.TrimSpace(name))
	switch {
	case name == "app_android_recover", name == "app_evm_inspect":
		return globalResourceCapacity
	case strings.Contains(name, "memscan"),
		strings.Contains(name, "memory_scan"),
		strings.Contains(name, "pointermap"),
		strings.Contains(name, "pointer_map"):
		return globalResourceCapacity
	case strings.HasPrefix(name, "ghidra_"),
		strings.HasPrefix(name, "binary_diff_"),
		name == "function_migration_plan",
		name == "web_wasm_inspect",
		strings.HasPrefix(name, "app_"),
		strings.HasPrefix(name, "apple_"),
		strings.HasPrefix(name, "crash_core_"),
		strings.HasPrefix(name, "r2_"),
		strings.HasPrefix(name, "x32dbg_"),
		strings.Contains(name, "source_audit"),
		strings.Contains(name, "malware"),
		strings.Contains(name, "dfir"),
		strings.Contains(name, "sarif"),
		strings.Contains(name, "sbom"),
		strings.Contains(name, "attack_graph"),
		strings.Contains(name, "cloud_inventory"),
		strings.Contains(name, "stix"),
		strings.Contains(name, "firmware"),
		strings.Contains(name, "ios_"):
		return 8
	case strings.Contains(name, "patch"),
		strings.Contains(name, "hook"),
		strings.Contains(name, "web_"),
		strings.Contains(name, "android_"),
		strings.Contains(name, "protocol"):
		return 4
	case strings.Contains(name, "target_identify"),
		strings.Contains(name, "target_compare"),
		strings.Contains(name, "bindiff"),
		strings.Contains(name, "die_scan"),
		strings.Contains(name, "crash_record"),
		strings.Contains(name, "compatibility"):
		// These tools hash or re-hash whole target files, so they are disk and
		// CPU bound even though they are not analysis engines.
		return 4
	default:
		return 1
	}
}

func (r *Runtime) addStatusTool() {
	r.addTool(&mcp.Tool{
		Name:        "reverse_status",
		Description: "Show x32dbg, Ghidra, and radare2 module state without starting a backend.",
		InputSchema: map[string]any{
			"type":                 "object",
			"properties":           map[string]any{},
			"additionalProperties": false,
		},
	}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		statuses := r.statuses()
		body, _ := json.Marshal(statuses)
		return &mcp.CallToolResult{
			Content:           []mcp.Content{&mcp.TextContent{Text: string(body)}},
			StructuredContent: map[string]any{"backends": statuses},
		}, nil
	})
}

func (r *Runtime) addBackendTools(catalogName, prefix, backendName string) error {
	tools, err := catalog.Load(catalogName, prefix)
	if err != nil {
		return err
	}
	for _, tool := range tools {
		publicTool := tool
		originalName := strings.TrimPrefix(publicTool.Name, prefix)
		if backendName == "x32dbg" {
			decorateX32Tool(publicTool, originalName)
		}
		r.addTool(publicTool, func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if request == nil || request.Params == nil {
				return nil, fmt.Errorf("missing tool parameters")
			}
			return r.modules.Call(ctx, backendName, originalName, request.Params.Arguments)
		})
	}
	return nil
}

func decorateX32Tool(tool *mcp.Tool, originalName string) {
	switch modules.X32ToolPolicy(originalName) {
	case modules.X32Guarded:
		schema, _ := tool.InputSchema.(map[string]any)
		if schema == nil {
			schema = map[string]any{"type": "object"}
			tool.InputSchema = schema
		}
		properties, _ := schema["properties"].(map[string]any)
		if properties == nil {
			properties = map[string]any{}
			schema["properties"] = properties
		}
		properties[modules.X32GuardArgument] = modules.X32GuardJSONSchema()
		appendSchemaRequired(schema, modules.X32GuardArgument)
		tool.Description += " ReverseResearch requires _rr_guard with pid, process_key, owner, lease_id, and operation_id; uncertain mutations are never replayed."
	case modules.X32Blocked:
		tool.Description += " ReverseResearch blocks this low-level tool because it can create or retarget a debugger session outside the typed process-lease boundary."
	}
}

func appendSchemaRequired(schema map[string]any, name string) {
	switch required := schema["required"].(type) {
	case []any:
		for _, value := range required {
			if value == name {
				return
			}
		}
		schema["required"] = append(required, name)
	case []string:
		for _, value := range required {
			if value == name {
				return
			}
		}
		schema["required"] = append(required, name)
	default:
		schema["required"] = []string{name}
	}
}

func (r *Runtime) statuses() []backend.Status {
	return r.modules.Statuses()
}

func (r *Runtime) Run(ctx context.Context, transport mcp.Transport) error {
	return r.server.Run(ctx, transport)
}

func (r *Runtime) LocalAuthPath() string {
	return r.localTokenPath
}

func (r *Runtime) ShutdownRequested() <-chan struct{} {
	return r.shutdown
}

func (r *Runtime) Handler() http.Handler {
	mux := http.NewServeMux()
	mcpHandler := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return r.server },
		&mcp.StreamableHTTPOptions{
			JSONResponse:                 true,
			PropagateRequestCancellation: true,
			MaxRequestBodyBytes:          8 << 20,
		},
	)
	mux.Handle("/mcp", requireLocalBearer(r.localToken, mcpHandler))
	mux.Handle("/control/shutdown", requireLocalBearer(r.localToken, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if request.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.shutdownOnce.Do(func() { close(r.shutdown) })
		w.WriteHeader(http.StatusAccepted)
	})))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		writeHTTPJSON(w, map[string]any{
			"ok":       true,
			"version":  buildversion.Version,
			"service":  "ReverseResearch",
			"backends": r.statuses(),
		})
	})
	return r.observeHTTP(mux)
}

func (r *Runtime) CloseContext(ctx context.Context) error {
	return r.modules.CloseContext(ctx)
}

func (r *Runtime) Close() error {
	return r.modules.Close()
}
