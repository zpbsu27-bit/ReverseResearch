package server

import (
	"context"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"reverseresearch/internal/webinspect"
)

func (r *Runtime) addWebTools() {
	r.addHARViewTools()
	r.addTool(&mcp.Tool{
		Name:        "web_backend_status",
		Description: "List supported installed Chromium-family browser backends and the installed-only integration/redistribution policy. Does not launch or attach to a browser.",
		InputSchema: objectSchema(map[string]any{}),
	}, func(_ context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		result, err := r.core.WebBackends()
		if err != nil {
			return nil, err
		}
		return structuredResult(result)
	})

	r.addTool(&mcp.Tool{
		Name:        "web_profile_prepare",
		Description: "Create a ReverseResearch-owned isolated browser profile directory and return safe Chromium launch arguments using loopback CDP with an ephemeral port. Never reuses the daily browser profile and does not launch the browser.",
		InputSchema: objectSchema(map[string]any{
			"profile_id": map[string]any{"type": "string", "minLength": 1},
			"browser":    map[string]any{"type": "string", "enum": []string{"chrome", "msedge"}, "default": "chrome"},
		}, "profile_id"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			ProfileID string `json:"profile_id"`
			Browser   string `json:"browser"`
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		result, err := r.core.PrepareWebProfile(args.ProfileID, args.Browser)
		if err != nil {
			return nil, err
		}
		return structuredResult(result)
	})

	r.addTool(&mcp.Tool{
		Name:        "web_cdp_inspect",
		Description: "Read CDP /json/version and /json/list from an explicitly supplied loopback HTTP endpoint. This is read-only discovery and rejects remote/non-loopback endpoints.",
		InputSchema: objectSchema(map[string]any{
			"endpoint":   map[string]any{"type": "string", "minLength": 1},
			"timeout_ms": map[string]any{"type": "integer", "minimum": 1, "maximum": 15000, "default": 3000},
		}, "endpoint"),
	}, func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			Endpoint  string `json:"endpoint"`
			TimeoutMS int64  `json:"timeout_ms"`
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		timeout := webinspect.DefaultCDPTimeout
		if args.TimeoutMS > 0 {
			timeout = time.Duration(args.TimeoutMS) * time.Millisecond
		}
		result, err := r.core.InspectWebCDP(ctx, args.Endpoint, timeout)
		if err != nil {
			return nil, err
		}
		return structuredResult(result)
	})

	r.addTool(&mcp.Tool{
		Name:        "web_source_analyze",
		Description: "Hash a local JavaScript/CSS artifact, extract sourceMappingURL, and validate a local/inline classic or embedded indexed source-map v3 with a bounded inventory. Use web_source_map_locate for generated coordinates. Does not execute code or fetch remote content.",
		InputSchema: objectSchema(map[string]any{
			"path": map[string]any{"type": "string", "minLength": 1},
		}, "path"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			Path string `json:"path"`
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		result, err := r.core.AnalyzeWebSource(args.Path)
		if err != nil {
			return nil, err
		}
		return structuredResult(result)
	})

	r.addTool(&mcp.Tool{
		Name:        "web_source_map_read",
		Description: "Read a bounded UTF-8 byte page from one sourcesContent entry in a local classic or embedded indexed source-map v3. Indexed source indexes flatten in section order. Preserves unavailable versus empty; use expected_sha256 on subsequent pages. Source labels/section URLs are never opened or fetched; no code runs.",
		InputSchema: objectSchema(map[string]any{
			"path":            map[string]any{"type": "string", "minLength": 1},
			"source_index":    map[string]any{"type": "integer", "minimum": 0, "default": 0},
			"offset":          map[string]any{"type": "integer", "minimum": 0, "default": 0},
			"limit":           map[string]any{"type": "integer", "minimum": 4, "maximum": webinspect.MaxSourceReadBytes, "default": webinspect.DefaultSourceReadBytes},
			"expected_sha256": map[string]any{"type": "string", "pattern": "^[A-Fa-f0-9]{64}$"},
		}, "path"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			Path string `json:"path"`
			webinspect.SourceMapReadOptions
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		result, err := r.core.ReadWebSourceMap(args.Path, args.SourceMapReadOptions)
		if err != nil {
			return nil, err
		}
		return structuredResult(result)
	})

	r.addTool(&mcp.Tool{
		Name:        "web_har_inspect",
		Description: "Inspect a local historical HAR 1.2 as a bounded summary page. Retains producer ordinals/JSON pointers and SHA-256, validates all projected records before selection, and reports omitted entries/coverage. Excludes headers, cookies, bodies and URL query values; visible paths/query names are not generally secret-free. No requests are replayed and no browser starts. Use expected_sha256 across pages; this is not full HAR-schema validation or current runtime evidence.",
		InputSchema: objectSchema(map[string]any{
			"path":            map[string]any{"type": "string", "minLength": 1},
			"offset":          map[string]any{"type": "integer", "minimum": 0, "default": 0},
			"limit":           map[string]any{"type": "integer", "minimum": 1, "maximum": webinspect.MaxHARPageSize, "default": webinspect.DefaultHARPageSize},
			"expected_sha256": map[string]any{"type": "string", "pattern": "^[A-Fa-f0-9]{64}$"},
		}, "path"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			Path string `json:"path"`
			webinspect.HAROptions
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		result, err := r.core.InspectWebHAR(args.Path, args.HAROptions)
		if err != nil {
			return nil, err
		}
		return structuredResult(result)
	})

	r.addTool(&mcp.Tool{
		Name:        "web_sse_inspect",
		Description: "Inspect a retained local UTF-8 SSE body with CR/LF/CRLF and multi-line data framing. Returns event ordinals, original byte/line spans, data/ID digests, bounded pages and pending EOF data. Default omits data and raw IDs; optional data_preview_bytes exposes a bounded UTF-8 prefix that may contain secrets. Scans all input before returning; [DONE] and EOF never establish application success. Use expected_sha256 across pages. No network, replay, browser or tool execution.",
		InputSchema: objectSchema(map[string]any{
			"path":               map[string]any{"type": "string", "minLength": 1},
			"offset":             map[string]any{"type": "integer", "minimum": 0, "maximum": 100000, "default": 0},
			"limit":              map[string]any{"type": "integer", "minimum": 1, "maximum": webinspect.MaxSSEPageSize, "default": webinspect.DefaultSSEPageSize},
			"data_preview_bytes": map[string]any{"type": "integer", "minimum": 0, "maximum": webinspect.MaxSSEPreviewBytes, "default": 0},
			"expected_sha256":    map[string]any{"type": "string", "pattern": "^[A-Fa-f0-9]{64}$"},
		}, "path"),
	}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			Path string `json:"path"`
			webinspect.SSEOptions
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		result, err := r.core.InspectWebSSE(args.Path, args.SSEOptions)
		if err != nil {
			return nil, err
		}
		return structuredResult(result)
	})

	r.addTool(&mcp.Tool{
		Name:        "web_wasm_inspect",
		Description: "Read local WASM section/import/export boundaries. The default is partial structural inspection. Select use_wabt for WABT 1.0.42 --enable-all validation and bounded paged WAT or objdump details; tools must already exist in runtime/wabt or REVERSERESEARCH_TOOLS. Records input/tool/output SHA, exact banners and arguments; invalid module returns isError with structured diagnostics. WAT is a decoded representation. Does not instantiate or execute WASM, install tools or certify publisher authenticity. Bind pages using both expected digests.",
		InputSchema: objectSchema(map[string]any{
			"path":                   map[string]any{"type": "string", "minLength": 1},
			"use_wabt":               map[string]any{"type": "boolean", "default": false},
			"view":                   map[string]any{"type": "string", "enum": []string{"validation", "wat", "details"}},
			"offset":                 map[string]any{"type": "integer", "minimum": 0, "maximum": 16 << 20},
			"limit":                  map[string]any{"type": "integer", "minimum": 1, "maximum": 32768},
			"expected_sha256":        map[string]any{"type": "string", "pattern": "^[A-Fa-f0-9]{64}$"},
			"expected_output_sha256": map[string]any{"type": "string", "pattern": "^[A-Fa-f0-9]{64}$"},
		}, "path"),
	}, func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			Path string `json:"path"`
			webinspect.WASMOptions
		}
		if err := decodeArguments(request, &args); err != nil {
			return nil, err
		}
		result, err := r.core.InspectWebWASMWithOptions(ctx, args.Path, args.WASMOptions)
		if err != nil {
			return nil, err
		}
		response, err := structuredResult(result)
		if err == nil && result.WABT != nil && !result.WABT.Validated {
			response.IsError = true
		}
		return response, err
	})
}
