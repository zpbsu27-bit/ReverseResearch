package server

import (
	"context"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"reverseresearch/internal/appinspect"
	"reverseresearch/internal/casebook"
	"reverseresearch/internal/webinspect"
)

func applicationSchema(extra map[string]any, required ...string) map[string]any {
	p := map[string]any{
		"path":            map[string]any{"type": "string", "minLength": 1},
		"offset":          map[string]any{"type": "integer", "minimum": 0},
		"limit":           map[string]any{"type": "integer", "minimum": 1, "maximum": 200},
		"expected_sha256": map[string]any{"type": "string", "pattern": "^[A-Fa-f0-9]{64}$"},
	}
	for k, v := range extra {
		p[k] = v
	}
	return objectSchema(p, append([]string{"path"}, required...)...)
}

func (r *Runtime) addApplicationTools() {
	r.addPortableArtifactTools()
	r.addSerializationTools()
	closed := false
	r.addTool(&mcp.Tool{
		Name:        "app_android_recover",
		Description: "Recover classes, parsed class metadata, selected method Java/smali or static incoming references from one local APK/DEX using the offline pinned JADX 0.7.1 metadata profile and existing Java21 lifecycle. A private immutable input and engine copy is closed and removed before success. class/method/references use exact class_name; method also requires method_name and explicit overload_index when ambiguous. references optionally selects one unique method. classes query filters top-level names. Results are canonical JSON bytes in base64 pages, limit=1..16384; subsequent pages require artifact and result digests. Producer identities and text are derived, completeness/runtime/JNI/signature/install/device facts are unknown. No target execution or engine download; native process-tree support and a full JDK are required.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: &closed},
		InputSchema: applicationSchema(map[string]any{
			"view":                   map[string]any{"type": "string", "enum": []string{"classes", "class", "method", "references"}},
			"class_name":             map[string]any{"type": "string", "minLength": 1, "maxLength": 4096},
			"method_name":            map[string]any{"type": "string", "minLength": 1, "maxLength": 4096},
			"query":                  map[string]any{"type": "string", "maxLength": 4096},
			"overload_index":         map[string]any{"type": "integer", "minimum": 0, "maximum": 65535},
			"limit":                  map[string]any{"type": "integer", "minimum": 1, "maximum": 16384},
			"expected_result_sha256": map[string]any{"type": "string", "pattern": "^[A-Fa-f0-9]{64}$"},
		}),
	}, func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var a struct {
			Path string `json:"path"`
			appinspect.AndroidRecoveryOptions
		}
		if err := decodeArguments(request, &a); err != nil {
			return nil, err
		}
		v, err := r.core.RecoverAndroid(ctx, a.Path, a.AndroidRecoveryOptions)
		if err != nil {
			return nil, err
		}
		return structuredResult(v)
	})
	r.addTool(&mcp.Tool{Name: "app_dex_inspect", Description: "Inspect bounded DEX 035/037/038/039/040 LE declarations, strings, or selected method instruction bytes/structural CFG. instructions/cfg/edges require build-local method_index; string-bytes requires string_index. Payload rows are data, offsets use code units, and byte ranges bind the exact DEX member. CFG includes unreachable code and conservative possible exception edges; it does not prove typed ART validation or runtime calls. Optional entry uses the canonical ZIP/APK CRC reader. Subsequent pages require expected_sha256. Metadata/code pages limit=1..200; string-bytes limit=1..16384. No VM/class loading, decompilation, APK signer verification or DEX 041 container support.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: &closed}, InputSchema: applicationSchema(map[string]any{"entry": map[string]any{"type": "string", "minLength": 1}, "view": map[string]any{"type": "string", "enum": []string{"classes", "methods", "strings", "string-bytes", "instructions", "cfg", "edges"}}, "method_index": map[string]any{"type": "integer", "minimum": 0, "maximum": 65535}, "string_index": map[string]any{"type": "integer", "minimum": 0, "maximum": (1 << 20) - 1}, "limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 16384}})}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var a struct {
			Path string `json:"path"`
			appinspect.DEXOptions
		}
		if err := decodeArguments(request, &a); err != nil {
			return nil, err
		}
		v, err := r.core.InspectDEX(a.Path, a.DEXOptions)
		if err != nil {
			return nil, err
		}
		return structuredResult(v)
	})
	r.addTool(&mcp.Tool{Name: "app_package_inspect", Description: "Inspect a local ZIP-backed Apple, Harmony or Android application through the canonical snapshot/CRC reader. components works for all families; bundles is Apple-only. Android manifest returns binary/plain XML declarations, resources returns typed ARSC configurations, resource-values pages one bag selected by resource_index. Subsequent Android pages require expected_sha256. Source/member hashes and byte ranges remain build-local; declared permissions/components/resource IDs and raw values do not verify effective permissions, winning configuration, runtime bindings, signer validity, installation or completed reconstruction.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: &closed}, InputSchema: applicationSchema(map[string]any{"family": map[string]any{"type": "string", "enum": []string{"apple", "harmony", "android"}}, "view": map[string]any{"type": "string", "enum": []string{"components", "bundles", "manifest", "resources", "resource-values"}}, "resource_index": map[string]any{"type": "integer", "minimum": 0, "maximum": (8 << 20) - 1}}, "family")}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var a struct {
			Path string `json:"path"`
			appinspect.PackageOptions
		}
		if err := decodeArguments(request, &a); err != nil {
			return nil, err
		}
		v, err := r.core.InspectApplicationPackage(a.Path, a.PackageOptions)
		if err != nil {
			return nil, err
		}
		return structuredResult(v)
	})
	r.addTool(&mcp.Tool{Name: "case_research_view", Description: "Page a read-only canonical Case snapshot graph/dossier and recorded research progress. Select a dossier by exact finding_id. Verifies evidence currentness and fences Case revision; does not infer function/target identity or accept completion.", InputSchema: objectSchema(map[string]any{
		"case_id":         map[string]any{"type": "string", "minLength": 1},
		"finding_id":      map[string]any{"type": "string"},
		"offset":          map[string]any{"type": "integer", "minimum": 0},
		"limit":           map[string]any{"type": "integer", "minimum": 1, "maximum": 200},
		"expected_sha256": map[string]any{"type": "string", "pattern": "^[A-Fa-f0-9]{64}$"},
	}, "case_id")}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var a struct {
			CaseID string `json:"case_id"`
			casebook.ResearchViewOptions
		}
		if err := decodeArguments(request, &a); err != nil {
			return nil, err
		}
		v, err := r.core.CaseResearchView(a.CaseID, a.ResearchViewOptions)
		if err != nil {
			return nil, err
		}
		return structuredResult(v)
	})
	r.addTool(&mcp.Tool{Name: "web_source_map_locate", Description: "Locate zero-based generated line/UTF-16 column in a local classic or embedded indexed SourceMap v3. Mapping declarations are static artifact facts; section URLs are never loaded.", InputSchema: objectSchema(map[string]any{
		"path":            map[string]any{"type": "string", "minLength": 1},
		"line":            map[string]any{"type": "integer", "minimum": 0, "maximum": 2147483647},
		"column":          map[string]any{"type": "integer", "minimum": 0, "maximum": 2147483647},
		"expected_sha256": map[string]any{"type": "string", "pattern": "^[A-Fa-f0-9]{64}$"},
	}, "path", "line", "column")}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var a struct {
			Path string `json:"path"`
			webinspect.SourceMapLocateOptions
		}
		if err := decodeArguments(request, &a); err != nil {
			return nil, err
		}
		v, err := r.core.LocateWebSourceMap(a.Path, a.SourceMapLocateOptions)
		if err != nil {
			return nil, err
		}
		return structuredResult(v)
	})
	r.addTool(&mcp.Tool{Name: "app_asar_inspect", Description: "Inspect a local Electron ASAR inventory with SHA-fenced paging. Validates all packed ranges before selection; links and external unpacked files are not read or extracted.", InputSchema: applicationSchema(nil)}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var a struct {
			Path string `json:"path"`
			appinspect.PageOptions
		}
		if err := decodeArguments(request, &a); err != nil {
			return nil, err
		}
		v, err := r.core.InspectASAR(a.Path, a.PageOptions)
		if err != nil {
			return nil, err
		}
		return structuredResult(v)
	})
	r.addTool(&mcp.Tool{Name: "app_asar_read", Description: "Read at most 16384 bytes from one exact packed ASAR entry as base64 with archive/content digests. Unavailable link/unpacked entries stay unavailable. Does not extract or execute.", InputSchema: applicationSchema(map[string]any{
		"entry": map[string]any{"type": "string", "minLength": 1}, "limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 16384},
	}, "entry")}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var a struct {
			Path string `json:"path"`
			appinspect.EntryReadOptions
		}
		if err := decodeArguments(request, &a); err != nil {
			return nil, err
		}
		v, err := r.core.ReadASAR(a.Path, a.EntryReadOptions)
		if err != nil {
			return nil, err
		}
		return structuredResult(v)
	})
	r.addTool(&mcp.Tool{Name: "app_javascript_inspect", Description: "Parse one local JavaScript file or packed ASAR entry with the single pinned ECMAScript AST parser. Page imports/exports, module requests, Electron/endpoint and Webpack/Rspack/esbuild bundle candidates. Literal object/array module factories retain original UTF-8 byte ranges (end exclusive) and SHA; normalized parser rendering hashes use a distinct algorithm. Lexical factory-loader and stable wrapper bindings recover static internal requests/exports/entries/async chunks; dynamic, duplicate or spread keys remain unknown/ambiguous. No target execution, Babel fingerprint compatibility, aliases or runtime binding/behavior proof. Complete validation and budgets precede paging.", InputSchema: applicationSchema(map[string]any{"entry": map[string]any{"type": "string"}})}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var a struct {
			Path string `json:"path"`
			appinspect.JavaScriptOptions
		}
		if err := decodeArguments(request, &a); err != nil {
			return nil, err
		}
		v, err := r.core.InspectJavaScript(a.Path, a.JavaScriptOptions)
		if err != nil {
			return nil, err
		}
		return structuredResult(v)
	})
	r.addTool(&mcp.Tool{Name: "app_managed_inspect", Description: "Inspect local PE/CLI metadata and page build-local MethodDef identities bound to SHA-256/MVID. Declared P/Invoke imports are static declarations. Native PE remains metadata-unavailable. Does not load CLR or execute the file.", InputSchema: applicationSchema(nil)}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var a struct {
			Path string `json:"path"`
			appinspect.PageOptions
		}
		if err := decodeArguments(request, &a); err != nil {
			return nil, err
		}
		v, err := r.core.InspectManaged(a.Path, a.PageOptions)
		if err != nil {
			return nil, err
		}
		return structuredResult(v)
	})
	r.addTool(&mcp.Tool{Name: "app_managed_method", Description: "Decode a selected build-local MethodDef CIL body with exact instruction/token/branch boundaries, raw IL digest and SHA-fenced paging. Static references do not prove runtime calls, native mapping or C# reconstruction.", InputSchema: applicationSchema(map[string]any{"token": map[string]any{"type": "string", "pattern": "^0x06[0-9a-fA-F]{6}$"}}, "token")}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var a struct {
			Path string `json:"path"`
			appinspect.ManagedMethodOptions
		}
		if err := decodeArguments(request, &a); err != nil {
			return nil, err
		}
		v, err := r.core.InspectManagedMethod(a.Path, a.ManagedMethodOptions)
		if err != nil {
			return nil, err
		}
		return structuredResult(v)
	})
}

func (r *Runtime) addPortableArtifactTools() {
	closed := false
	r.addTool(&mcp.Tool{Name: "app_go_metadata_read", Description: "Read original Go build-info bytes or lossless module records from admitted local PE/ELF/thin Mach-O. header/version/module/module-body are byte pages; records pages the full parsed inventory including exact raw ranges/hashes, duplicates, unknown/bad-UTF8/unterminated lines and explicit replacement associations. record-field reads one decoded path/version/sum/key/value selected by record_index as base64, including binary escapes and empty values. Field bytes are derived, not an original contiguous source range. Semantic views require exact module sentinels or an explicit empty historical module anchor; grammar, text completeness including compiler encoding, and page coverage are independent. Inline/historical-pointer/zero-fill anchors remain supported. records limit=1..200, byte views=1..16384; follow next_offset with artifact expected_sha256. No target execution or compiler/module authentication.", InputSchema: applicationSchema(map[string]any{"part": map[string]any{"type": "string", "enum": []string{"header", "version", "module", "module-body", "records", "record-field"}}, "record_index": map[string]any{"type": "integer", "minimum": 0, "maximum": 65535}, "field": map[string]any{"type": "string", "enum": []string{"path", "version", "sum", "key", "value"}}, "limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 16384}})}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var a struct {
			Path string `json:"path"`
			appinspect.GoMetadataOptions
		}
		if err := decodeArguments(request, &a); err != nil {
			return nil, err
		}
		v, err := r.core.ReadGoMetadata(a.Path, a.GoMetadataOptions)
		if err != nil {
			return nil, err
		}
		return structuredResult(v)
	})
	for _, spec := range []struct {
		name, description string
		run               func(string, appinspect.PageOptions) (any, error)
	}{
		{"app_javascript_application", "Inspect a bounded local ASAR/directory snapshot, including node_modules, before paging JavaScript module relations. Selected JS/JSON/native-addon bytes, package.json metadata and directory/link boundaries share one SHA fence. Node default static path candidates distinguish import/require, ordered conditions and array targets, main/index lookup, dependencies/self and imports/exports patterns with metadata SHA provenance. Webpack/Rspack/esbuild object/array factories and internal loader/wrapper requests use typed virtual-module candidates, never guessed filesystem paths. Unknown/spread/duplicate keys stay ambiguous; 64 bundle facts per file are a labeled preview, with full facts paged by app_javascript_inspect. Limits: 2048 selected files, 8192 path boundaries and virtual modules, 1 MiB per file, 32 MiB selected bytes, 48 KiB output. Logical paths are case sensitive. No dependency download, target execution, custom loader/alias/runtime binding or new Case store.", func(p string, o appinspect.PageOptions) (any, error) { return r.core.InspectApplication(p, o) }},
		{"app_go_inspect", "Summarize the canonical lossless Go build-metadata observation and page dependencies from a local supported executable. Known records are retained alongside grammar/text completeness, unparsed counts and observed setting counts; binary decoded settings are not normalized into UTF8 strings. Use app_go_metadata_read records/record-field/module-body for exact partial evidence. Declarations are unauthenticated; no target execution or Go process starts.", func(p string, o appinspect.PageOptions) (any, error) { return r.core.InspectGoBinary(p, o) }},
		{"app_zip_inspect", "Page ZIP directory declarations after checking all paths and compressed ranges. Does not extract files, verify all CRCs or validate APK/IPA signatures.", func(p string, o appinspect.PageOptions) (any, error) { return r.core.InspectZIP(p, o) }},
	} {
		r.addTool(&mcp.Tool{Name: spec.name, Description: spec.description, InputSchema: applicationSchema(nil)}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var a struct {
				Path string `json:"path"`
				appinspect.PageOptions
			}
			if err := decodeArguments(request, &a); err != nil {
				return nil, err
			}
			v, err := spec.run(a.Path, a.PageOptions)
			if err != nil {
				return nil, err
			}
			return structuredResult(v)
		})
	}
	r.addTool(&mcp.Tool{Name: "app_evm_inspect", Description: "Inspect one local explicit raw/hex EVM carrier. instructions (default) pages linear opcodes and PUSH4/EQ candidates, including unreachable/data bytes. interface uses pinned EVMole 0.9.3 to infer selector/body offset, ABI/fallback dispatch, arguments and mutability; null remains unknown. interface-bytes reads the complete original engine JSON as base64 with a result digest. Item limit=1..200; byte limit=1..16384. Subsequent interface pages require artifact expected_sha256 and expected_result_sha256. Raw/UTF-8 hex permits optional 0x/0X and outer ASCII whitespace; EF00 containers are outside the interface profile. The bundled import-free analyzer has 256 MiB WASM linear memory and a 30-second deadline; cancellation closes its per-request runtime. Discovery completeness, hardfork, bytecode kind and deployment authenticity remain unknown. No target EVM execution, RPC, network, deployed ABI verification or second store.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: &closed}, InputSchema: applicationSchema(map[string]any{"encoding": map[string]any{"type": "string", "enum": []string{"raw", "hex"}}, "view": map[string]any{"type": "string", "enum": []string{"instructions", "interface", "interface-bytes"}}, "expected_result_sha256": map[string]any{"type": "string", "pattern": "^[A-Fa-f0-9]{64}$"}, "limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 16384}})}, func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var a struct {
			Path string `json:"path"`
			appinspect.EVMOptions
		}
		if err := decodeArguments(request, &a); err != nil {
			return nil, err
		}
		v, err := r.core.InspectEVM(ctx, a.Path, a.EVMOptions)
		if err != nil {
			return nil, err
		}
		return structuredResult(v)
	})
	r.addTool(&mcp.Tool{Name: "app_zip_read", Description: "CRC-check and bound-decompress one exact ZIP entry, then return at most 16384 bytes as base64 with container/content digests. Links/encrypted/unsupported entries remain unavailable; no extraction or target execution.", InputSchema: applicationSchema(map[string]any{"entry": map[string]any{"type": "string", "minLength": 1}, "limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 16384}}, "entry")}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var a struct {
			Path string `json:"path"`
			appinspect.EntryReadOptions
		}
		if err := decodeArguments(request, &a); err != nil {
			return nil, err
		}
		v, err := r.core.ReadZIP(a.Path, a.EntryReadOptions)
		if err != nil {
			return nil, err
		}
		return structuredResult(v)
	})
	for _, spec := range []struct {
		name, description string
		run               func(string, string, appinspect.CompareOptions) (any, error)
	}{
		{"app_javascript_compare", "Compare the declared AST vocabulary of two local JavaScript snapshots as ordered multiset differences. Does not prove behavior equivalence or full export/control-flow equality.", func(l, rp string, o appinspect.CompareOptions) (any, error) {
			return r.core.CompareJavaScript(l, rp, o)
		}},
		{"app_managed_compare", "Compare PE/CLI declaration candidates by type/name/signature bytes, preserving ambiguity and build-local tokens. Inspect selected-page raw IL equality separately; it is not a cross-build semantic or native identity proof.", func(l, rp string, o appinspect.CompareOptions) (any, error) { return r.core.CompareManaged(l, rp, o) }},
	} {
		schema := applicationSchema(map[string]any{"right_path": map[string]any{"type": "string", "minLength": 1}, "expected_left_sha256": map[string]any{"type": "string", "pattern": "^[A-Fa-f0-9]{64}$"}, "expected_right_sha256": map[string]any{"type": "string", "pattern": "^[A-Fa-f0-9]{64}$"}}, "right_path")
		r.addTool(&mcp.Tool{Name: spec.name, Description: spec.description + " Use expected_sha256 for comparison_sha256 across pages.", InputSchema: schema}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var a struct {
				Path      string `json:"path"`
				RightPath string `json:"right_path"`
				appinspect.CompareOptions
			}
			if err := decodeArguments(request, &a); err != nil {
				return nil, err
			}
			v, err := spec.run(a.Path, a.RightPath, a.CompareOptions)
			if err != nil {
				return nil, err
			}
			return structuredResult(v)
		})
	}
}
