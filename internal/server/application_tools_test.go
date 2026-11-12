package server

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"os"
	"path/filepath"
	"reverseresearch/internal/appinspect"
	"reverseresearch/internal/appinspect/testfixture"
	corefixture "reverseresearch/internal/dfir/testfixture"
	applefixture "reverseresearch/internal/iosinspect/testfixture"
	"strings"
	"testing"
	"time"
)

func TestREAApplicationMCPUsesCanonicalOfflineOwners(t *testing.T) {
	root, sourceRoot := isolatedServerRoot(t)
	runtime, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	st, ct := mcp.NewInMemoryTransports()
	go func() { _ = runtime.Run(ctx, st) }()
	client := mcp.NewClient(&mcp.Implementation{Name: "rea-application-test", Version: "1"}, nil)
	session, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	input := func(name string, b []byte) string {
		p := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	assembly := input("demo.dll", testfixture.Managed(42))
	asar := input("app.asar", testfixture.JavaScriptASAR())
	js := input("app.js", []byte(`import './bridge.js'; fetch('/api');`))
	evm := input("code.hex", []byte("63a9059cbb1400"))
	tar := input("app.tar", testfixture.TAR())
	plist := input("blob.plist", []byte(`<plist><data>AP8=</data></plist>`))
	keyed := input("keyed.plist", []byte(applefixture.KeyedXML))
	nib := input("view.nib", applefixture.NIB())
	core := input("recorded.core", corefixture.Core())
	hap := input("entry.hap", testfixture.HarmonyZIP())
	goRaw := input("old-go.exe", testfixture.GoMetadataPE(testfixture.GoPointerRecord(true), 1024))
	packageASAR := input("package-app.asar", testfixture.JavaScriptPackageASAR())
	bundleASAR := input("bundle-app.asar", testfixture.JavaScriptBundlerASAR())
	har := filepath.Join(sourceRoot, "testdata", "rea-web-capture.har")
	mapPath := filepath.Join(sourceRoot, "testdata", "rea-web-source.map")
	for _, call := range []struct {
		name  string
		args  map[string]any
		field string
		want  any
	}{
		{"app_asar_inspect", map[string]any{"path": asar, "limit": 1}, "total_entries", float64(4)},
		{"app_asar_read", map[string]any{"path": asar, "entry": "link.js"}, "execution_performed", false},
		{"app_javascript_inspect", map[string]any{"path": js}, "total_facts", float64(2)},
		{"app_javascript_application", map[string]any{"path": asar}, "total_modules", float64(4)},
		{"app_javascript_application", map[string]any{"path": packageASAR}, "package_manifests", float64(2)},
		{"app_javascript_application", map[string]any{"path": bundleASAR}, "total_virtual_modules", float64(2)},
		{"app_javascript_inspect", map[string]any{"path": bundleASAR, "entry": "bundle.js"}, "content_sha256", fmt.Sprintf("%x", sha256.Sum256([]byte(testfixture.JavaScriptBundlerSource)))},
		{"app_managed_inspect", map[string]any{"path": assembly}, "mvid", "12345678-9abc-def0-0102-030405060708"},
		{"app_managed_method", map[string]any{"path": assembly, "token": "0x06000001"}, "total_instructions", float64(3)},
		{"app_managed_compare", map[string]any{"path": assembly, "right_path": assembly}, "total_items", float64(2)},
		{"app_javascript_compare", map[string]any{"path": js, "right_path": js}, "total_items", float64(2)},
		{"app_evm_inspect", map[string]any{"path": evm, "encoding": "hex"}, "total_instructions", float64(3)},
		{"app_tar_inspect", map[string]any{"path": tar}, "total_entries", float64(1)},
		{"app_package_inspect", map[string]any{"path": hap, "family": "harmony"}, "packaging_model_hint", "stage-path"},
		{"app_go_metadata_read", map[string]any{"path": goRaw, "part": "module"}, "build_info_available", true},
		{"app_tar_read", map[string]any{"path": tar, "entry": "app/main.txt"}, "data_base64", "YWJj"},
		{"apple_plist_inspect", map[string]any{"path": plist}, "total_objects", float64(1)},
		{"apple_plist_data_read", map[string]any{"path": plist, "object_index": 0}, "data_base64", "AP8="},
		{"apple_keyed_archive_inspect", map[string]any{"path": keyed}, "reference_resolution_complete", false},
		{"apple_nib_inspect", map[string]any{"path": nib, "view": "values"}, "total_values", float64(3)},
		{"crash_core_inspect", map[string]any{"path": core, "view": "threads"}, "total_threads", float64(2)},
		{"crash_core_note_read", map[string]any{"path": core, "note_index": 3}, "data_base64", "AQID"},
		{"web_source_map_locate", map[string]any{"path": mapPath, "line": 0, "column": 0}, "network_interaction", false},
		{"web_har_api", map[string]any{"path": har}, "total_entries", float64(2)},
		{"web_har_body_read", map[string]any{"path": har, "entry_ordinal": 0, "side": "response"}, "network_interaction", false},
		{"web_har_compare", map[string]any{"path": har, "right_path": har}, "network_interaction", false},
	} {
		result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: call.name, Arguments: call.args})
		if err != nil || result == nil || result.IsError {
			t.Fatalf("%s result=%+v err=%v", call.name, result, err)
		}
		var v map[string]any
		b, _ := json.Marshal(result.StructuredContent)
		if err := json.Unmarshal(b, &v); err != nil {
			t.Fatal(err)
		}
		if v[call.field] != call.want {
			t.Fatalf("%s %s=%v want=%v", call.name, call.field, v[call.field], call.want)
		}
		if call.field == "total_virtual_modules" {
			var graph appinspect.ApplicationReport
			if err := json.Unmarshal(b, &graph); err != nil {
				t.Fatal(err)
			}
			if len(graph.Modules) != 1 || len(graph.Modules[0].VirtualModules) != 2 || len(graph.Modules[0].Relations) != 2 || graph.Modules[0].Relations[0].Resolution != "bundle-module-candidate" || len(graph.Modules[0].Relations[0].Candidates) != 0 {
				t.Fatalf("MCP bundle graph %+v", graph)
			}
		}
		if call.field == "package_manifests" {
			var graph appinspect.ApplicationReport
			if err := json.Unmarshal(b, &graph); err != nil {
				t.Fatal(err)
			}
			resolved := map[string]string{}
			for _, module := range graph.Modules {
				if module.Path == "main.js" {
					for _, rel := range module.Relations {
						if rel.Resolution == "admitted-path-candidate" && len(rel.Candidates) == 1 {
							resolved[rel.Specifier] = rel.Candidates[0]
						}
					}
				}
			}
			if resolved["#entry"] != "esm.mjs" || resolved["pkg"] != "node_modules/pkg/index.cjs" || graph.ExecutionPerformed {
				t.Fatalf("MCP package relation contract: %+v", graph)
			}
		}
	}
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "app_managed_method", Arguments: map[string]any{"path": assembly, "token": "0x06000001", "expected_sha256": strings.Repeat("0", 64)}})
	if err == nil && (result == nil || !result.IsError) {
		t.Fatal("MCP accepted stale assembly")
	}
	for _, call := range []struct {
		name string
		args map[string]any
	}{
		{"apple_plist_inspect", map[string]any{"path": plist, "expected_sha256": strings.Repeat("0", 64)}},
		{"apple_plist_data_read", map[string]any{"path": plist, "object_index": 100}},
		{"apple_keyed_archive_inspect", map[string]any{"path": keyed, "root": "absent"}},
		{"crash_core_inspect", map[string]any{"path": core, "expected_sha256": strings.Repeat("0", 64)}},
		{"crash_core_note_read", map[string]any{"path": core, "note_index": 100}},
		{"app_tar_read", map[string]any{"path": tar, "entry": "absent"}},
		{"app_package_inspect", map[string]any{"path": hap, "family": "harmony", "view": "bundles"}},
		{"app_package_inspect", map[string]any{"path": hap, "family": "harmony", "expected_sha256": strings.Repeat("0", 64)}},
	} {
		v, err := session.CallTool(ctx, &mcp.CallToolParams{Name: call.name, Arguments: call.args})
		if err == nil && (v == nil || !v.IsError) {
			t.Fatalf("%s accepted invalid selection", call.name)
		}
	}
	for _, s := range runtime.statuses() {
		if s.State != "idle" {
			t.Fatalf("static query started %s: %s", s.Name, s.State)
		}
	}
}
