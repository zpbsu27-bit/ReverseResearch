package server

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"reverseresearch/internal/appinspect"
	"reverseresearch/internal/appinspect/testfixture"
)

func TestAndroidPackageMCPMatchesCanonicalOfflineOwner(t *testing.T) {
	runtime, session, _, _ := workflowTestSession(t)
	p := filepath.Join(t.TempDir(), "offline.apk")
	if err := os.WriteFile(p, testfixture.AndroidZIP(), 0600); err != nil {
		t.Fatal(err)
	}
	for _, view := range []string{"components", "manifest", "resources", "resource-values"} {
		args := map[string]any{"path": p, "family": "android", "view": view, "limit": 1}
		opts := appinspect.PackageOptions{Family: "android", View: view, PageOptions: appinspect.PageOptions{Limit: 1}}
		if view == "resource-values" {
			i := 1
			opts.ResourceIndex = &i
			args["resource_index"] = i
		}
		var actual appinspect.PackageReport
		workflowCall(t, session, "app_package_inspect", args, &actual)
		want, err := appinspect.InspectPackage(p, opts)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(actual, want) || actual.ExecutionPerformed {
			t.Fatalf("MCP package projection differs for %s", view)
		}
	}
	for _, args := range []map[string]any{
		{"path": p, "family": "android", "unexpected": true},
		{"path": p, "family": "android", "view": "bundles"},
		{"path": p, "family": "android", "view": "resources", "resource_index": 0},
		{"path": p, "family": "android", "view": "resource-values"},
		{"path": p, "family": "android", "view": "resource-values", "resource_index": 99},
		{"path": p, "family": "android", "view": "manifest", "offset": 1},
		{"path": p, "family": "android", "expected_sha256": strings.Repeat("0", 64)},
	} {
		v, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "app_package_inspect", Arguments: args})
		if err == nil && (v == nil || !v.IsError) {
			t.Fatalf("invalid Android request accepted: %+v", args)
		}
	}
	for _, backend := range runtime.statuses() {
		if backend.State != "idle" {
			t.Fatalf("offline package started backend: %+v", backend)
		}
	}
}
