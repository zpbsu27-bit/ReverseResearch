package server

import (
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestAndroidRecoveryMCPSelectorSchemaAndSharedAdmission(t *testing.T) {
	runtime, session, _, _ := workflowTestSession(t)
	for _, args := range []map[string]any{
		{"path": "not-opened", "unexpected": true},
		{"path": "not-opened", "view": "class"},
		{"path": "not-opened", "view": "method", "class_name": "demo.C"},
		{"path": "not-opened", "view": "classes", "overload_index": 0},
		{"path": "not-opened", "view": "method", "class_name": "demo.C", "method_name": "f", "overload_index": -1},
		{"path": "not-opened", "view": "references", "class_name": "demo.C", "overload_index": 0},
		{"path": "not-opened", "offset": 1},
		{"path": "not-opened", "limit": 16385},
		{"path": "not-opened", "expected_result_sha256": "invalid"},
	} {
		r, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "app_android_recover", Arguments: args})
		if err == nil && (r == nil || !r.IsError) {
			t.Fatalf("invalid Android recovery accepted: %+v", args)
		}
	}
	if resourceWeight("app_android_recover") != globalResourceCapacity {
		t.Fatal("JVM recovery bypasses the existing shared memory admission")
	}
	for _, status := range runtime.statuses() {
		if status.State != "idle" {
			t.Fatalf("rejected recovery started a backend: %+v", status)
		}
	}
}
