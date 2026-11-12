package appinspect

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAndroidRecoveryRejectsInvalidSelectorsBeforeCreatingWorkspace(t *testing.T) {
	root := t.TempDir()
	n := 0
	for _, o := range []AndroidRecoveryOptions{
		{View: "unknown"}, {View: "method"}, {View: "class"},
		{View: "classes", ClassName: "demo.C"}, {View: "classes", OverloadIndex: &n},
		{View: "class", ClassName: "demo.C", MethodName: "f"},
		{View: "references", ClassName: "demo.C", OverloadIndex: &n},
		{View: "method", ClassName: "demo.C", MethodName: "f", Query: "C"},
		{PageOptions: PageOptions{Offset: -1}}, {PageOptions: PageOptions{Limit: 16385}},
		{PageOptions: PageOptions{Offset: 1}},
	} {
		if _, err := RecoverAndroid(context.Background(), root, "not-opened", o); err == nil {
			t.Fatalf("invalid selector accepted: %+v", o)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := RecoverAndroid(ctx, root, "not-opened", AndroidRecoveryOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("caller cancellation lost: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "state")); !os.IsNotExist(err) {
		t.Fatalf("rejected request created state: %v", err)
	}
}

func TestAndroidRecoveryRejectsProducerIdentityDriftAndMalformedRows(t *testing.T) {
	metadata := map[string]any{"producer_short_id": "f(I)I", "code_available": true}
	method := map[string]any{"producer_short_id": "f(I)I", "code_available": true, "body": "int f(int v) { return v; }", "mode": "java", "fell_back": false, "markers": []any{}}
	if err := validateAndroidMethod(method, metadata); err != nil {
		t.Fatal(err)
	}
	for _, change := range []struct {
		key   string
		value any
	}{
		{"producer_short_id", "f(Ljava/lang/String;)I"}, {"code_available", false},
		{"body", nil}, {"markers", []any{13}}, {"mode", "unknown"}, {"fell_back", nil},
	} {
		bad := map[string]any{}
		for key, value := range method {
			bad[key] = value
		}
		bad[change.key] = change.value
		if err := validateAndroidMethod(bad, metadata); err == nil {
			t.Fatalf("producer identity/profile drift accepted: %s", change.key)
		}
	}
	refs := map[string]any{"target": "demo.C.f", "total": float64(1), "count": float64(1), "resolve_line": false, "items": []any{map[string]any{"method": "demo.C.caller"}}}
	if err := validateAndroidReferences(refs, "demo.C.f"); err != nil {
		t.Fatal(err)
	}
	for _, change := range []struct {
		key   string
		value any
	}{
		{"target", "demo.C.other"}, {"total", float64(2)}, {"count", float64(0)},
		{"resolve_line", true}, {"items", []any{"not-metadata"}},
	} {
		bad := map[string]any{}
		for key, value := range refs {
			bad[key] = value
		}
		bad[change.key] = change.value
		if err := validateAndroidReferences(bad, "demo.C.f"); err == nil {
			t.Fatalf("incomplete/misidentified references accepted: %s", change.key)
		}
	}
}
