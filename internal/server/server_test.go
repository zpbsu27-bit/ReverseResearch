package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestHealthDoesNotStartBackends(t *testing.T) {
	root, _ := isolatedServerRoot(t)
	runtime, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	response := httptest.NewRecorder()
	runtime.Handler().ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("health status=%d body=%s", response.Code, response.Body.String())
	}
	var payload struct {
		Backends []struct {
			Name  string `json:"name"`
			State string `json:"state"`
		} `json:"backends"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Backends) != 3 {
		t.Fatalf("backend count=%d want=3", len(payload.Backends))
	}
	for _, item := range payload.Backends {
		if item.State != "idle" {
			t.Fatalf("%s state=%q want idle", item.Name, item.State)
		}
	}
}

func TestInMemoryTransportPublishesUnifiedCatalogWithoutStartingBackends(t *testing.T) {
	root, _ := isolatedServerRoot(t)
	runtime, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	runErr := make(chan error, 1)
	go func() {
		runErr <- runtime.Run(ctx, serverTransport)
	}()

	client := mcp.NewClient(&mcp.Implementation{
		Name:    "reverse-research-test",
		Version: "1.0.0",
	}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(tools.Tools), 282; got != want {
		t.Fatalf("tool count=%d want=%d", got, want)
	}
	var guardedTool, blockedTool *mcp.Tool
	for _, tool := range tools.Tools {
		switch tool.Name {
		case "x32dbg_WriteMemToAddress":
			guardedTool = tool
		case "x32dbg_ExecuteDebuggerCommand":
			blockedTool = tool
		}
	}
	if guardedTool == nil || blockedTool == nil {
		t.Fatalf("missing x32dbg policy tools: guarded=%v blocked=%v", guardedTool, blockedTool)
	}
	schema, _ := guardedTool.InputSchema.(map[string]any)
	properties, _ := schema["properties"].(map[string]any)
	if _, ok := properties["_rr_guard"]; !ok {
		t.Fatalf("guarded x32dbg schema does not publish _rr_guard: %#v", guardedTool.InputSchema)
	}
	requiredGuard := false
	switch required := schema["required"].(type) {
	case []any:
		for _, item := range required {
			requiredGuard = requiredGuard || item == "_rr_guard"
		}
	case []string:
		for _, item := range required {
			requiredGuard = requiredGuard || item == "_rr_guard"
		}
	}
	if !requiredGuard {
		t.Fatalf("guarded x32dbg schema does not require _rr_guard: %#v", guardedTool.InputSchema)
	}
	if !strings.Contains(blockedTool.Description, "blocks this low-level tool") {
		t.Fatalf("blocked generic command is not advertised as blocked: %q", blockedTool.Description)
	}

	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "reverse_status",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("reverse_status returned tool error: %#v", result.Content)
	}
	body, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Backends []struct {
			Name  string `json:"name"`
			State string `json:"state"`
		} `json:"backends"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Backends) != 3 {
		t.Fatalf("backend count=%d want=3", len(payload.Backends))
	}
	for _, item := range payload.Backends {
		if item.State != "idle" {
			t.Fatalf("%s state=%q want idle before any backend tool call", item.Name, item.State)
		}
	}

	_ = session.Close()
	cancel()
	select {
	case err := <-runErr:
		if err != nil && err != context.Canceled {
			t.Fatalf("server Run returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("server Run did not stop after context cancellation")
	}
}

func TestShutdownControlRequiresBearerAndPostAndIsIdempotent(t *testing.T) {
	root, _ := isolatedServerRoot(t)
	runtime, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	handler := runtime.Handler()

	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodPost, "/control/shutdown", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized shutdown status=%d", unauthorized.Code)
	}
	select {
	case <-runtime.ShutdownRequested():
		t.Fatal("unauthorized request triggered shutdown")
	default:
	}

	badMethod := httptest.NewRequest(http.MethodGet, "/control/shutdown", nil)
	badMethod.Header.Set("Authorization", "Bearer "+runtime.localToken)
	badMethodResponse := httptest.NewRecorder()
	handler.ServeHTTP(badMethodResponse, badMethod)
	if badMethodResponse.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET shutdown status=%d", badMethodResponse.Code)
	}
	select {
	case <-runtime.ShutdownRequested():
		t.Fatal("wrong method triggered shutdown")
	default:
	}

	shutdown := httptest.NewRequest(http.MethodPost, "/control/shutdown", nil)
	shutdown.Header.Set("Authorization", "Bearer "+runtime.localToken)
	shutdownResponse := httptest.NewRecorder()
	handler.ServeHTTP(shutdownResponse, shutdown)
	if shutdownResponse.Code != http.StatusAccepted {
		t.Fatalf("shutdown status=%d body=%s", shutdownResponse.Code, shutdownResponse.Body.String())
	}
	select {
	case <-runtime.ShutdownRequested():
	case <-time.After(time.Second):
		t.Fatal("authorized shutdown did not signal runtime")
	}

	repeated := httptest.NewRequest(http.MethodPost, "/control/shutdown", nil)
	repeated.Header.Set("Authorization", "Bearer "+runtime.localToken)
	repeatedResponse := httptest.NewRecorder()
	handler.ServeHTTP(repeatedResponse, repeated)
	if repeatedResponse.Code != http.StatusAccepted {
		t.Fatalf("repeated shutdown status=%d", repeatedResponse.Code)
	}
}
