package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalMCPBearerIsStableAndRequired(t *testing.T) {
	root := t.TempDir()
	first, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()

	if len(first.localToken) != 64 || first.localToken != second.localToken {
		t.Fatalf("local bearer not stable: first=%q second=%q", first.localToken, second.localToken)
	}
	body, err := os.ReadFile(filepath.Join(root, "state", "auth", "local-mcp.token"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(body)) != first.localToken {
		t.Fatalf("persisted token mismatch")
	}

	handler := first.Handler()
	for _, authorization := range []string{"", "Bearer wrong"} {
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("{}"))
		if authorization != "" {
			req.Header.Set("Authorization", authorization)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("authorization=%q status=%d body=%s", authorization, response.Code, response.Body.String())
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+first.localToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code == http.StatusUnauthorized {
		t.Fatalf("valid bearer was rejected: body=%s", response.Body.String())
	}
}

func TestInvalidPersistedLocalBearerFailsClosed(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "state", "auth", "local-mcp.token")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not-a-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(root); err == nil {
		t.Fatal("invalid persisted local bearer was silently replaced")
	}
}
