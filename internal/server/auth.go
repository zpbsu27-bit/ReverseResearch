package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"reverseresearch/internal/recordio"
	"reverseresearch/internal/securefile"
)

const localTokenFilename = "local-mcp.token"

func loadOrCreateLocalToken(root string) (token string, path string, err error) {
	absolute, err := filepath.Abs(root)
	if err != nil {
		return "", "", err
	}
	path = filepath.Join(absolute, "state", "auth", localTokenFilename)
	authDir := filepath.Dir(path)
	if err := os.MkdirAll(authDir, 0o700); err != nil {
		return "", path, fmt.Errorf("create local MCP auth directory: %w", err)
	}
	if err := securefile.RestrictDir(authDir); err != nil {
		return "", path, fmt.Errorf("restrict local MCP auth directory: %w", err)
	}
	release, err := recordio.Acquire(path+".lock", 10*time.Second)
	if err != nil {
		return "", path, fmt.Errorf("lock local MCP bearer: %w", err)
	}
	defer func() {
		err = errors.Join(err, release())
	}()

	body, readErr := recordio.ReadFileLimit(path, int64(4<<10))
	if readErr == nil {
		if err := securefile.RestrictFile(path); err != nil {
			return "", path, fmt.Errorf("restrict local MCP bearer: %w", err)
		}
		token, err = validateLocalToken(body)
		if err != nil {
			return "", path, err
		}
		return token, path, nil
	}
	if !errors.Is(readErr, os.ErrNotExist) {
		return "", path, fmt.Errorf("read local MCP bearer: %w", readErr)
	}

	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", path, fmt.Errorf("generate local MCP bearer: %w", err)
	}
	token = hex.EncodeToString(random)
	if err := recordio.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		return "", path, fmt.Errorf("persist local MCP bearer: %w", err)
	}
	return token, path, nil
}

func validateLocalToken(body []byte) (string, error) {
	token := strings.TrimSpace(string(body))
	if len(token) != 64 {
		return "", errors.New("invalid persisted local MCP bearer: expected 64 hex characters")
	}
	decoded, err := hex.DecodeString(token)
	if err != nil || len(decoded) != 32 {
		return "", errors.New("invalid persisted local MCP bearer: expected 32 random bytes encoded as hex")
	}
	return strings.ToLower(token), nil
}

func requireLocalBearer(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		authorization := request.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(authorization, prefix) {
			localUnauthorized(w)
			return
		}
		provided := strings.TrimSpace(strings.TrimPrefix(authorization, prefix))
		if len(provided) != len(token) ||
			subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
			localUnauthorized(w)
			return
		}
		next.ServeHTTP(w, request)
	})
}

func localUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}
