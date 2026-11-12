package remoteagent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestBuiltinReadOnlyCapabilitiesAreBoundedAndTyped(t *testing.T) {
	handlers := BuiltinReadOnlyCapabilities()
	for _, name := range []string{
		"artifact.inspect", "artifact.hash", "artifact.metadata", "directory.snapshot",
		"tool.inventory", "process.inventory", "environment.fingerprint",
		"file.read_excerpt", "case.evidence.capture",
	} {
		if handlers[name] == nil {
			t.Fatalf("missing capability %s", name)
		}
		if forbiddenCapability(name) {
			t.Fatalf("builtin capability unexpectedly forbidden: %s", name)
		}
	}
	for name := range handlers {
		lower := strings.ToLower(name)
		if strings.Contains(lower, "shell") || strings.Contains(lower, "exec") || strings.Contains(lower, "powershell") {
			t.Fatalf("dangerous builtin capability name %q", name)
		}
	}
}

func TestReadOnlyFileCapabilitiesAndEvidenceCapture(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "sample.bin")
	if err := os.WriteFile(target, []byte("0123456789abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}
	handlers := BuiltinReadOnlyCapabilities()

	result, err := handlers["file.read_excerpt"](context.Background(), JobRequest{
		Target: target, Parameters: map[string]string{"offset": "4", "max_bytes": "6"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var excerpt excerptResult
	if err := json.Unmarshal(result.Body, &excerpt); err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(excerpt.DataBase64)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != "456789" || excerpt.Bytes != 6 || excerpt.EOF {
		t.Fatalf("excerpt=%+v decoded=%q", excerpt, decoded)
	}
	if len(excerpt.SHA256) != 64 {
		t.Fatalf("excerpt SHA=%q", excerpt.SHA256)
	}

	capture, err := handlers["case.evidence.capture"](context.Background(), JobRequest{
		Target: target, Parameters: map[string]string{"max_bytes": "8"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var evidence map[string]any
	if err := json.Unmarshal(capture.Body, &evidence); err != nil {
		t.Fatal(err)
	}
	if evidence["schema"] != "reverseresearch.remote-evidence-capture.v1" {
		t.Fatalf("capture=%v", evidence)
	}
	if got, _ := evidence["capture_sha256"].(string); len(got) != 64 {
		t.Fatalf("capture sha=%q", got)
	}

	if _, err := handlers["file.read_excerpt"](context.Background(), JobRequest{
		Target: target, Parameters: map[string]string{"max_bytes": "65537"},
	}); err == nil {
		t.Fatal("oversized excerpt accepted")
	}
	if _, err := handlers["file.read_excerpt"](context.Background(), JobRequest{
		Target: target, Parameters: map[string]string{"command": "whoami"},
	}); err == nil {
		t.Fatal("unknown command-like parameter accepted")
	}
}

func TestDirectoryToolEnvironmentAndProcessInventory(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sub", "b.txt"), []byte("b"), 0o600); err != nil {
		t.Fatal(err)
	}
	handlers := BuiltinReadOnlyCapabilities()

	dirResult, err := handlers["directory.snapshot"](context.Background(), JobRequest{
		Target: root, Parameters: map[string]string{"max_depth": "1", "max_entries": "16"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(dirResult.Body), "sub/b.txt") {
		t.Fatalf("depth bound not enforced: %s", dirResult.Body)
	}
	if !strings.Contains(string(dirResult.Body), "a.txt") {
		t.Fatalf("snapshot missing direct child: %s", dirResult.Body)
	}

	toolResult, err := handlers["tool.inventory"](context.Background(), JobRequest{
		Target: "host", Parameters: map[string]string{"names": "definitely-not-a-real-tool-reverseresearch-test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(toolResult.Body), "\"available\":false") {
		t.Fatalf("tool inventory=%s", toolResult.Body)
	}

	envResult, err := handlers["environment.fingerprint"](context.Background(), JobRequest{Target: "host"})
	if err != nil {
		t.Fatal(err)
	}
	var env map[string]any
	if err := json.Unmarshal(envResult.Body, &env); err != nil {
		t.Fatal(err)
	}
	if got, _ := env["fingerprint_sha256"].(string); len(got) != 64 {
		t.Fatalf("fingerprint=%q", got)
	}

	if runtime.GOOS == "windows" || runtime.GOOS == "linux" {
		processResult, err := handlers["process.inventory"](context.Background(), JobRequest{
			Target: "host", Parameters: map[string]string{"max_entries": "8"},
		})
		if err != nil {
			t.Fatal(err)
		}
		var inventory struct {
			Processes []ProcessInfo `json:"processes"`
		}
		if err := json.Unmarshal(processResult.Body, &inventory); err != nil {
			t.Fatal(err)
		}
		if len(inventory.Processes) == 0 || len(inventory.Processes) > 8 {
			t.Fatalf("process count=%d", len(inventory.Processes))
		}
	}
}
