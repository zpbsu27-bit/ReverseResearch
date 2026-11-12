package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"reverseresearch/internal/remoteagent"
)

func TestLoadPrivateKeyAndArtifactInspectCapability(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	keyPath := filepath.Join(t.TempDir(), "key.txt")
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(priv)), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadPrivateKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(priv) {
		t.Fatal("private key mismatch")
	}
	target := filepath.Join(t.TempDir(), "target.bin")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := artifactInspectCapability(context.Background(), remoteagent.JobRequest{Target: target})
	if err != nil {
		t.Fatal(err)
	}
	var identity struct {
		SHA256 string `json:"sha256"`
	}
	if err := json.Unmarshal(result.Body, &identity); err != nil {
		t.Fatal(err)
	}
	if len(identity.SHA256) != 64 || result.State != "applied" {
		t.Fatalf("result=%+v", result)
	}
	hashResult, err := artifactHashCapability(context.Background(), remoteagent.JobRequest{Target: target})
	if err != nil {
		t.Fatal(err)
	}
	var hashOnly struct {
		SHA256 string `json:"sha256"`
		Size   int64  `json:"size"`
	}
	if err := json.Unmarshal(hashResult.Body, &hashOnly); err != nil {
		t.Fatal(err)
	}
	if len(hashOnly.SHA256) != 64 || hashOnly.Size != int64(len("fixture")) {
		t.Fatalf("hash=%+v", hashOnly)
	}
}

func TestRunRequiresExplicitTLSAndState(t *testing.T) {
	if err := run(nil); err == nil {
		t.Fatal("agent accepted implicit configuration")
	}
}
