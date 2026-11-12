package sourceaudit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanBuildsDependencyInventoryAndRedactsSecrets(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module demo\n\ngo 1.24\n\nrequire example.com/lib v1.2.3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"dependencies":{"left-pad":"1.3.0"},"devDependencies":{"vitest":"^2.0.0"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	secret := "AKIAABCDEFGHIJKLMNOP"
	code := "package demo\nvar apiKey = \"super-secret-token-value\"\n// " + secret + "\n"
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte(code), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "node_modules", "ignored"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "node_modules", "ignored", "x.js"), []byte("secret=\"should-not-scan\""), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := Scan(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.SnapshotSHA256) != 64 || len(report.Manifests) != 2 || len(report.Dependencies) != 3 {
		t.Fatalf("report=%+v", report)
	}
	if report.LanguageCounts["go"] == 0 || len(report.SecretCandidates) < 2 {
		t.Fatalf("report=%+v", report)
	}
	for _, candidate := range report.SecretCandidates {
		if strings.Contains(candidate.Redacted, "super-secret-token-value") || strings.Contains(candidate.Redacted, secret) {
			t.Fatalf("secret leaked: %+v", candidate)
		}
		if candidate.Fingerprint == "" || candidate.Strength != "candidate" {
			t.Fatalf("candidate=%+v", candidate)
		}
	}
	foundIgnored := false
	for _, path := range report.SkippedDirs {
		if path == "node_modules" {
			foundIgnored = true
		}
	}
	if !foundIgnored {
		t.Fatalf("skipped=%+v", report.SkippedDirs)
	}
}

func TestScanFailsClosedOnBounds(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 2; i++ {
		if err := os.WriteFile(filepath.Join(root, string(rune('a'+i))+".txt"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Scan(root, Options{MaxFiles: 1}); err == nil {
		t.Fatal("expected file bound failure")
	}
}
