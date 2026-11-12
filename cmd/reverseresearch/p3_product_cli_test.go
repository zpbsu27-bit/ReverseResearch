package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"reverseresearch/internal/casebook"
	"reverseresearch/internal/packregistry"
	"reverseresearch/internal/remoteagent"
)

func TestP3CLIProductFlows(t *testing.T) {
	root, _ := isolatedCLIRoot(t)
	var c casebook.Case
	if err := json.Unmarshal(p0CLI(t, root, "case", "create", "--title", "p3-cli"), &c); err != nil {
		t.Fatal(err)
	}

	reportPath := filepath.Join(root, "report.json")
	var report struct {
		ContentSHA256 string `json:"content_sha256"`
		Output        struct {
			SHA256 string `json:"sha256"`
		} `json:"output"`
	}
	if err := json.Unmarshal(p0CLI(t, root, "report", "render", c.ID, "--profile", "general", "--format", "json", "--section", "summary,evidence", "--out", reportPath), &report); err != nil {
		t.Fatal(err)
	}
	if report.ContentSHA256 == "" || report.Output.SHA256 != report.ContentSHA256 {
		t.Fatalf("report=%+v", report)
	}
	reportBody, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	var filteredDoc struct {
		Sections []string `json:"sections"`
		Findings []any    `json:"findings"`
	}
	if err := json.Unmarshal(reportBody, &filteredDoc); err != nil {
		t.Fatal(err)
	}
	if len(filteredDoc.Sections) != 2 || filteredDoc.Findings != nil {
		t.Fatalf("filtered report=%+v", filteredDoc)
	}
	var stdout, stderr bytes.Buffer
	if err := runCLI(context.Background(), root, []string{"report", "render", c.ID, "--profile", "general", "--format", "json", "--out", reportPath}, &stdout, &stderr); err == nil {
		t.Fatal("report overwrite without expected SHA accepted")
	}
	var replaced struct {
		Output struct {
			SHA256 string `json:"sha256"`
		} `json:"output"`
	}
	if err := json.Unmarshal(p0CLI(t, root, "report", "render", c.ID, "--profile", "general", "--format", "json", "--out", reportPath, "--expected-output-sha", report.Output.SHA256), &replaced); err != nil {
		t.Fatal(err)
	}
	if replaced.Output.SHA256 == "" {
		t.Fatal("replacement output identity missing")
	}

	var workspace struct {
		Revision  string `json:"revision"`
		CaseOwner string `json:"case_owner"`
	}
	if err := json.Unmarshal(p0CLI(t, root, "collab", "init", c.ID, "--owner", "alice"), &workspace); err != nil {
		t.Fatal(err)
	}
	if workspace.Revision == "" || workspace.CaseOwner != "alice" {
		t.Fatalf("workspace=%+v", workspace)
	}
	if err := json.Unmarshal(p0CLI(t, root, "collab", "participant", c.ID, "--expected-revision", workspace.Revision, "--actor", "alice", "--subject", "bob", "--role", "reviewer"), &workspace); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Revision string `json:"revision"`
	}
	if err := json.Unmarshal(p0CLI(t, root, "collab", "get", c.ID, "--actor", "bob"), &got); err != nil {
		t.Fatal(err)
	}
	if got.Revision != workspace.Revision {
		t.Fatalf("got=%+v workspace=%+v", got, workspace)
	}
	var requested struct {
		Workspace struct {
			Revision string `json:"revision"`
		} `json:"workspace"`
		Review struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"review"`
	}
	if err := json.Unmarshal(p0CLI(t, root, "collab", "review-request", c.ID, "--expected-revision", workspace.Revision, "--actor", "alice", "--kind", "case", "--subject-id", c.ID), &requested); err != nil {
		t.Fatal(err)
	}
	if requested.Workspace.Revision == "" || requested.Review.ID == "" || requested.Review.Status != "pending" {
		t.Fatalf("requested=%+v", requested)
	}
	workspace.Revision = requested.Workspace.Revision
	var reviewQueue []struct {
		State string `json:"state"`
	}
	if err := json.Unmarshal(p0CLI(t, root, "collab", "review-queue", c.ID, "--actor", "bob"), &reviewQueue); err != nil {
		t.Fatal(err)
	}
	if len(reviewQueue) != 1 || reviewQueue[0].State != "pending" {
		t.Fatalf("review queue=%+v", reviewQueue)
	}
	var history []struct {
		Action string `json:"action"`
	}
	if err := json.Unmarshal(p0CLI(t, root, "collab", "history", c.ID, "--actor", "alice"), &history); err != nil {
		t.Fatal(err)
	}
	if len(history) == 0 || history[len(history)-1].Action != "review.request" {
		t.Fatalf("history=%+v", history)
	}

	dashboardPath := filepath.Join(root, "dashboard.html")
	var dashboard struct {
		ContentSHA256 string `json:"content_sha256"`
		Output        struct {
			SHA256 string `json:"sha256"`
		} `json:"output"`
	}
	if err := json.Unmarshal(p0CLI(t, root, "dashboard", "render", c.ID, "--actor", "alice", "--out", dashboardPath), &dashboard); err != nil {
		t.Fatal(err)
	}
	if dashboard.ContentSHA256 == "" || dashboard.Output.SHA256 != dashboard.ContentSHA256 {
		t.Fatalf("dashboard=%+v", dashboard)
	}
	body, err := os.ReadFile(dashboardPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte("Collaboration")) || !bytes.Contains(body, []byte("Review queue")) || !bytes.Contains(body, []byte(requested.Review.ID)) {
		t.Fatal("dashboard collaboration review queue missing")
	}

	var decision struct {
		Allowed bool `json:"allowed"`
	}
	if err := json.Unmarshal(p0CLI(t, root, "rbac", "check", "--role", "reviewer", "--action", "report.finalize"), &decision); err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed {
		t.Fatal("expected reviewer report.finalize allow")
	}

	pub, priv, _ := ed25519.GenerateKey(nil)
	manifest, err := remoteagent.SignManifest(remoteagent.Manifest{AgentID: "agent-cli", Platform: "windows", Architecture: "x86-64", Capabilities: []string{"artifact.inspect"}, TargetAllowlist: []string{"lab-host"}, MutualTLSRequired: true, NoRemoteShell: true, PublicKey: base64.StdEncoding.EncodeToString(pub), ExpiresUTC: time.Now().UTC().Add(time.Hour).Format(time.RFC3339)}, priv)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "agent.json")
	writeP3CLITestJSON(t, manifestPath, manifest)
	p0CLI(t, root, "agent", "register", manifestPath, "--authority-role", "owner")
	jobPath := filepath.Join(root, "job.json")
	writeP3CLITestJSON(t, jobPath, remoteagent.JobRequest{Version: 1, JobID: "j", OperationID: "o", Capability: "artifact.inspect", Target: "lab-host"})
	var validated struct {
		Valid              bool `json:"valid"`
		ExecutionPerformed bool `json:"execution_performed"`
	}
	if err := json.Unmarshal(p0CLI(t, root, "agent", "validate-job", "agent-cli", "--job", jobPath), &validated); err != nil {
		t.Fatal(err)
	}
	if !validated.Valid || validated.ExecutionPerformed {
		t.Fatalf("validated=%+v", validated)
	}

	packRoot := filepath.Join(root, "pack")
	if err := os.MkdirAll(packRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packRoot, "data.txt"), []byte("pack"), 0o600); err != nil {
		t.Fatal(err)
	}
	pm, err := packregistry.Build(packRoot, packregistry.Manifest{ID: "demo", PackVersion: "1", Kind: "plugin", Publisher: "lab", PublicKeyID: "lab", Entrypoints: []packregistry.Entrypoint{{Name: "data", Kind: "data", Path: "data.txt"}}})
	if err != nil {
		t.Fatal(err)
	}
	pm, err = packregistry.Sign(pm, priv)
	if err != nil {
		t.Fatal(err)
	}
	pmPath := filepath.Join(root, "pack-manifest.json")
	writeP3CLITestJSON(t, pmPath, pm)
	trustPath := filepath.Join(root, "trust.json")
	writeP3CLITestJSON(t, trustPath, packregistry.TrustStore{Keys: map[string]string{"lab": base64.StdEncoding.EncodeToString(pub)}})
	var pack struct {
		Verification struct {
			Verified bool `json:"verified"`
		} `json:"verification"`
	}
	if err := json.Unmarshal(p0CLI(t, root, "pack", "verify", "--root", packRoot, "--manifest", pmPath, "--trust", trustPath), &pack); err != nil {
		t.Fatal(err)
	}
	if !pack.Verification.Verified {
		t.Fatalf("pack=%+v", pack)
	}

	var registry struct {
		Revision string `json:"revision"`
	}
	if err := json.Unmarshal(p0CLI(t, root, "pack", "trust-add", "--authority-role", "owner", "--key-id", "lab", "--public-key", base64.StdEncoding.EncodeToString(pub), "--publisher", "Lab"), &registry); err != nil {
		t.Fatal(err)
	}
	if registry.Revision == "" {
		t.Fatal("registry revision missing")
	}
	var recorded struct {
		Receipt struct {
			ID               string `json:"id"`
			RegistryRevision string `json:"registry_revision"`
		} `json:"receipt"`
		State struct {
			Revision string `json:"revision"`
		} `json:"state"`
	}
	if err := json.Unmarshal(p0CLI(t, root, "pack", "verify-registry", "--authority-role", "analyst", "--expected-revision", registry.Revision, "--root", packRoot, "--manifest", pmPath), &recorded); err != nil {
		t.Fatal(err)
	}
	if recorded.Receipt.ID == "" || recorded.Receipt.RegistryRevision == "" || recorded.State.Revision == "" {
		t.Fatalf("recorded=%+v", recorded)
	}
	var activated struct {
		State struct {
			Revision string `json:"revision"`
		} `json:"state"`
		Pack struct {
			Status string `json:"status"`
		} `json:"pack"`
	}
	if err := json.Unmarshal(p0CLI(t, root, "pack", "activate", "--authority-role", "owner", "--expected-revision", recorded.State.Revision, "--receipt-id", recorded.Receipt.ID), &activated); err != nil {
		t.Fatal(err)
	}
	if activated.State.Revision == "" || activated.Pack.Status != "active" {
		t.Fatalf("activated=%+v", activated)
	}
	var active struct {
		Pack struct {
			ReceiptID string `json:"receipt_id"`
		} `json:"pack"`
	}
	if err := json.Unmarshal(p0CLI(t, root, "pack", "active", "--authority-role", "analyst", "--pack-id", "demo"), &active); err != nil {
		t.Fatal(err)
	}
	if active.Pack.ReceiptID != recorded.Receipt.ID {
		t.Fatalf("active=%+v", active)
	}
	var entry struct {
		Body []byte `json:"body"`
	}
	if err := json.Unmarshal(p0CLI(t, root, "pack", "read-entrypoint", "--authority-role", "analyst", "--pack-id", "demo", "--entrypoint", "data"), &entry); err != nil {
		t.Fatal(err)
	}
	if string(entry.Body) != "pack" {
		t.Fatalf("entry body=%q", entry.Body)
	}
}

func writeP3CLITestJSON(t *testing.T, path string, value any) {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}
