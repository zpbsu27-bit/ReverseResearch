package server

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"reverseresearch/internal/casebook"
	"reverseresearch/internal/packregistry"
	"reverseresearch/internal/remoteagent"
)

func TestP3ProductToolsEnforceVerificationAndCurrentness(t *testing.T) {
	root, _ := isolatedServerRoot(t)
	runtime, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	c, err := runtime.core.CreateCase(casebook.CreateRequest{Title: "p3"})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	st, ct := mcp.NewInMemoryTransports()
	go func() { _ = runtime.Run(ctx, st) }()
	client := mcp.NewClient(&mcp.Implementation{Name: "p3-test", Version: "1"}, nil)
	session, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	call := func(name string, args map[string]any, out any) {
		t.Helper()
		res, callErr := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if callErr != nil || res == nil || res.IsError {
			t.Fatalf("%s failed result=%#v err=%v", name, res, callErr)
		}
		if out != nil {
			decodeStructured(t, res.StructuredContent, out)
		}
	}

	var policy struct {
		Allowed bool `json:"allowed"`
	}
	call("rbac_check", map[string]any{"role": "reviewer", "action": "report.finalize"}, &policy)
	if !policy.Allowed {
		t.Fatal("reviewer finalization unexpectedly denied")
	}

	var workspace struct {
		Revision  string `json:"revision"`
		CaseOwner string `json:"case_owner"`
	}
	call("collaboration_apply", map[string]any{"operation": "init", "case_id": c.ID, "owner": "alice"}, &workspace)
	if workspace.Revision == "" || workspace.CaseOwner != "alice" {
		t.Fatalf("workspace=%+v", workspace)
	}
	call("collaboration_apply", map[string]any{"operation": "add_participant", "case_id": c.ID, "expected_revision": workspace.Revision, "actor": "alice", "subject": "bob", "role": "reviewer"}, &workspace)
	var loaded struct {
		Revision string `json:"revision"`
	}
	call("collaboration_get", map[string]any{"case_id": c.ID, "actor": "bob"}, &loaded)
	if loaded.Revision != workspace.Revision {
		t.Fatalf("loaded=%+v workspace=%+v", loaded, workspace)
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
	call("collaboration_apply", map[string]any{"operation": "review_request", "case_id": c.ID, "expected_revision": workspace.Revision, "actor": "alice", "kind": "case", "subject_id": c.ID}, &requested)
	if requested.Workspace.Revision == "" || requested.Review.ID == "" || requested.Review.Status != "pending" {
		t.Fatalf("requested=%+v", requested)
	}
	workspace.Revision = requested.Workspace.Revision
	var reviewQueue []struct {
		State string `json:"state"`
	}
	call("collaboration_get", map[string]any{"case_id": c.ID, "actor": "bob", "view": "review_queue"}, &reviewQueue)
	if len(reviewQueue) != 1 || reviewQueue[0].State != "pending" {
		t.Fatalf("review queue=%+v", reviewQueue)
	}
	var history []struct {
		Action string `json:"action"`
	}
	call("collaboration_get", map[string]any{"case_id": c.ID, "actor": "alice", "view": "history"}, &history)
	if len(history) == 0 || history[len(history)-1].Action != "review.request" {
		t.Fatalf("history=%+v", history)
	}

	reportPath := filepath.Join(root, "p3-report.json")
	var report struct {
		ContentSHA256 string `json:"content_sha256"`
		Output        struct {
			SHA256 string `json:"sha256"`
		} `json:"output"`
	}
	call("report_render", map[string]any{"case_id": c.ID, "profile": "general", "format": "json", "status": "draft", "sections": []string{"summary", "evidence"}, "output_path": reportPath}, &report)
	if report.ContentSHA256 == "" || report.Output.SHA256 != report.ContentSHA256 {
		t.Fatalf("report=%+v", report)
	}
	reportBody, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	var filtered struct {
		Sections []string `json:"sections"`
		Findings []any    `json:"findings"`
	}
	if err := json.Unmarshal(reportBody, &filtered); err != nil {
		t.Fatal(err)
	}
	if len(filtered.Sections) != 2 || filtered.Findings != nil {
		t.Fatalf("filtered report=%+v", filtered)
	}
	dashboardPath := filepath.Join(root, "dashboard.html")
	var dashboard struct {
		ContentSHA256 string `json:"content_sha256"`
		Output        struct {
			SHA256 string `json:"sha256"`
		} `json:"output"`
	}
	call("dashboard_render", map[string]any{"case_id": c.ID, "actor": "alice", "output_path": dashboardPath}, &dashboard)
	if dashboard.ContentSHA256 == "" || dashboard.Output.SHA256 != dashboard.ContentSHA256 {
		t.Fatalf("dashboard=%+v", dashboard)
	}

	pub, priv, _ := ed25519.GenerateKey(nil)
	manifest, err := remoteagent.SignManifest(remoteagent.Manifest{AgentID: "agent-1", Platform: "windows", Architecture: "x86-64", Capabilities: []string{"artifact.inspect"}, TargetAllowlist: []string{"lab-host"}, MutualTLSRequired: true, NoRemoteShell: true, PublicKey: base64.StdEncoding.EncodeToString(pub), ExpiresUTC: time.Now().UTC().Add(time.Hour).Format(time.RFC3339)}, priv)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "agent.json")
	writeP3JSON(t, manifestPath, manifest)
	call("remote_agent_manage", map[string]any{"operation": "register", "manifest_path": manifestPath, "authority_role": "owner"}, nil)
	jobPath := filepath.Join(root, "job.json")
	writeP3JSON(t, jobPath, remoteagent.JobRequest{Version: 1, JobID: "j1", OperationID: "op1", Capability: "artifact.inspect", Target: "lab-host"})
	var validated struct {
		Valid              bool `json:"valid"`
		ExecutionPerformed bool `json:"execution_performed"`
	}
	call("remote_agent_manage", map[string]any{"operation": "validate_job", "agent_id": "agent-1", "job_path": jobPath}, &validated)
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
	pmPath := filepath.Join(root, "manifest.json")
	writeP3JSON(t, pmPath, pm)
	trustPath := filepath.Join(root, "trust.json")
	writeP3JSON(t, trustPath, packregistry.TrustStore{Keys: map[string]string{"lab": base64.StdEncoding.EncodeToString(pub)}})
	var verified struct {
		Verification struct {
			Verified bool `json:"verified"`
		} `json:"verification"`
	}
	call("pack_verify", map[string]any{"root": packRoot, "manifest_path": pmPath, "trust_path": trustPath}, &verified)
	if !verified.Verification.Verified {
		t.Fatalf("pack=%+v", verified)
	}

	var registry struct {
		Revision string `json:"revision"`
	}
	call("pack_registry", map[string]any{
		"operation": "trust_add", "authority_role": "owner", "key_id": "lab",
		"public_key": base64.StdEncoding.EncodeToString(pub), "publisher": "lab",
	}, &registry)
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
	call("pack_registry", map[string]any{
		"operation": "verify", "authority_role": "analyst", "expected_revision": registry.Revision,
		"root": packRoot, "manifest_path": pmPath,
	}, &recorded)
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
	call("pack_registry", map[string]any{
		"operation": "activate", "authority_role": "owner", "expected_revision": recorded.State.Revision,
		"receipt_id": recorded.Receipt.ID,
	}, &activated)
	if activated.State.Revision == "" || activated.Pack.Status != "active" {
		t.Fatalf("activated=%+v", activated)
	}
	var active struct {
		Pack struct {
			ReceiptID string `json:"receipt_id"`
		} `json:"pack"`
	}
	call("pack_registry", map[string]any{"operation": "active", "authority_role": "analyst", "pack_id": "demo"}, &active)
	if active.Pack.ReceiptID != recorded.Receipt.ID {
		t.Fatalf("active=%+v", active)
	}
	var entry struct {
		Body []byte `json:"body"`
	}
	call("pack_registry", map[string]any{"operation": "read_entrypoint", "authority_role": "analyst", "pack_id": "demo", "entrypoint": "data"}, &entry)
	if string(entry.Body) != "pack" {
		t.Fatalf("entry body=%q", entry.Body)
	}
}

func writeP3JSON(t *testing.T, path string, value any) {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}
