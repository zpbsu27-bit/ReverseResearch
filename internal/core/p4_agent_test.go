package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"reverseresearch/internal/remoteagent"
)

func TestP4AgentFleetServiceAndReadOnlyProjection(t *testing.T) {
	root, _ := isolatedCoreRoot(t)
	service, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	agentStateRoot := filepath.Join(root, "state", "remote-agents")
	if _, err := os.Stat(agentStateRoot); !os.IsNotExist(err) {
		t.Fatalf("remote agent state unexpectedly exists before use: %v", err)
	}
	fleet, err := service.dashboardAgentFleetProjection()
	if err != nil {
		t.Fatal(err)
	}
	if len(fleet) != 0 {
		t.Fatalf("unexpected fleet before registration: %+v", fleet)
	}
	if _, err := os.Stat(agentStateRoot); !os.IsNotExist(err) {
		t.Fatal("read-only dashboard projection created remote-agent state")
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := remoteagent.SignManifest(remoteagent.Manifest{
		AgentID: "core-agent", Platform: "windows", Architecture: "amd64",
		Capabilities: []string{"artifact.metadata"}, MutualTLSRequired: true, NoRemoteShell: true,
		PublicKey:  base64.StdEncoding.EncodeToString(pub),
		ExpiresUTC: time.Now().UTC().Add(30 * 24 * time.Hour).Format(time.RFC3339),
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "agent-manifest.json")
	if err := os.WriteFile(manifestPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	registered, err := service.RegisterRemoteAgent(RemoteAgentRegisterRequest{
		ManifestPath: manifestPath, AuthorityRole: "owner",
	})
	if err != nil {
		t.Fatal(err)
	}
	if registered.Registration.Manifest.AgentID != "core-agent" {
		t.Fatalf("registration=%+v", registered)
	}
	fleet, err = service.ListRemoteAgentFleet(RemoteAgentFleetRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(fleet) != 1 || fleet[0].State != "unseen" || fleet[0].CertificateState != "unknown" || fleet[0].ManifestState != "valid" {
		t.Fatalf("fleet=%+v", fleet)
	}
	if _, err := service.ListRemoteAgentFleet(RemoteAgentFleetRequest{StaleAfterSeconds: 10, OfflineAfterSeconds: 10}); err == nil {
		t.Fatal("invalid fleet thresholds accepted")
	}
}

func TestP4RefreshStatusRequiresAgentManageAuthority(t *testing.T) {
	root, _ := isolatedCoreRoot(t)
	service, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.RefreshRemoteAgentStatus(RemoteAgentStatusRefreshRequest{
		AgentID: "missing", Endpoint: "https://127.0.0.1:1",
		ClientCertPath: "missing", ClientKeyPath: "missing", ServerCAPath: "missing",
		AuthorityRole: "viewer",
	})
	if err == nil {
		t.Fatal("viewer unexpectedly allowed to refresh remote-agent status")
	}
}
