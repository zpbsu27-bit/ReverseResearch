package remoteagent

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
	"time"
)

func TestSignedManifestAndBoundedJob(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	m, err := SignManifest(Manifest{AgentID: "agent-1", Platform: "windows", Architecture: "x86-64", Capabilities: []string{"artifact.inspect", "job.collect"}, TargetAllowlist: []string{"host-1"}, MutualTLSRequired: true, NoRemoteShell: true, PublicKey: base64.StdEncoding.EncodeToString(pub), ExpiresUTC: time.Now().UTC().Add(time.Hour).Format(time.RFC3339)}, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyManifest(m); err != nil {
		t.Fatal(err)
	}
	if err := ValidateJob(m, JobRequest{Version: 1, JobID: "j1", OperationID: "op1", Capability: "artifact.inspect", Target: "host-1"}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateJob(m, JobRequest{Version: 1, JobID: "j2", OperationID: "op2", Capability: "shell", Target: "host-1"}); err == nil {
		t.Fatal("remote shell accepted")
	}
	if err := ValidateJob(m, JobRequest{Version: 1, JobID: "j3", OperationID: "op3", Capability: "artifact.inspect", Target: "host-2"}); err == nil {
		t.Fatal("out-of-scope target accepted")
	}
}
func TestSignedResultFailsOnTamper(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	r, err := SignResult(ResultEnvelope{AgentID: "a", JobID: "j", OperationID: "o", State: "applied", ResultSHA256: ResultIdentity([]byte("result")), CompletedUTC: time.Now().UTC().Format(time.RFC3339)}, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyResult(r, pub); err != nil {
		t.Fatal(err)
	}
	r.State = "failed"
	if err := VerifyResult(r, pub); err == nil {
		t.Fatal("tampered result verified")
	}
}

func TestManifestRejectsPowerShellCapability(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	_, err := SignManifest(Manifest{
		AgentID: "agent-danger", Platform: "windows", Architecture: "amd64",
		Capabilities: []string{"powershell"}, MutualTLSRequired: true, NoRemoteShell: true,
		PublicKey:  base64.StdEncoding.EncodeToString(pub),
		ExpiresUTC: time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
	}, priv)
	if err == nil {
		t.Fatal("manifest accepted PowerShell capability")
	}
}
