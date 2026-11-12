package remoteagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestAgentRuntimeRequiresMTLSAndPreventsReplay(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	manifest, err := SignManifest(Manifest{AgentID: "agent-1", Platform: "windows", Architecture: "x86-64", Capabilities: []string{"artifact.inspect"}, TargetAllowlist: []string{"lab-host"}, MutualTLSRequired: true, NoRemoteShell: true, PublicKey: base64.StdEncoding.EncodeToString(pub), ExpiresUTC: time.Now().UTC().Add(time.Hour).Format(time.RFC3339)}, priv)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := NewOperationLedger(filepath.Join(t.TempDir(), "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := NewAgentRuntime(manifest, priv, ledger)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	if err := runtime.RegisterCapability("artifact.inspect", func(_ context.Context, j JobRequest) (CapabilityResult, error) {
		calls.Add(1)
		return CapabilityResult{Body: []byte(`{"target":"ok"}`)}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := runtime.RegisterCapability("shell", func(context.Context, JobRequest) (CapabilityResult, error) { return CapabilityResult{}, nil }); err == nil {
		t.Fatal("shell handler accepted")
	}

	job := JobRequest{Version: 1, JobID: "job-1", OperationID: "operation:1", Capability: "artifact.inspect", Target: "lab-host"}
	body, _ := json.Marshal(job)
	req := httptest.NewRequest(http.MethodPost, "https://agent/v1/jobs", bytes.NewReader(body))
	req.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{&x509.Certificate{}}}}
	rec := httptest.NewRecorder()
	runtime.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var response JobResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if err := VerifyResult(response.Envelope, pub); err != nil {
		t.Fatal(err)
	}
	resultBody, err := base64.StdEncoding.DecodeString(response.ResultBase64)
	if err != nil {
		t.Fatal(err)
	}
	if response.Envelope.ResultSHA256 != ResultIdentity(resultBody) {
		t.Fatal("result body identity mismatch")
	}

	req2 := httptest.NewRequest(http.MethodPost, "https://agent/v1/jobs", bytes.NewReader(body))
	req2.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{&x509.Certificate{}}}}
	rec2 := httptest.NewRecorder()
	runtime.Handler().ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusConflict {
		t.Fatalf("duplicate status=%d body=%s", rec2.Code, rec2.Body.String())
	}
	if calls.Load() != 1 {
		t.Fatalf("handler calls=%d want=1", calls.Load())
	}

	req3 := httptest.NewRequest(http.MethodPost, "https://agent/v1/jobs", bytes.NewReader(body))
	rec3 := httptest.NewRecorder()
	runtime.Handler().ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusUnauthorized {
		t.Fatalf("missing mTLS status=%d", rec3.Code)
	}
}

func TestAgentRuntimeRejectsMultipleJSONValues(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	manifest, _ := SignManifest(Manifest{AgentID: "a", Platform: "linux", Architecture: "x86-64", Capabilities: []string{"artifact.inspect"}, TargetAllowlist: []string{"x"}, MutualTLSRequired: true, NoRemoteShell: true, PublicKey: base64.StdEncoding.EncodeToString(pub), ExpiresUTC: time.Now().UTC().Add(time.Hour).Format(time.RFC3339)}, priv)
	ledger, _ := NewOperationLedger(filepath.Join(t.TempDir(), "ledger"))
	runtime, _ := NewAgentRuntime(manifest, priv, ledger)
	_ = runtime.RegisterCapability("artifact.inspect", func(context.Context, JobRequest) (CapabilityResult, error) {
		return CapabilityResult{Body: []byte("ok")}, nil
	})
	req := httptest.NewRequest(http.MethodPost, "https://agent/v1/jobs", bytes.NewBufferString(`{"version":1,"job_id":"a","operation_id":"a","capability":"artifact.inspect","target":"x"} {}`))
	req.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{&x509.Certificate{}}}}
	rec := httptest.NewRecorder()
	runtime.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestOperationLedgerHandlesFilenameUnsafeOperationID(t *testing.T) {
	ledger, err := NewOperationLedger(filepath.Join(t.TempDir(), "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	j := JobRequest{Version: 1, JobID: "j", OperationID: "tenant:job:1", Capability: "artifact.inspect", Target: "x"}
	if _, err := ledger.Begin(j); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Complete(j.OperationID, "applied"); err != nil {
		t.Fatal(err)
	}
	got, err := ledger.Get(j.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != "applied" {
		t.Fatalf("receipt=%+v", got)
	}
}
