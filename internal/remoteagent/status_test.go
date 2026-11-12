package remoteagent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStatusRoundTripBindsSignedStatusToMTLSClient(t *testing.T) {
	agentPub, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := SignManifest(Manifest{
		AgentID: "agent-status", Platform: "windows", Architecture: "amd64",
		Capabilities: []string{"artifact.hash"}, TargetAllowlist: []string{"host"},
		MutualTLSRequired: true, NoRemoteShell: true,
		PublicKey:  base64.StdEncoding.EncodeToString(agentPub),
		ExpiresUTC: time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
	}, agentPriv)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := NewOperationLedger(filepath.Join(t.TempDir(), "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := NewAgentRuntime(manifest, agentPriv, ledger)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.RegisterCapability("artifact.hash", func(context.Context, JobRequest) (CapabilityResult, error) {
		return CapabilityResult{Body: []byte("{}")}, nil
	}); err != nil {
		t.Fatal(err)
	}

	pki := newTestPKI(t)
	serverTLS, err := LoadServerTLSConfig(pki.serverCert, pki.serverKey, pki.caCert)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.BindTLSConfig(serverTLS); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(runtime.Handler())
	server.TLS = serverTLS.Clone()
	server.StartTLS()
	defer server.Close()

	clientTLS, clientSHA, err := LoadClientTLSConfig(pki.clientCert, pki.clientKey, pki.caCert)
	if err != nil {
		t.Fatal(err)
	}
	status, observation, err := FetchStatus(context.Background(), server.URL, clientTLS, clientSHA)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyStatus(status, agentPub); err != nil {
		t.Fatal(err)
	}
	if status.AgentID != manifest.AgentID || status.ManifestSHA256 != ManifestIdentity(manifest) {
		t.Fatalf("status identity=%+v", status)
	}
	if status.ClientCertificateSHA256 != clientSHA || !observation.ServerCertificateVerified || !observation.ClientCertificateMatched {
		t.Fatalf("transport binding status=%+v observation=%+v", status, observation)
	}
	if status.CertificateNotAfterUTC != observation.ServerCertificateNotAfterUTC {
		t.Fatalf("signed cert expiry=%s observed=%s", status.CertificateNotAfterUTC, observation.ServerCertificateNotAfterUTC)
	}
	if len(status.RegisteredCapabilities) != 1 || status.RegisteredCapabilities[0] != "artifact.hash" {
		t.Fatalf("registered capabilities=%v", status.RegisteredCapabilities)
	}
}

func TestFleetStatusCurrentnessAndStateProjection(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := SignManifest(Manifest{
		AgentID: "fleet-1", Platform: "linux", Architecture: "amd64",
		Capabilities: []string{"artifact.metadata"}, MutualTLSRequired: true, NoRemoteShell: true,
		PublicKey:  base64.StdEncoding.EncodeToString(pub),
		ExpiresUTC: now.Add(time.Hour).Format(time.RFC3339),
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(filepath.Join(t.TempDir(), "agents"))
	if err != nil {
		t.Fatal(err)
	}
	registration, err := store.Register(manifest, "")
	if err != nil {
		t.Fatal(err)
	}
	if registration.ManifestSHA256 != ManifestIdentity(manifest) {
		t.Fatal("registration manifest identity mismatch")
	}
	clientSHA := ResultIdentity([]byte("client-cert"))
	serverSHA := ResultIdentity([]byte("server-cert"))
	expiry := now.Add(30 * 24 * time.Hour).Format(time.RFC3339Nano)
	status, err := SignStatus(StatusEnvelope{
		AgentID: "fleet-1", GeneratedUTC: now.Format(time.RFC3339Nano),
		ManifestSHA256: registration.ManifestSHA256, AgentVersion: "test",
		Platform: "linux", Architecture: "amd64", CertificateNotAfterUTC: expiry,
		DeclaredCapabilities:    []string{"artifact.metadata"},
		RegisteredCapabilities:  []string{"artifact.metadata"},
		ClientCertificateSHA256: clientSHA,
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	observation := TransportObservation{
		Endpoint:                "https://fleet-1.example/v1/status",
		ObservedUTC:             now.Add(time.Second).Format(time.RFC3339Nano),
		ServerCertificateSHA256: serverSHA, ServerCertificateNotAfterUTC: expiry,
		ClientCertificateSHA256:   clientSHA,
		ServerCertificateVerified: true, ClientCertificateMatched: true,
	}
	record, err := store.RecordStatus(status, observation, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.RecordStatus(status, observation, ""); err == nil {
		t.Fatal("existing status replacement without expected revision accepted")
	}
	fleet, err := store.ListFleet(now.Add(3*time.Minute), time.Minute, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(fleet) != 1 || fleet[0].State != "stale" || fleet[0].CertificateState != "valid" {
		t.Fatalf("fleet=%+v", fleet)
	}

	nextStatus := status
	nextStatus.GeneratedUTC = now.Add(2 * time.Second).Format(time.RFC3339Nano)
	nextStatus.Signature = ""
	nextStatus, err = SignStatus(nextStatus, priv)
	if err != nil {
		t.Fatal(err)
	}
	nextObservation := observation
	nextObservation.ObservedUTC = now.Add(3 * time.Second).Format(time.RFC3339Nano)
	if _, err := store.RecordStatus(nextStatus, nextObservation, record.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RecordStatus(status, observation, statusRecordRevision(StatusRecord{})); err == nil {
		t.Fatal("stale replay unexpectedly accepted")
	}
}

type testPKI struct {
	caCert, serverCert, serverKey, clientCert, clientKey string
}

func newTestPKI(t *testing.T) testPKI {
	t.Helper()
	root := t.TempDir()
	now := time.Now().UTC()
	caPub, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "RR Test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPub, caPriv)
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(root, "ca.pem")
	writePEM(t, caPath, "CERTIFICATE", caDER)

	serverCert, serverKey := issueTestLeaf(t, root, "server", 2, caTemplate, caPriv, x509.ExtKeyUsageServerAuth, []net.IP{net.ParseIP("127.0.0.1")})
	clientCert, clientKey := issueTestLeaf(t, root, "client", 3, caTemplate, caPriv, x509.ExtKeyUsageClientAuth, nil)
	return testPKI{caCert: caPath, serverCert: serverCert, serverKey: serverKey, clientCert: clientCert, clientKey: clientKey}
}

func issueTestLeaf(t *testing.T, root, name string, serial int64, ca *x509.Certificate, caKey ed25519.PrivateKey, usage x509.ExtKeyUsage, ips []net.IP) (string, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(12 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{usage}, IPAddresses: ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, pub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(root, name+".pem")
	keyPath := filepath.Join(root, name+".key")
	writePEM(t, certPath, "CERTIFICATE", der)
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, keyPath, "PRIVATE KEY", keyDER)
	return certPath, keyPath
}

func writePEM(t *testing.T, path, typ string, body []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: body}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestExpiredStoredManifestIsVisibleButNotAuthorized(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := Manifest{
		Version: ContractVersion, AgentID: "expired-agent", Platform: "linux", Architecture: "amd64",
		Capabilities: []string{"artifact.metadata"}, MutualTLSRequired: true, NoRemoteShell: true,
		PublicKey:  base64.StdEncoding.EncodeToString(pub),
		ExpiresUTC: now.Add(-time.Hour).Format(time.RFC3339),
	}
	manifest.Capabilities = clean(manifest.Capabilities)
	unsigned := manifest
	unsigned.Signature = ""
	body, err := json.Marshal(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, body))

	store, err := NewStore(filepath.Join(t.TempDir(), "agents"))
	if err != nil {
		t.Fatal(err)
	}
	registration := Registration{
		Manifest: manifest, ManifestSHA256: ManifestIdentity(manifest),
		RegisteredUTC: now.Add(-2 * time.Hour).Format(time.RFC3339Nano),
	}
	registration.Revision = registrationRevision(registration)
	regBody, err := json.MarshalIndent(registration, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	regBody = append(regBody, '\n')
	if err := os.WriteFile(store.path(manifest.AgentID), regBody, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(manifest.AgentID); err != nil {
		t.Fatalf("expired stored manifest should remain readable: %v", err)
	}
	fleet, err := store.ListFleet(now, time.Minute, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(fleet) != 1 || fleet[0].ManifestState != "expired" {
		t.Fatalf("fleet=%+v", fleet)
	}
	if err := ValidateJob(manifest, JobRequest{
		Version: ContractVersion, JobID: "j", OperationID: "o", Capability: "artifact.metadata", Target: "host",
	}); err == nil {
		t.Fatal("expired manifest authorized a job")
	}

	clientSHA := ResultIdentity([]byte("client"))
	serverSHA := ResultIdentity([]byte("server"))
	certExpiry := now.Add(time.Hour).Format(time.RFC3339Nano)
	status, err := SignStatus(StatusEnvelope{
		AgentID: manifest.AgentID, GeneratedUTC: now.Format(time.RFC3339Nano),
		ManifestSHA256: registration.ManifestSHA256, AgentVersion: "expired-test",
		Platform: manifest.Platform, Architecture: manifest.Architecture,
		CertificateNotAfterUTC: certExpiry,
		DeclaredCapabilities:   manifest.Capabilities, RegisteredCapabilities: manifest.Capabilities,
		ClientCertificateSHA256: clientSHA,
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	observation := TransportObservation{
		Endpoint:                "https://expired.example/v1/status",
		ObservedUTC:             now.Format(time.RFC3339Nano),
		ServerCertificateSHA256: serverSHA, ServerCertificateNotAfterUTC: certExpiry,
		ClientCertificateSHA256: clientSHA, ServerCertificateVerified: true, ClientCertificateMatched: true,
	}
	if _, err := store.RecordStatus(status, observation, ""); err == nil {
		t.Fatal("expired manifest accepted a fresh status authorization")
	}
}
