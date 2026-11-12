package remoteagent

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"reverseresearch/internal/recordio"
)

const MaxStatusBodyBytes int64 = 1 << 20

type OperationStats struct {
	Total      int `json:"total"`
	Running    int `json:"running"`
	Applied    int `json:"applied"`
	Failed     int `json:"failed"`
	Uncertain  int `json:"uncertain"`
	RolledBack int `json:"rolled_back"`
	Cancelled  int `json:"cancelled"`
	// Unreadable counts receipts that could not be decoded or carried an unknown
	// state. It is deliberately outside the Total == sum-of-states invariant so
	// broken records are visible without blocking operations.
	Unreadable int `json:"unreadable,omitempty"`
}

type QueueStatus struct {
	QueuedJobs      int `json:"queued_jobs"`
	RunningJobs     int `json:"running_jobs"`
	TerminalResults int `json:"terminal_results"`
}

type StatusEnvelope struct {
	Version                 int            `json:"version"`
	AgentID                 string         `json:"agent_id"`
	GeneratedUTC            string         `json:"generated_utc"`
	ManifestSHA256          string         `json:"manifest_sha256"`
	AgentVersion            string         `json:"agent_version"`
	Platform                string         `json:"platform"`
	Architecture            string         `json:"architecture"`
	CertificateNotAfterUTC  string         `json:"certificate_not_after_utc,omitempty"`
	DeclaredCapabilities    []string       `json:"declared_capabilities"`
	RegisteredCapabilities  []string       `json:"registered_capabilities"`
	Operations              OperationStats `json:"operations"`
	Queue                   QueueStatus    `json:"queue"`
	ClientCertificateSHA256 string         `json:"client_certificate_sha256"`
	Signature               string         `json:"signature,omitempty"`
}

type TransportObservation struct {
	Endpoint                     string `json:"endpoint"`
	ObservedUTC                  string `json:"observed_utc"`
	ServerCertificateSHA256      string `json:"server_certificate_sha256"`
	ServerCertificateNotAfterUTC string `json:"server_certificate_not_after_utc"`
	ClientCertificateSHA256      string `json:"client_certificate_sha256"`
	ServerCertificateVerified    bool   `json:"server_certificate_verified"`
	ClientCertificateMatched     bool   `json:"client_certificate_matched"`
}

func ManifestIdentity(m Manifest) string {
	body, _ := json.Marshal(m)
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func SignStatus(status StatusEnvelope, private ed25519.PrivateKey) (StatusEnvelope, error) {
	status.Version = ContractVersion
	status.AgentID = strings.TrimSpace(status.AgentID)
	status.GeneratedUTC = strings.TrimSpace(status.GeneratedUTC)
	status.ManifestSHA256 = strings.ToLower(strings.TrimSpace(status.ManifestSHA256))
	status.AgentVersion = strings.TrimSpace(status.AgentVersion)
	status.Platform = strings.TrimSpace(status.Platform)
	status.Architecture = strings.TrimSpace(status.Architecture)
	status.CertificateNotAfterUTC = strings.TrimSpace(status.CertificateNotAfterUTC)
	status.DeclaredCapabilities = clean(status.DeclaredCapabilities)
	status.RegisteredCapabilities = clean(status.RegisteredCapabilities)
	status.ClientCertificateSHA256 = strings.ToLower(strings.TrimSpace(status.ClientCertificateSHA256))
	status.Signature = ""
	if err := validateStatus(status); err != nil {
		return StatusEnvelope{}, err
	}
	body, err := json.Marshal(status)
	if err != nil {
		return StatusEnvelope{}, err
	}
	status.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, body))
	return status, nil
}

func VerifyStatus(status StatusEnvelope, public ed25519.PublicKey) error {
	if err := validateStatus(status); err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(status.Signature)
	if err != nil {
		return errors.New("invalid status signature encoding")
	}
	copyStatus := status
	copyStatus.Signature = ""
	copyStatus.DeclaredCapabilities = clean(copyStatus.DeclaredCapabilities)
	copyStatus.RegisteredCapabilities = clean(copyStatus.RegisteredCapabilities)
	body, err := json.Marshal(copyStatus)
	if err != nil {
		return err
	}
	if !ed25519.Verify(public, body, sig) {
		return errors.New("status signature verification failed")
	}
	return nil
}

func validateStatus(status StatusEnvelope) error {
	if status.Version != ContractVersion {
		return fmt.Errorf("unsupported status contract version %d", status.Version)
	}
	if status.AgentID == "" || status.GeneratedUTC == "" || status.Platform == "" || status.Architecture == "" {
		return errors.New("agent_id, generated_utc, platform, and architecture are required")
	}
	if !validSHA(status.ManifestSHA256) {
		return errors.New("manifest_sha256 must be SHA-256")
	}
	if !validSHA(status.ClientCertificateSHA256) {
		return errors.New("client_certificate_sha256 must be SHA-256")
	}
	if _, err := time.Parse(time.RFC3339Nano, status.GeneratedUTC); err != nil {
		if _, fallbackErr := time.Parse(time.RFC3339, status.GeneratedUTC); fallbackErr != nil {
			return errors.New("invalid generated_utc")
		}
	}
	if status.CertificateNotAfterUTC != "" {
		if _, err := time.Parse(time.RFC3339Nano, status.CertificateNotAfterUTC); err != nil {
			if _, fallbackErr := time.Parse(time.RFC3339, status.CertificateNotAfterUTC); fallbackErr != nil {
				return errors.New("invalid certificate_not_after_utc")
			}
		}
	}
	if status.Operations.Total < 0 || status.Operations.Running < 0 || status.Queue.QueuedJobs < 0 || status.Queue.RunningJobs < 0 || status.Queue.TerminalResults < 0 {
		return errors.New("status counters cannot be negative")
	}
	return nil
}

func (a *AgentRuntime) BindTLSConfig(config *tls.Config) error {
	if config == nil || len(config.Certificates) == 0 || len(config.Certificates[0].Certificate) == 0 {
		return errors.New("agent TLS server certificate is required")
	}
	leaf := config.Certificates[0].Leaf
	if leaf == nil {
		var err error
		leaf, err = x509.ParseCertificate(config.Certificates[0].Certificate[0])
		if err != nil {
			return fmt.Errorf("parse agent TLS server certificate: %w", err)
		}
	}
	a.mu.Lock()
	a.serverCertificateNotAfter = leaf.NotAfter.UTC().Format(time.RFC3339Nano)
	a.mu.Unlock()
	return nil
}

func (a *AgentRuntime) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !verifiedClient(r) {
		http.Error(w, "mTLS client certificate required", http.StatusUnauthorized)
		return
	}
	if len(r.TLS.PeerCertificates) == 0 || len(r.TLS.PeerCertificates[0].Raw) == 0 {
		http.Error(w, "verified client certificate missing", http.StatusUnauthorized)
		return
	}
	clientSum := sha256.Sum256(r.TLS.PeerCertificates[0].Raw)
	stats, err := a.ledger.Stats()
	if err != nil {
		http.Error(w, "operation ledger status unavailable", http.StatusInternalServerError)
		return
	}
	a.mu.RLock()
	registered := make([]string, 0, len(a.handlers))
	for name := range a.handlers {
		registered = append(registered, name)
	}
	sort.Strings(registered)
	certExpiry := a.serverCertificateNotAfter
	a.mu.RUnlock()
	agentVersion := "(devel)"
	if info, ok := debug.ReadBuildInfo(); ok && strings.TrimSpace(info.Main.Version) != "" {
		agentVersion = info.Main.Version
	}
	status, err := SignStatus(StatusEnvelope{
		AgentID:                a.manifest.AgentID,
		GeneratedUTC:           time.Now().UTC().Format(time.RFC3339Nano),
		ManifestSHA256:         ManifestIdentity(a.manifest),
		AgentVersion:           agentVersion,
		Platform:               a.manifest.Platform,
		Architecture:           a.manifest.Architecture,
		CertificateNotAfterUTC: certExpiry,
		DeclaredCapabilities:   a.manifest.Capabilities,
		RegisteredCapabilities: registered,
		Operations:             stats,
		Queue: QueueStatus{
			QueuedJobs:      0,
			RunningJobs:     stats.Running,
			TerminalResults: stats.Total - stats.Running,
		},
		ClientCertificateSHA256: hex.EncodeToString(clientSum[:]),
	}, a.privateKey)
	if err != nil {
		http.Error(w, "status signing failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	writeHTTPJSON(w, status)
}

func LoadClientTLSConfig(certFile, keyFile, serverCAFile string) (*tls.Config, string, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, "", err
	}
	if len(cert.Certificate) == 0 {
		return nil, "", errors.New("client certificate chain is empty")
	}
	clientSum := sha256.Sum256(cert.Certificate[0])
	caBody, err := osReadFile(serverCAFile)
	if err != nil {
		return nil, "", err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBody) {
		return nil, "", errors.New("no server CA certificate loaded")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
	}, hex.EncodeToString(clientSum[:]), nil
}

var osReadFile = func(path string) ([]byte, error) {
	return recordio.ReadFileLimit(path, MaxTLSPEMBytes)
}

func FetchStatus(ctx context.Context, endpoint string, tlsConfig *tls.Config, clientCertificateSHA256 string) (StatusEnvelope, TransportObservation, error) {
	if tlsConfig == nil {
		return StatusEnvelope{}, TransportObservation{}, errors.New("TLS config is required")
	}
	clientCertificateSHA256 = strings.ToLower(strings.TrimSpace(clientCertificateSHA256))
	if !validSHA(clientCertificateSHA256) {
		return StatusEnvelope{}, TransportObservation{}, errors.New("client certificate SHA-256 is required")
	}
	u, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil {
		return StatusEnvelope{}, TransportObservation{}, err
	}
	if u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return StatusEnvelope{}, TransportObservation{}, errors.New("endpoint must be an https URL without userinfo, query, or fragment")
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/v1/status"
	u.RawPath = ""
	transport := &http.Transport{TLSClientConfig: tlsConfig.Clone(), ForceAttemptHTTP2: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return StatusEnvelope{}, TransportObservation{}, err
	}
	response, err := client.Do(request)
	if err != nil {
		return StatusEnvelope{}, TransportObservation{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return StatusEnvelope{}, TransportObservation{}, fmt.Errorf("status endpoint returned %s: %s", response.Status, strings.TrimSpace(string(body)))
	}
	if response.TLS == nil || len(response.TLS.VerifiedChains) == 0 || len(response.TLS.PeerCertificates) == 0 {
		return StatusEnvelope{}, TransportObservation{}, errors.New("status endpoint did not provide a verified TLS server certificate")
	}
	limited := io.LimitReader(response.Body, MaxStatusBodyBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return StatusEnvelope{}, TransportObservation{}, err
	}
	if int64(len(body)) > MaxStatusBodyBytes {
		return StatusEnvelope{}, TransportObservation{}, errors.New("status response exceeds size limit")
	}
	var status StatusEnvelope
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&status); err != nil {
		return StatusEnvelope{}, TransportObservation{}, fmt.Errorf("decode status: %w", err)
	}
	if err := remoteEOF(dec); err != nil {
		return StatusEnvelope{}, TransportObservation{}, errors.New("multiple JSON values are not allowed in status response")
	}
	if strings.ToLower(status.ClientCertificateSHA256) != clientCertificateSHA256 {
		return StatusEnvelope{}, TransportObservation{}, errors.New("agent did not bind status to the configured client certificate")
	}
	peer := response.TLS.PeerCertificates[0]
	peerSum := sha256.Sum256(peer.Raw)
	return status, TransportObservation{
		Endpoint:                     u.String(),
		ObservedUTC:                  time.Now().UTC().Format(time.RFC3339Nano),
		ServerCertificateSHA256:      hex.EncodeToString(peerSum[:]),
		ServerCertificateNotAfterUTC: peer.NotAfter.UTC().Format(time.RFC3339Nano),
		ClientCertificateSHA256:      clientCertificateSHA256,
		ServerCertificateVerified:    true,
		ClientCertificateMatched:     true,
	}, nil
}
