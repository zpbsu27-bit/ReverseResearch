package remoteagent

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"reverseresearch/internal/recordio"
)

const (
	MaxJobBodyBytes        int64 = 1 << 20
	MaxCapabilityBodyBytes       = 4 << 20
	MaxConcurrentAgentJobs       = 8
)

type CapabilityResult struct {
	State          string
	Body           []byte
	ArtifactSHA256 []string
}
type CapabilityHandler func(context.Context, JobRequest) (CapabilityResult, error)
type JobResponse struct {
	Envelope     ResultEnvelope `json:"envelope"`
	ResultBase64 string         `json:"result_base64,omitempty"`
}
type AgentRuntime struct {
	manifest                  Manifest
	privateKey                ed25519.PrivateKey
	ledger                    *OperationLedger
	mu                        sync.RWMutex
	handlers                  map[string]CapabilityHandler
	serverCertificateNotAfter string
	jobSlots                  chan struct{}
}

func NewAgentRuntime(manifest Manifest, privateKey ed25519.PrivateKey, ledger *OperationLedger) (*AgentRuntime, error) {
	if ledger == nil {
		return nil, errors.New("operation ledger is required")
	}
	if err := VerifyManifest(manifest); err != nil {
		return nil, err
	}
	public, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("private key is not Ed25519")
	}
	declared, err := base64.StdEncoding.DecodeString(manifest.PublicKey)
	if err != nil {
		return nil, err
	}
	if !public.Equal(ed25519.PublicKey(declared)) {
		return nil, errors.New("agent private key does not match manifest public key")
	}
	return &AgentRuntime{
		manifest: manifest, privateKey: privateKey, ledger: ledger,
		handlers: map[string]CapabilityHandler{},
		jobSlots: make(chan struct{}, MaxConcurrentAgentJobs),
	}, nil
}
func (a *AgentRuntime) RegisterCapability(name string, handler CapabilityHandler) error {
	name = strings.TrimSpace(name)
	if handler == nil {
		return errors.New("capability handler is required")
	}
	if forbiddenCapability(name) {
		return errors.New("arbitrary shell/exec capability is prohibited")
	}
	if !contains(clean(a.manifest.Capabilities), name) {
		return fmt.Errorf("capability %q not declared by signed manifest", name)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, exists := a.handlers[name]; exists {
		return fmt.Errorf("capability %q already registered", name)
	}
	a.handlers[name] = handler
	return nil
}
func (a *AgentRuntime) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/jobs", a.handleJob)
	mux.HandleFunc("/v1/status", a.handleStatus)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if !verifiedClient(r) {
			http.Error(w, "mTLS client certificate required", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		writeHTTPString(w, `{"status":"ok"}`)
	})
	return mux
}
func (a *AgentRuntime) handleJob(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !verifiedClient(r) {
		http.Error(w, "mTLS client certificate required", http.StatusUnauthorized)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxJobBodyBytes)
	defer r.Body.Close()
	var job JobRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&job); err != nil {
		http.Error(w, "invalid job", http.StatusBadRequest)
		return
	}
	if err := remoteEOF(dec); err != nil {
		http.Error(w, "multiple JSON values are not allowed", http.StatusBadRequest)
		return
	}
	if err := ValidateJob(a.manifest, job); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	jobCtx := r.Context()
	var cancel context.CancelFunc
	// Every job gets a real execution bound: the caller's deadline when it is
	// sooner, otherwise the agent's own ceiling. A missing deadline must never
	// mean "run forever" under unattended operation.
	executionDeadline := time.Now().Add(DefaultJobExecutionWindow)
	if job.DeadlineUTC != "" {
		if requested, parseErr := time.Parse(time.RFC3339, job.DeadlineUTC); parseErr == nil && requested.Before(executionDeadline) {
			executionDeadline = requested
		}
	}
	jobCtx, cancel = context.WithDeadline(jobCtx, executionDeadline)
	defer cancel()
	select {
	case a.jobSlots <- struct{}{}:
		defer func() { <-a.jobSlots }()
	default:
		http.Error(w, "agent is at concurrent job capacity", http.StatusTooManyRequests)
		return
	}
	if receipt, err := a.ledger.BeginContext(jobCtx, job); err != nil {
		if errors.Is(err, ErrOperationExists) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			writeHTTPJSON(w, receipt)
			return
		}
		http.Error(w, "operation ledger failure", http.StatusInternalServerError)
		return
	}
	a.mu.RLock()
	handler := a.handlers[job.Capability]
	a.mu.RUnlock()
	if handler == nil {
		if _, completeErr := a.ledger.CompleteWithRecovery(jobCtx, job.OperationID, "failed"); completeErr != nil {
			http.Error(w, "capability handler is not registered and operation receipt completion failed", http.StatusInternalServerError)
			return
		}
		http.Error(w, "capability handler is not registered", http.StatusNotImplemented)
		return
	}
	started := time.Now().UTC()
	result, runErr := handler(jobCtx, job)
	completed := time.Now().UTC()
	state := strings.ToLower(strings.TrimSpace(result.State))
	if state == "" {
		state = "applied"
	}
	if runErr != nil {
		state = "failed"
		if errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded) ||
			errors.Is(jobCtx.Err(), context.Canceled) || errors.Is(jobCtx.Err(), context.DeadlineExceeded) {
			state = "cancelled"
		}
		result.Body = []byte(runErr.Error())
	}
	if len(result.Body) > MaxCapabilityBodyBytes {
		state = "failed"
		result.Body = []byte(fmt.Sprintf("capability result exceeds %d bytes", MaxCapabilityBodyBytes))
		result.ArtifactSHA256 = nil
	}
	switch state {
	case "applied", "failed", "uncertain", "rolled_back", "cancelled":
	default:
		state = "failed"
		result.Body = []byte("capability returned invalid state")
	}
	envelope, err := SignResult(ResultEnvelope{AgentID: a.manifest.AgentID, JobID: job.JobID, OperationID: job.OperationID, State: state, ResultSHA256: ResultIdentity(result.Body), ArtifactSHA256: result.ArtifactSHA256, StartedUTC: started.Format(time.RFC3339Nano), CompletedUTC: completed.Format(time.RFC3339Nano)}, a.privateKey)
	if err != nil {
		if _, completeErr := a.ledger.CompleteWithRecovery(jobCtx, job.OperationID, "uncertain"); completeErr != nil {
			http.Error(w, "result signing failed and operation receipt completion failed", http.StatusInternalServerError)
			return
		}
		http.Error(w, "result signing failed", http.StatusInternalServerError)
		return
	}
	if _, err := a.ledger.CompleteWithRecovery(jobCtx, job.OperationID, state); err != nil {
		http.Error(w, "operation receipt completion failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	writeHTTPJSON(w, JobResponse{Envelope: envelope, ResultBase64: base64.StdEncoding.EncodeToString(result.Body)})
}
func verifiedClient(r *http.Request) bool {
	return r.TLS != nil && len(r.TLS.VerifiedChains) > 0 && len(r.TLS.VerifiedChains[0]) > 0
}
func remoteEOF(dec *json.Decoder) error {
	var extra any
	err := dec.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("extra JSON value")
	}
	return err
}
func LoadServerTLSConfig(certFile, keyFile, clientCAFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	caBody, err := recordio.ReadFileLimit(clientCAFile, MaxTLSPEMBytes)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBody) {
		return nil, errors.New("no client CA certificate loaded")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}, nil
}
func ServeMTLS(ctx context.Context, addr string, handler http.Handler, tlsConfig *tls.Config) error {
	if handler == nil || tlsConfig == nil {
		return errors.New("handler and TLS config are required")
	}
	server := &http.Server{
		Addr: addr, Handler: handler, TLSConfig: tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- server.ListenAndServeTLS("", "") }()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
