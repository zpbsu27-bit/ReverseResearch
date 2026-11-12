package remoteagent

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const ContractVersion = 1

type Manifest struct {
	Version           int      `json:"version"`
	AgentID           string   `json:"agent_id"`
	Platform          string   `json:"platform"`
	Architecture      string   `json:"architecture"`
	Capabilities      []string `json:"capabilities"`
	TargetAllowlist   []string `json:"target_allowlist,omitempty"`
	MutualTLSRequired bool     `json:"mutual_tls_required"`
	NoRemoteShell     bool     `json:"no_remote_shell"`
	PublicKey         string   `json:"public_key"`
	ExpiresUTC        string   `json:"expires_utc,omitempty"`
	Signature         string   `json:"signature,omitempty"`
}
type JobRequest struct {
	Version       int               `json:"version"`
	JobID         string            `json:"job_id"`
	OperationID   string            `json:"operation_id"`
	Capability    string            `json:"capability"`
	Target        string            `json:"target"`
	Parameters    map[string]string `json:"parameters,omitempty"`
	ExpectedState string            `json:"expected_state,omitempty"`
	DeadlineUTC   string            `json:"deadline_utc,omitempty"`
}
type ResultEnvelope struct {
	Version        int      `json:"version"`
	AgentID        string   `json:"agent_id"`
	JobID          string   `json:"job_id"`
	OperationID    string   `json:"operation_id"`
	State          string   `json:"state"`
	ResultSHA256   string   `json:"result_sha256"`
	ArtifactSHA256 []string `json:"artifact_sha256,omitempty"`
	StartedUTC     string   `json:"started_utc,omitempty"`
	CompletedUTC   string   `json:"completed_utc"`
	Signature      string   `json:"signature,omitempty"`
}

func ValidateManifest(m Manifest) error {
	return validateManifest(m, true)
}
func validateManifest(m Manifest, enforceExpiry bool) error {
	if m.Version != ContractVersion {
		return fmt.Errorf("unsupported agent contract version %d", m.Version)
	}
	if strings.TrimSpace(m.AgentID) == "" || strings.TrimSpace(m.Platform) == "" || strings.TrimSpace(m.Architecture) == "" {
		return errors.New("agent_id, platform, and architecture are required")
	}
	if !m.MutualTLSRequired {
		return errors.New("remote agent contract requires mutual TLS")
	}
	if !m.NoRemoteShell {
		return errors.New("remote agent contract must prohibit arbitrary remote shell")
	}
	capabilities := clean(m.Capabilities)
	if len(capabilities) == 0 {
		return errors.New("at least one capability is required")
	}
	for _, capability := range capabilities {
		if forbiddenCapability(capability) {
			return fmt.Errorf("capability %q is prohibited by remote agent contract", capability)
		}
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(m.PublicKey))
	if err != nil || len(key) != ed25519.PublicKeySize {
		return errors.New("public_key must be base64 Ed25519 public key")
	}
	if m.ExpiresUTC != "" {
		expiry, err := time.Parse(time.RFC3339, m.ExpiresUTC)
		if err != nil {
			return errors.New("invalid expires_utc")
		}
		if enforceExpiry && time.Now().UTC().After(expiry) {
			return errors.New("agent manifest expired")
		}
	}
	return nil
}
func ValidateJob(m Manifest, j JobRequest) error {
	if err := ValidateManifest(m); err != nil {
		return err
	}
	if j.Version != ContractVersion {
		return errors.New("job contract version mismatch")
	}
	j.JobID = strings.TrimSpace(j.JobID)
	j.OperationID = strings.TrimSpace(j.OperationID)
	j.Capability = strings.TrimSpace(j.Capability)
	j.Target = strings.TrimSpace(j.Target)
	if j.JobID == "" || j.OperationID == "" || j.Capability == "" || j.Target == "" {
		return errors.New("job_id, operation_id, capability, and target are required")
	}
	if forbiddenCapability(j.Capability) {
		return errors.New("arbitrary shell/exec capability is prohibited")
	}
	if !contains(clean(m.Capabilities), j.Capability) {
		return fmt.Errorf("capability %q not allowed by agent", j.Capability)
	}
	if len(m.TargetAllowlist) > 0 && !contains(clean(m.TargetAllowlist), j.Target) {
		return fmt.Errorf("target %q not in agent allowlist", j.Target)
	}
	for k := range j.Parameters {
		lower := strings.ToLower(strings.TrimSpace(k))
		if lower == "command" || lower == "cmd" || lower == "shell" || lower == "script" || lower == "powershell" {
			return fmt.Errorf("parameter %q is prohibited", k)
		}
	}
	if j.DeadlineUTC != "" {
		deadline, err := time.Parse(time.RFC3339, j.DeadlineUTC)
		if err != nil {
			return errors.New("invalid deadline_utc")
		}
		if time.Now().UTC().After(deadline) {
			return errors.New("job deadline expired")
		}
	}
	return nil
}
func SignManifest(m Manifest, private ed25519.PrivateKey) (Manifest, error) {
	m.Version = ContractVersion
	m.Capabilities = clean(m.Capabilities)
	m.TargetAllowlist = clean(m.TargetAllowlist)
	m.Signature = ""
	if err := ValidateManifest(m); err != nil {
		return Manifest{}, err
	}
	body, _ := json.Marshal(m)
	m.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, body))
	return m, nil
}
func VerifyManifest(m Manifest) error {
	return verifyManifest(m, true)
}
func verifyStoredManifest(m Manifest) error {
	return verifyManifest(m, false)
}
func verifyManifest(m Manifest, enforceExpiry bool) error {
	if err := validateManifest(m, enforceExpiry); err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil {
		return errors.New("invalid manifest signature encoding")
	}
	key, _ := base64.StdEncoding.DecodeString(m.PublicKey)
	copy := m
	copy.Signature = ""
	copy.Capabilities = clean(copy.Capabilities)
	copy.TargetAllowlist = clean(copy.TargetAllowlist)
	body, _ := json.Marshal(copy)
	if !ed25519.Verify(ed25519.PublicKey(key), body, sig) {
		return errors.New("agent manifest signature verification failed")
	}
	return nil
}
func SignResult(r ResultEnvelope, private ed25519.PrivateKey) (ResultEnvelope, error) {
	r.Version = ContractVersion
	r.AgentID = strings.TrimSpace(r.AgentID)
	r.JobID = strings.TrimSpace(r.JobID)
	r.OperationID = strings.TrimSpace(r.OperationID)
	r.State = strings.TrimSpace(r.State)
	r.ResultSHA256 = strings.ToLower(strings.TrimSpace(r.ResultSHA256))
	r.ArtifactSHA256 = clean(r.ArtifactSHA256)
	r.Signature = ""
	if r.AgentID == "" || r.JobID == "" || r.OperationID == "" || r.CompletedUTC == "" {
		return ResultEnvelope{}, errors.New("agent_id, job_id, operation_id, and completed_utc are required")
	}
	if !validSHA(r.ResultSHA256) {
		return ResultEnvelope{}, errors.New("result_sha256 must be SHA-256")
	}
	for _, h := range r.ArtifactSHA256 {
		if !validSHA(strings.ToLower(h)) {
			return ResultEnvelope{}, errors.New("artifact_sha256 must contain SHA-256 values")
		}
	}
	switch r.State {
	case "applied", "failed", "uncertain", "rolled_back", "cancelled":
	default:
		return ResultEnvelope{}, fmt.Errorf("invalid result state %q", r.State)
	}
	body, _ := json.Marshal(r)
	r.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, body))
	return r, nil
}
func VerifyResult(r ResultEnvelope, public ed25519.PublicKey) error {
	sig, err := base64.StdEncoding.DecodeString(r.Signature)
	if err != nil {
		return errors.New("invalid result signature encoding")
	}
	copy := r
	copy.Signature = ""
	copy.ArtifactSHA256 = clean(copy.ArtifactSHA256)
	body, _ := json.Marshal(copy)
	if !ed25519.Verify(public, body, sig) {
		return errors.New("result signature verification failed")
	}
	return nil
}
func ResultIdentity(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
func forbiddenCapability(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	switch v {
	case "shell", "exec", "command", "cmd", "cmd.exe", "powershell", "powershell.exe", "generic.exec":
		return true
	}
	return strings.Contains(v, "remote-shell") || strings.Contains(v, "arbitrary-shell") || strings.Contains(v, "powershell")
}
func clean(v []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, x := range v {
		x = strings.TrimSpace(x)
		if x != "" && !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}
func contains(v []string, x string) bool {
	for _, y := range v {
		if y == x {
			return true
		}
	}
	return false
}
func validSHA(v string) bool { b, err := hex.DecodeString(v); return err == nil && len(b) == 32 }
