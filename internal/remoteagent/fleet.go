package remoteagent

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"reverseresearch/internal/recordio"
)

type StatusRecord struct {
	Status      StatusEnvelope       `json:"status"`
	Transport   TransportObservation `json:"transport"`
	RecordedUTC string               `json:"recorded_utc"`
	Revision    string               `json:"revision"`
}

type FleetEntry struct {
	Registration     Registration  `json:"registration"`
	Status           *StatusRecord `json:"status,omitempty"`
	State            string        `json:"state"`
	LastSeenUTC      string        `json:"last_seen_utc,omitempty"`
	CertificateState string        `json:"certificate_state"`
	ManifestState    string        `json:"manifest_state"`
}

func (s *Store) RecordStatus(status StatusEnvelope, observation TransportObservation, expectedRevision string) (record StatusRecord, err error) {
	registration, err := s.Get(strings.TrimSpace(status.AgentID))
	if err != nil {
		return StatusRecord{}, err
	}
	if err := VerifyManifest(registration.Manifest); err != nil {
		return StatusRecord{}, err
	}
	keyBytes, err := base64.StdEncoding.DecodeString(registration.Manifest.PublicKey)
	if err != nil {
		return StatusRecord{}, err
	}
	if err := VerifyStatus(status, ed25519.PublicKey(keyBytes)); err != nil {
		return StatusRecord{}, err
	}
	if status.ManifestSHA256 != registration.ManifestSHA256 {
		return StatusRecord{}, errors.New("status manifest identity does not match registered manifest")
	}
	if status.Platform != registration.Manifest.Platform || status.Architecture != registration.Manifest.Architecture {
		return StatusRecord{}, errors.New("status platform identity does not match registered manifest")
	}
	if !sameStrings(status.DeclaredCapabilities, registration.Manifest.Capabilities) {
		return StatusRecord{}, errors.New("status declared capabilities do not match registered manifest")
	}
	declared := map[string]bool{}
	for _, capability := range clean(status.DeclaredCapabilities) {
		declared[capability] = true
	}
	for _, capability := range clean(status.RegisteredCapabilities) {
		if !declared[capability] {
			return StatusRecord{}, fmt.Errorf("status registered undeclared capability %q", capability)
		}
	}
	if !observation.ServerCertificateVerified || !observation.ClientCertificateMatched {
		return StatusRecord{}, errors.New("status transport observation is not authenticated")
	}
	if !validSHA(strings.ToLower(strings.TrimSpace(observation.ServerCertificateSHA256))) {
		return StatusRecord{}, errors.New("server certificate SHA-256 is required")
	}
	if !validSHA(strings.ToLower(strings.TrimSpace(observation.ClientCertificateSHA256))) {
		return StatusRecord{}, errors.New("client certificate SHA-256 is required")
	}
	if !strings.EqualFold(status.ClientCertificateSHA256, observation.ClientCertificateSHA256) {
		return StatusRecord{}, errors.New("signed status client certificate identity mismatch")
	}
	if status.CertificateNotAfterUTC == "" || observation.ServerCertificateNotAfterUTC == "" {
		return StatusRecord{}, errors.New("server certificate expiry is required")
	}
	statusExpiry, err := parseStatusTime(status.CertificateNotAfterUTC)
	if err != nil {
		return StatusRecord{}, errors.New("invalid signed server certificate expiry")
	}
	observedExpiry, err := parseStatusTime(observation.ServerCertificateNotAfterUTC)
	if err != nil {
		return StatusRecord{}, errors.New("invalid observed server certificate expiry")
	}
	if !statusExpiry.Equal(observedExpiry) {
		return StatusRecord{}, errors.New("signed server certificate expiry does not match observed TLS certificate")
	}
	generated, err := parseStatusTime(status.GeneratedUTC)
	if err != nil {
		return StatusRecord{}, err
	}
	observed, err := parseStatusTime(observation.ObservedUTC)
	if err != nil {
		return StatusRecord{}, errors.New("invalid observed_utc")
	}
	now := time.Now().UTC()
	if observed.After(now.Add(5 * time.Minute)) {
		return StatusRecord{}, errors.New("transport observation is unreasonably in the future")
	}
	if generated.After(observed.Add(5 * time.Minute)) {
		return StatusRecord{}, errors.New("signed status timestamp is newer than authenticated observation")
	}
	if generated.Before(observed.Add(-5 * time.Minute)) {
		return StatusRecord{}, errors.New("signed status timestamp is stale relative to authenticated observation")
	}

	if err := os.MkdirAll(s.statusRoot(), 0o700); err != nil {
		return StatusRecord{}, err
	}
	release, err := recordio.Acquire(s.statusLockPath(status.AgentID), 2*time.Second)
	if err != nil {
		return StatusRecord{}, err
	}
	defer func() { err = errors.Join(err, release()) }()

	existing, readErr := s.readStatus(status.AgentID)
	if readErr == nil {
		if strings.TrimSpace(expectedRevision) == "" {
			return StatusRecord{}, errors.New("expected_revision is required to replace existing agent status")
		}
		if existing.Revision != strings.TrimSpace(expectedRevision) {
			return StatusRecord{}, fmt.Errorf("agent status revision changed: expected %s current %s", expectedRevision, existing.Revision)
		}
		previousGenerated, err := parseStatusTime(existing.Status.GeneratedUTC)
		if err != nil {
			return StatusRecord{}, err
		}
		if !generated.After(previousGenerated) {
			return StatusRecord{}, errors.New("agent status replay or non-monotonic generated_utc rejected")
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return StatusRecord{}, readErr
	} else if strings.TrimSpace(expectedRevision) != "" {
		return StatusRecord{}, errors.New("expected_revision supplied for new agent status")
	}

	record = StatusRecord{
		Status: status, Transport: observation,
		RecordedUTC: now.Format(time.RFC3339Nano),
	}
	record.Revision = statusRecordRevision(record)
	body, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return StatusRecord{}, err
	}
	body = append(body, '\n')
	if len(body) > MaxStatusRecordBytes {
		return StatusRecord{}, fmt.Errorf("agent status exceeds durable size limit: %d > %d", len(body), MaxStatusRecordBytes)
	}
	if err := recordio.WriteFile(s.statusPath(status.AgentID), body, 0o600); err != nil {
		return StatusRecord{}, err
	}
	return record, nil
}

func (s *Store) GetStatus(agentID string) (StatusRecord, error) {
	agentID = strings.TrimSpace(agentID)
	if !safeAgentID.MatchString(agentID) {
		return StatusRecord{}, errors.New("invalid agent_id")
	}
	registration, err := s.Get(agentID)
	if err != nil {
		return StatusRecord{}, err
	}
	record, err := s.readStatus(agentID)
	if err != nil {
		return StatusRecord{}, err
	}
	if err := validateStoredStatus(registration, record); err != nil {
		return StatusRecord{}, err
	}
	return record, nil
}

func (s *Store) ListFleet(now time.Time, staleAfter, offlineAfter time.Duration) ([]FleetEntry, error) {
	if staleAfter <= 0 || offlineAfter <= staleAfter {
		return nil, errors.New("fleet thresholds require 0 < stale_after < offline_after")
	}
	now = now.UTC()
	registrations, err := s.List()
	if err != nil {
		return nil, err
	}
	out := make([]FleetEntry, 0, len(registrations))
	for _, registration := range registrations {
		entry := FleetEntry{
			Registration: registration,
			State:        "unseen", CertificateState: "unknown", ManifestState: "valid",
		}
		if registration.Manifest.ExpiresUTC != "" {
			expiry, parseErr := time.Parse(time.RFC3339, registration.Manifest.ExpiresUTC)
			if parseErr != nil {
				return nil, parseErr
			}
			if !expiry.After(now) {
				entry.ManifestState = "expired"
			} else if !expiry.After(now.Add(7 * 24 * time.Hour)) {
				entry.ManifestState = "expiring"
			}
		}
		status, err := s.readStatus(registration.Manifest.AgentID)
		if err == nil {
			if err := validateStoredStatus(registration, status); err != nil {
				return nil, err
			}
			observed, parseErr := parseStatusTime(status.Transport.ObservedUTC)
			if parseErr != nil {
				return nil, parseErr
			}
			age := now.Sub(observed)
			switch {
			case age <= staleAfter:
				entry.State = "recent"
			case age <= offlineAfter:
				entry.State = "stale"
			default:
				entry.State = "offline"
			}
			expiry, parseErr := parseStatusTime(status.Transport.ServerCertificateNotAfterUTC)
			if parseErr != nil {
				return nil, parseErr
			}
			switch {
			case !expiry.After(now):
				entry.CertificateState = "expired"
			case !expiry.After(now.Add(7 * 24 * time.Hour)):
				entry.CertificateState = "expiring"
			default:
				entry.CertificateState = "valid"
			}
			entry.Status = &status
			entry.LastSeenUTC = status.Transport.ObservedUTC
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Registration.Manifest.AgentID < out[j].Registration.Manifest.AgentID
	})
	return out, nil
}

func (s *Store) readStatus(agentID string) (StatusRecord, error) {
	body, err := recordio.ReadFileLimit(s.statusPath(agentID), MaxStatusRecordBytes)
	if err != nil {
		return StatusRecord{}, err
	}
	var record StatusRecord
	if err := json.Unmarshal(body, &record); err != nil {
		return StatusRecord{}, err
	}
	if record.Status.AgentID != agentID {
		return StatusRecord{}, errors.New("agent status identity mismatch")
	}
	if record.Revision != statusRecordRevision(record) {
		return StatusRecord{}, errors.New("agent status revision mismatch")
	}
	return record, nil
}

func validateStoredStatus(registration Registration, record StatusRecord) error {
	keyBytes, err := base64.StdEncoding.DecodeString(registration.Manifest.PublicKey)
	if err != nil {
		return err
	}
	if err := VerifyStatus(record.Status, ed25519.PublicKey(keyBytes)); err != nil {
		return err
	}
	if record.Status.AgentID != registration.Manifest.AgentID || record.Status.ManifestSHA256 != registration.ManifestSHA256 {
		return errors.New("stored agent status does not match registration identity")
	}
	if !strings.EqualFold(record.Status.ClientCertificateSHA256, record.Transport.ClientCertificateSHA256) {
		return errors.New("stored status client certificate binding mismatch")
	}
	return nil
}
func statusRecordRevision(record StatusRecord) string {
	copyRecord := record
	copyRecord.Revision = ""
	body, _ := json.Marshal(copyRecord)
	return ResultIdentity(body)
}

func (s *Store) statusRoot() string {
	return filepath.Join(s.root, "status")
}

func (s *Store) statusPath(agentID string) string {
	return filepath.Join(s.statusRoot(), agentID+".json")
}

func (s *Store) statusLockPath(agentID string) string {
	return filepath.Join(s.statusRoot(), agentID+".lock")
}

func parseStatusTime(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return parsed.UTC(), nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, err
	}
	return parsed.UTC(), nil
}

func sameStrings(left, right []string) bool {
	a := clean(left)
	b := clean(right)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
