package remoteagent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"reverseresearch/internal/recordio"
)

var safeAgentID = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

type Registration struct {
	Manifest       Manifest `json:"manifest"`
	ManifestSHA256 string   `json:"manifest_sha256"`
	RegisteredUTC  string   `json:"registered_utc"`
	Revision       string   `json:"revision"`
}
type Store struct{ root string }

func NewStore(root string) (*Store, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("remote agent store root is required")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, err
	}
	return &Store{root: abs}, nil
}
func (s *Store) Register(m Manifest, expectedRevision string) (result Registration, err error) {
	if err := VerifyManifest(m); err != nil {
		return Registration{}, err
	}
	if !safeAgentID.MatchString(m.AgentID) {
		return Registration{}, errors.New("agent_id contains unsafe characters")
	}
	release, err := recordio.Acquire(s.lockPath(m.AgentID), 2*time.Second)
	if err != nil {
		return Registration{}, err
	}
	defer func() { err = errors.Join(err, release()) }()
	var existing Registration
	body, readErr := recordio.ReadFileLimit(s.path(m.AgentID), MaxRegistrationRecordBytes)
	if readErr == nil {
		existing, err = decodeRegistration(body, m.AgentID)
		if err != nil {
			return Registration{}, err
		}
		if strings.TrimSpace(expectedRevision) == "" {
			return Registration{}, errors.New("expected_revision is required to replace an existing agent registration")
		}
		if existing.Revision != expectedRevision {
			return Registration{}, fmt.Errorf("agent registration revision changed: expected %s current %s", expectedRevision, existing.Revision)
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return Registration{}, readErr
	} else if expectedRevision != "" {
		return Registration{}, errors.New("expected_revision supplied for new agent")
	}
	result = Registration{Manifest: m, ManifestSHA256: ManifestIdentity(m), RegisteredUTC: time.Now().UTC().Format(time.RFC3339Nano)}
	result.Revision = registrationRevision(result)
	out, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return Registration{}, err
	}
	out = append(out, '\n')
	if len(out) > MaxRegistrationRecordBytes {
		return Registration{}, fmt.Errorf("agent registration exceeds durable size limit: %d > %d", len(out), MaxRegistrationRecordBytes)
	}
	if err := recordio.WriteFile(s.path(m.AgentID), out, 0o600); err != nil {
		return Registration{}, err
	}
	return result, nil
}
func (s *Store) Get(agentID string) (Registration, error) {
	agentID = strings.TrimSpace(agentID)
	if !safeAgentID.MatchString(agentID) {
		return Registration{}, errors.New("invalid agent_id")
	}
	body, err := recordio.ReadFileLimit(s.path(agentID), MaxRegistrationRecordBytes)
	if err != nil {
		return Registration{}, err
	}
	return decodeRegistration(body, agentID)
}
func (s *Store) List() ([]Registration, error) {
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return nil, err
	}
	out := []Registration{}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".json")
		r, err := s.Get(id)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Manifest.AgentID < out[j].Manifest.AgentID })
	return out, nil
}
func decodeRegistration(body []byte, agentID string) (Registration, error) {
	var r Registration
	if err := json.Unmarshal(body, &r); err != nil {
		return Registration{}, err
	}
	if r.Manifest.AgentID != agentID {
		return Registration{}, errors.New("agent registration identity mismatch")
	}
	if err := verifyStoredManifest(r.Manifest); err != nil {
		return Registration{}, err
	}
	if r.Revision != registrationRevision(r) {
		return Registration{}, errors.New("agent registration revision mismatch")
	}
	return r, nil
}
func registrationRevision(r Registration) string {
	copy := r
	copy.Revision = ""
	body, _ := json.Marshal(copy)
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
func (s *Store) path(id string) string     { return filepath.Join(s.root, id+".json") }
func (s *Store) lockPath(id string) string { return filepath.Join(s.root, id+".lock") }
