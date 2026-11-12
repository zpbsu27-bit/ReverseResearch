package packregistry

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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

const RegistryVersion = 1

type TrustedKey struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
	Publisher string `json:"publisher"`
	AddedUTC  string `json:"added_utc"`
}
type Receipt struct {
	ID               string `json:"id"`
	PackID           string `json:"pack_id"`
	PackVersion      string `json:"pack_version"`
	Kind             string `json:"kind"`
	Publisher        string `json:"publisher"`
	ManifestSHA256   string `json:"manifest_sha256"`
	RegistryRevision string `json:"registry_revision"`
	Files            int    `json:"files"`
	VerifiedUTC      string `json:"verified_utc"`
}
type PackRecord struct {
	ReceiptID        string     `json:"receipt_id"`
	Root             string     `json:"root"`
	Manifest         Manifest   `json:"manifest"`
	Policy           LoadPolicy `json:"policy"`
	Status           string     `json:"status"`
	VerifiedUTC      string     `json:"verified_utc"`
	QuarantineReason string     `json:"quarantine_reason,omitempty"`
}
type AuditEvent struct {
	ID         string `json:"id"`
	Action     string `json:"action"`
	PackID     string `json:"pack_id"`
	ReceiptID  string `json:"receipt_id,omitempty"`
	Detail     string `json:"detail,omitempty"`
	CreatedUTC string `json:"created_utc"`
}
type RegistryState struct {
	Version     int                   `json:"version"`
	TrustedKeys map[string]TrustedKey `json:"trusted_keys,omitempty"`
	Receipts    []Receipt             `json:"receipts,omitempty"`
	Packs       map[string]PackRecord `json:"packs,omitempty"`
	Active      map[string]string     `json:"active,omitempty"`
	Audit       []AuditEvent          `json:"audit,omitempty"`
	UpdatedUTC  string                `json:"updated_utc"`
	Revision    string                `json:"revision"`
}
type Registry struct{ root string }

func NewRegistry(root string) (*Registry, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("registry root is required")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, err
	}
	return &Registry{root: abs}, nil
}
func (r *Registry) Get() (RegistryState, error) {
	state, err := r.GetHot()
	if err != nil {
		return RegistryState{}, err
	}
	return r.hydrateArchivedState(state)
}
func (r *Registry) TrustKey(expectedRevision, keyID, publicKey, publisher string) (RegistryState, error) {
	keyID = strings.TrimSpace(keyID)
	publicKey = strings.TrimSpace(publicKey)
	publisher = strings.TrimSpace(publisher)
	if keyID == "" || publisher == "" {
		return RegistryState{}, errors.New("key_id and publisher are required")
	}
	keyBytes, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil || len(keyBytes) != 32 {
		return RegistryState{}, errors.New("public_key must be base64 Ed25519 public key")
	}
	return r.mutate(expectedRevision, func(s *RegistryState) error {
		if existing, ok := s.TrustedKeys[keyID]; ok && existing.PublicKey != publicKey {
			return fmt.Errorf("trusted key %q already exists with different public key", keyID)
		}
		s.TrustedKeys[keyID] = TrustedKey{KeyID: keyID, PublicKey: publicKey, Publisher: publisher, AddedUTC: time.Now().UTC().Format(time.RFC3339Nano)}
		return nil
	})
}
func (r *Registry) RemoveKey(expectedRevision, keyID string) (RegistryState, error) {
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		return RegistryState{}, errors.New("key_id is required")
	}
	return r.mutate(expectedRevision, func(s *RegistryState) error {
		if _, ok := s.TrustedKeys[keyID]; !ok {
			return fmt.Errorf("unknown trusted key %q", keyID)
		}
		delete(s.TrustedKeys, keyID)
		return nil
	})
}
func (r *Registry) VerifyAndRecord(packRoot string, m Manifest, manifestSHA, expectedRevision string) (RegistryState, Receipt, error) {
	manifestSHA = strings.ToLower(strings.TrimSpace(manifestSHA))
	if len(manifestSHA) != 64 {
		return RegistryState{}, Receipt{}, errors.New("manifest_sha256 is required")
	}
	root, err := filepath.Abs(packRoot)
	if err != nil {
		return RegistryState{}, Receipt{}, err
	}
	policy, err := EvaluateLoadPolicy(m)
	if err != nil {
		return RegistryState{}, Receipt{}, err
	}
	var created Receipt
	state, err := r.mutate(expectedRevision, func(s *RegistryState) error {
		keys := trustKeys(*s)
		verification, err := Verify(root, m, TrustStore{Keys: keys})
		if err != nil {
			return err
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		sum := sha256.Sum256([]byte(m.ID + "\x00" + m.PackVersion + "\x00" + manifestSHA))
		id := "packreceipt_" + hex.EncodeToString(sum[:8])
		if receipt, ok, err := r.lookupReceipt(*s, id); err != nil {
			return err
		} else if ok {
			created = receipt
			return nil
		}
		created = Receipt{ID: id, PackID: verification.ID, PackVersion: verification.PackVersion, Kind: verification.Kind, Publisher: verification.Publisher, ManifestSHA256: manifestSHA, Files: verification.Files, VerifiedUTC: now}
		s.Receipts = append(s.Receipts, created)
		sort.Slice(s.Receipts, func(i, j int) bool { return s.Receipts[i].ID < s.Receipts[j].ID })
		return nil
	})
	if err != nil {
		return RegistryState{}, Receipt{}, err
	}
	_, havePack, lookupErr := r.lookupPackRecord(state, created.ID)
	if lookupErr != nil {
		return RegistryState{}, Receipt{}, lookupErr
	}
	if created.RegistryRevision == "" || !havePack {
		sourceRevision := state.Revision
		updated, err := r.mutate(sourceRevision, func(s *RegistryState) error {
			receipt, ok, err := r.lookupReceipt(*s, created.ID)
			if err != nil {
				return err
			}
			if !ok {
				return errors.New("verification receipt disappeared")
			}
			if receipt.RegistryRevision == "" {
				receipt.RegistryRevision = sourceRevision
				updatedHot := false
				for i := range s.Receipts {
					if s.Receipts[i].ID == receipt.ID {
						s.Receipts[i] = receipt
						updatedHot = true
						break
					}
				}
				if !updatedHot {
					if err := r.writeReceiptArchive(receipt); err != nil {
						return err
					}
				}
			}
			created = receipt
			if s.Packs == nil {
				s.Packs = map[string]PackRecord{}
			}
			if _, exists, err := r.lookupPackRecord(*s, created.ID); err != nil {
				return err
			} else if !exists {
				s.Packs[created.ID] = PackRecord{
					ReceiptID: created.ID, Root: root, Manifest: m, Policy: policy,
					Status: "verified", VerifiedUTC: created.VerifiedUTC,
				}
				appendAudit(s, "verify", created.PackID, created.ID, created.PackVersion)
			}
			return nil
		})
		if err != nil {
			return RegistryState{}, Receipt{}, err
		}
		state = updated
	}
	return state, created, nil
}
func (r *Registry) mutate(expectedRevision string, fn func(*RegistryState) error) (result RegistryState, err error) {
	release, err := recordio.Acquire(r.lockPath(), 2*time.Second)
	if err != nil {
		return RegistryState{}, err
	}
	defer func() { err = errors.Join(err, release()) }()
	state, err := r.readUnlocked()
	if err != nil {
		return RegistryState{}, err
	}
	if expectedRevision != "" && state.Revision != expectedRevision {
		return RegistryState{}, fmt.Errorf("registry revision changed: expected %s current %s", expectedRevision, state.Revision)
	}
	if expectedRevision == "" && state.Revision != "" && state.UpdatedUTC != "" {
		return RegistryState{}, errors.New("expected_revision is required for existing registry mutation")
	}
	if err := fn(&state); err != nil {
		return RegistryState{}, err
	}
	if err := r.compactState(&state); err != nil {
		return RegistryState{}, err
	}
	state.Version = RegistryVersion
	state.UpdatedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	state.Revision = registryRevision(state)
	body, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return RegistryState{}, err
	}
	body = append(body, '\n')
	if len(body) > MaxRegistryHotBytes {
		return RegistryState{}, fmt.Errorf("hot pack registry exceeds durable size limit: %d > %d", len(body), MaxRegistryHotBytes)
	}
	if err := recordio.WriteFile(r.path(), body, 0o600); err != nil {
		return RegistryState{}, err
	}
	return state, nil
}
func (r *Registry) readUnlocked() (RegistryState, error) {
	body, err := recordio.ReadFileLimit(r.path(), MaxRegistryHotBytes)
	if errors.Is(err, os.ErrNotExist) {
		return freshRegistry(), nil
	}
	if err != nil {
		return RegistryState{}, err
	}
	return decodeRegistry(body)
}
func freshRegistry() RegistryState {
	return RegistryState{Version: RegistryVersion, TrustedKeys: map[string]TrustedKey{}, Receipts: []Receipt{}, Packs: map[string]PackRecord{}, Active: map[string]string{}, Audit: []AuditEvent{}}
}
func decodeRegistry(body []byte) (RegistryState, error) {
	var s RegistryState
	if err := json.Unmarshal(body, &s); err != nil {
		return RegistryState{}, err
	}
	if s.Version != RegistryVersion {
		return RegistryState{}, fmt.Errorf("unsupported registry version %d", s.Version)
	}
	if s.TrustedKeys == nil {
		s.TrustedKeys = map[string]TrustedKey{}
	}
	if s.Packs == nil {
		s.Packs = map[string]PackRecord{}
	}
	if s.Active == nil {
		s.Active = map[string]string{}
	}
	if s.Audit == nil {
		s.Audit = []AuditEvent{}
	}
	if s.Revision != registryRevision(s) {
		return RegistryState{}, errors.New("registry revision mismatch")
	}
	return s, nil
}
func registryRevision(s RegistryState) string {
	copy := s
	copy.Revision = ""
	body, _ := json.Marshal(copy)
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
func (r *Registry) path() string     { return filepath.Join(r.root, "registry.json") }
func (r *Registry) lockPath() string { return filepath.Join(r.root, "registry.lock") }
