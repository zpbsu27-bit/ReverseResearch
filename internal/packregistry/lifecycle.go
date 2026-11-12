package packregistry

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"reverseresearch/internal/recordio"
)

const MaxActiveEntrypointBytes = 4 << 20

type ActiveEntrypoint struct {
	PackID           string `json:"pack_id"`
	PackVersion      string `json:"pack_version"`
	ReceiptID        string `json:"receipt_id"`
	RegistryRevision string `json:"registry_revision"`
	Name             string `json:"name"`
	Kind             string `json:"kind"`
	Path             string `json:"path"`
	SHA256           string `json:"sha256"`
	Body             []byte `json:"body"`
}

func (r *Registry) Activate(expectedRevision, receiptID string) (RegistryState, PackRecord, error) {
	receiptID = strings.TrimSpace(receiptID)
	if receiptID == "" {
		return RegistryState{}, PackRecord{}, errors.New("receipt_id is required")
	}
	var activated PackRecord
	state, err := r.mutate(expectedRevision, func(s *RegistryState) error {
		record, ok, err := r.lookupPackRecord(*s, receiptID)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("unknown verified pack receipt %q", receiptID)
		}
		if record.Status == "quarantined" {
			return errors.New("quarantined pack cannot be activated")
		}
		if !record.Policy.Activatable || !record.Policy.DataOnly {
			return errors.New("pack load policy requires an external adapter")
		}
		if err := verifyRecordCurrent(*s, record); err != nil {
			return err
		}
		if err := dependenciesSatisfied(*s, record.Manifest); err != nil {
			return err
		}
		if currentID := s.Active[record.Manifest.ID]; currentID != "" && currentID != receiptID {
			current, ok, err := r.lookupPackRecord(*s, currentID)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("active pack receipt %q is missing", currentID)
			}
			if current.Status == "active" {
				current.Status = "verified"
				s.Packs[currentID] = current
			}
		}
		record.Status = "active"
		record.QuarantineReason = ""
		s.Packs[receiptID] = record
		s.Active[record.Manifest.ID] = receiptID
		appendAudit(s, "activate", record.Manifest.ID, receiptID, record.Manifest.PackVersion)
		activated = record
		return nil
	})
	return state, activated, err
}

func (r *Registry) Quarantine(expectedRevision, receiptID, reason string) (RegistryState, PackRecord, error) {
	receiptID = strings.TrimSpace(receiptID)
	reason = strings.TrimSpace(reason)
	if receiptID == "" || reason == "" {
		return RegistryState{}, PackRecord{}, errors.New("receipt_id and reason are required")
	}
	var quarantined PackRecord
	state, err := r.mutate(expectedRevision, func(s *RegistryState) error {
		record, ok, err := r.lookupPackRecord(*s, receiptID)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("unknown verified pack receipt %q", receiptID)
		}
		record.Status = "quarantined"
		record.QuarantineReason = reason
		s.Packs[receiptID] = record
		if s.Active[record.Manifest.ID] == receiptID {
			delete(s.Active, record.Manifest.ID)
		}
		appendAudit(s, "quarantine", record.Manifest.ID, receiptID, reason)
		quarantined = record
		return nil
	})
	return state, quarantined, err
}

func (r *Registry) Rollback(expectedRevision, packID, targetReceiptID string) (RegistryState, PackRecord, error) {
	packID = strings.TrimSpace(packID)
	targetReceiptID = strings.TrimSpace(targetReceiptID)
	if packID == "" || targetReceiptID == "" {
		return RegistryState{}, PackRecord{}, errors.New("pack_id and target_receipt_id are required")
	}
	var activated PackRecord
	state, err := r.mutate(expectedRevision, func(s *RegistryState) error {
		target, ok, err := r.lookupPackRecord(*s, targetReceiptID)
		if err != nil {
			return err
		}
		if !ok || target.Manifest.ID != packID {
			return fmt.Errorf("rollback target %q does not belong to pack %q", targetReceiptID, packID)
		}
		currentID := s.Active[packID]
		if currentID == "" {
			return fmt.Errorf("pack %q has no active version to roll back", packID)
		}
		if currentID == targetReceiptID {
			return errors.New("rollback target is already active")
		}
		if target.Status == "quarantined" {
			return errors.New("cannot roll back to quarantined pack")
		}
		if !target.Policy.Activatable || !target.Policy.DataOnly {
			return errors.New("rollback target requires an external adapter")
		}
		if err := verifyRecordCurrent(*s, target); err != nil {
			return err
		}
		if err := dependenciesSatisfied(*s, target.Manifest); err != nil {
			return err
		}
		current, ok, err := r.lookupPackRecord(*s, currentID)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("active pack receipt %q is missing", currentID)
		}
		if current.Status == "active" {
			current.Status = "verified"
			s.Packs[currentID] = current
		}
		target.Status = "active"
		s.Packs[targetReceiptID] = target
		s.Active[packID] = targetReceiptID
		appendAudit(s, "rollback", packID, targetReceiptID, "from "+currentID)
		activated = target
		return nil
	})
	return state, activated, err
}

func (r *Registry) ResolveActive(packID string) (RegistryState, PackRecord, error) {
	packID = strings.TrimSpace(packID)
	if packID == "" {
		return RegistryState{}, PackRecord{}, errors.New("pack_id is required")
	}
	state, err := r.GetHot()
	if err != nil {
		return RegistryState{}, PackRecord{}, err
	}
	receiptID := state.Active[packID]
	if receiptID == "" {
		return RegistryState{}, PackRecord{}, fmt.Errorf("pack %q has no active version", packID)
	}
	record, ok, err := r.lookupPackRecord(state, receiptID)
	if err != nil {
		return RegistryState{}, PackRecord{}, err
	}
	if !ok || record.Status != "active" {
		return RegistryState{}, PackRecord{}, errors.New("active pack registry state is inconsistent")
	}
	if !record.Policy.Activatable || !record.Policy.DataOnly {
		return RegistryState{}, PackRecord{}, errors.New("active pack is not allowed by the data-only load policy")
	}
	if err := verifyRecordCurrent(state, record); err != nil {
		return RegistryState{}, PackRecord{}, err
	}
	if err := dependenciesSatisfied(state, record.Manifest); err != nil {
		return RegistryState{}, PackRecord{}, err
	}
	return state, record, nil
}

func (r *Registry) ReadActiveEntrypoint(packID, name string, maxBytes int) (ActiveEntrypoint, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return ActiveEntrypoint{}, errors.New("entrypoint name is required")
	}
	if maxBytes == 0 {
		maxBytes = MaxActiveEntrypointBytes
	}
	if maxBytes < 1 || maxBytes > MaxActiveEntrypointBytes {
		return ActiveEntrypoint{}, fmt.Errorf("max_bytes must be between 1 and %d", MaxActiveEntrypointBytes)
	}
	state, record, err := r.ResolveActive(packID)
	if err != nil {
		return ActiveEntrypoint{}, err
	}
	var entry Entrypoint
	found := false
	for _, candidate := range record.Manifest.Entrypoints {
		if candidate.Name == name {
			entry = candidate
			found = true
			break
		}
	}
	if !found {
		return ActiveEntrypoint{}, fmt.Errorf("unknown active entrypoint %q", name)
	}
	if entry.Kind == "mcp-adapter" {
		return ActiveEntrypoint{}, errors.New("executable adapter entrypoint cannot be read by data-only loader")
	}
	var expected File
	found = false
	for _, file := range record.Manifest.Files {
		if filepath.ToSlash(file.Path) == filepath.ToSlash(entry.Path) {
			expected = file
			found = true
			break
		}
	}
	if !found {
		return ActiveEntrypoint{}, errors.New("entrypoint file missing from manifest")
	}
	if expected.Size > int64(maxBytes) {
		return ActiveEntrypoint{}, fmt.Errorf("entrypoint size %d exceeds max_bytes %d", expected.Size, maxBytes)
	}
	path := filepath.Join(record.Root, filepath.FromSlash(entry.Path))
	body, err := recordio.ReadFileLimit(path, int64(maxBytes))
	if err != nil {
		return ActiveEntrypoint{}, err
	}
	sum := sha256.Sum256(body)
	actual := hex.EncodeToString(sum[:])
	if actual != strings.ToLower(expected.SHA256) {
		return ActiveEntrypoint{}, errors.New("entrypoint changed after pack verification")
	}
	return ActiveEntrypoint{
		PackID: record.Manifest.ID, PackVersion: record.Manifest.PackVersion,
		ReceiptID: record.ReceiptID, RegistryRevision: state.Revision,
		Name: entry.Name, Kind: entry.Kind, Path: entry.Path, SHA256: actual, Body: body,
	}, nil
}

func verifyRecordCurrent(state RegistryState, record PackRecord) error {
	if record.Status == "quarantined" {
		return errors.New("quarantined pack is not loadable")
	}
	_, err := Verify(record.Root, record.Manifest, TrustStore{Keys: trustKeys(state)})
	return err
}

func dependenciesSatisfied(state RegistryState, manifest Manifest) error {
	for _, dependency := range manifest.Dependencies {
		receiptID := state.Active[dependency.ID]
		if receiptID == "" {
			return fmt.Errorf("dependency %q is not active", dependency.ID)
		}
		record, ok := state.Packs[receiptID]
		if !ok || record.Status != "active" {
			return fmt.Errorf("dependency %q active record is invalid", dependency.ID)
		}
		if record.Manifest.PackVersion != dependency.Version {
			return fmt.Errorf("dependency %q requires version %s, active version is %s", dependency.ID, dependency.Version, record.Manifest.PackVersion)
		}
	}
	return nil
}

func trustKeys(state RegistryState) map[string]string {
	keys := map[string]string{}
	for id, key := range state.TrustedKeys {
		keys[id] = key.PublicKey
	}
	return keys
}

func appendAudit(state *RegistryState, action, packID, receiptID, detail string) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	seed := action + "\x00" + packID + "\x00" + receiptID + "\x00" + detail + "\x00" + now
	sum := sha256.Sum256([]byte(seed))
	event := AuditEvent{
		ID: "packaudit_" + hex.EncodeToString(sum[:8]), Action: action, PackID: packID,
		ReceiptID: receiptID, Detail: detail, CreatedUTC: now,
	}
	state.Audit = append(state.Audit, event)
	sortAudit(state.Audit)
}
