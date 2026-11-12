package packregistry

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"reverseresearch/internal/recordio"
)

const (
	registryHotReceiptLimit = 256
	registryHotAuditLimit   = 512
	registryHotPackLimit    = 256

	registryReceiptArchiveShardMaxFiles = 64
	registryReceiptArchiveShardMaxBytes = int64(128 << 10)
	registryReceiptArchiveMaxFiles      = registryReceiptArchiveShardMaxFiles * 256
	registryReceiptArchiveMaxBytes      = registryReceiptArchiveShardMaxBytes * 256

	registryAuditArchiveShardMaxFiles = 64
	registryAuditArchiveShardMaxBytes = int64(128 << 10)
	registryAuditArchiveMaxFiles      = registryAuditArchiveShardMaxFiles * 256
	registryAuditArchiveMaxBytes      = registryAuditArchiveShardMaxBytes * 256

	registryPackArchiveShardMaxFiles = 32
	registryPackArchiveShardMaxBytes = int64(1 << 20)
	registryPackArchiveMaxFiles      = registryPackArchiveShardMaxFiles * 256
	registryPackArchiveMaxBytes      = registryPackArchiveShardMaxBytes * 256
)

func (r *Registry) archiveRoot(kind string) string {
	return filepath.Join(r.root, "archive", kind)
}

func registryArchiveShard(id string) string {
	sum := sha256.Sum256([]byte(id))
	return fmt.Sprintf("%02x", sum[0])
}

func (r *Registry) archivePath(kind, id string) string {
	return filepath.Join(r.archiveRoot(kind), registryArchiveShard(id), id+".json")
}

func (r *Registry) legacyArchivePath(kind, id string) string {
	return filepath.Join(r.archiveRoot(kind), id+".json")
}

func (r *Registry) archiveReceiptPath(id string) string {
	return r.archivePath("receipts", id)
}

func (r *Registry) archiveAuditPath(id string) string {
	return r.archivePath("audit", id)
}

func (r *Registry) archivePackPath(id string) string {
	return r.archivePath("packs", id)
}

func (r *Registry) GetHot() (RegistryState, error) {
	return r.readUnlocked()
}

func (r *Registry) hydrateArchivedState(state RegistryState) (RegistryState, error) {
	receipts, err := r.readArchivedReceipts()
	if err != nil {
		return RegistryState{}, err
	}
	receiptByID := make(map[string]Receipt, len(receipts)+len(state.Receipts))
	for _, receipt := range receipts {
		receiptByID[receipt.ID] = receipt
	}
	for _, receipt := range state.Receipts {
		receiptByID[receipt.ID] = receipt
	}
	state.Receipts = state.Receipts[:0]
	for _, receipt := range receiptByID {
		state.Receipts = append(state.Receipts, receipt)
	}
	sort.Slice(state.Receipts, func(i, j int) bool { return state.Receipts[i].ID < state.Receipts[j].ID })

	audit, err := r.readArchivedAudit()
	if err != nil {
		return RegistryState{}, err
	}
	auditByID := make(map[string]AuditEvent, len(audit)+len(state.Audit))
	for _, event := range audit {
		auditByID[event.ID] = event
	}
	for _, event := range state.Audit {
		if existing, ok := auditByID[event.ID]; ok && existing != event {
			return RegistryState{}, fmt.Errorf("pack audit event %q conflicts with archived copy", event.ID)
		}
		auditByID[event.ID] = event
	}
	state.Audit = state.Audit[:0]
	for _, event := range auditByID {
		state.Audit = append(state.Audit, event)
	}
	sortAudit(state.Audit)

	packs, err := r.readArchivedPacks()
	if err != nil {
		return RegistryState{}, err
	}
	if state.Packs == nil {
		state.Packs = map[string]PackRecord{}
	}
	for id, record := range packs {
		if _, hot := state.Packs[id]; !hot {
			state.Packs[id] = record
		}
	}
	return state, nil
}

func (r *Registry) compactState(state *RegistryState) error {
	if state == nil {
		return errors.New("registry state is required")
	}
	if len(state.Receipts) > registryHotReceiptLimit {
		sort.Slice(state.Receipts, func(i, j int) bool {
			if state.Receipts[i].VerifiedUTC != state.Receipts[j].VerifiedUTC {
				return state.Receipts[i].VerifiedUTC < state.Receipts[j].VerifiedUTC
			}
			return state.Receipts[i].ID < state.Receipts[j].ID
		})
		cut := len(state.Receipts) - registryHotReceiptLimit
		for _, receipt := range state.Receipts[:cut] {
			if err := r.writeReceiptArchive(receipt); err != nil {
				return err
			}
		}
		state.Receipts = append([]Receipt(nil), state.Receipts[cut:]...)
		sort.Slice(state.Receipts, func(i, j int) bool { return state.Receipts[i].ID < state.Receipts[j].ID })
	}

	if len(state.Audit) > registryHotAuditLimit {
		sortAudit(state.Audit)
		cut := len(state.Audit) - registryHotAuditLimit
		for _, event := range state.Audit[:cut] {
			if err := r.writeImmutableArchive("audit", r.archiveAuditPath(event.ID), r.legacyArchivePath("audit", event.ID), event); err != nil {
				return err
			}
		}
		state.Audit = append([]AuditEvent(nil), state.Audit[cut:]...)
	}

	if len(state.Packs) > registryHotPackLimit+len(state.Active) {
		active := make(map[string]struct{}, len(state.Active))
		for _, receiptID := range state.Active {
			if receiptID != "" {
				active[receiptID] = struct{}{}
			}
		}
		type packCandidate struct {
			id       string
			verified string
		}
		candidates := make([]packCandidate, 0, len(state.Packs))
		for id, record := range state.Packs {
			if _, keep := active[id]; keep {
				continue
			}
			candidates = append(candidates, packCandidate{id: id, verified: record.VerifiedUTC})
		}
		sort.Slice(candidates, func(i, j int) bool {
			if candidates[i].verified != candidates[j].verified {
				return candidates[i].verified > candidates[j].verified
			}
			return candidates[i].id < candidates[j].id
		})
		for _, candidate := range candidates[registryHotPackLimit:] {
			record := state.Packs[candidate.id]
			if err := r.writePackArchive(candidate.id, record); err != nil {
				return err
			}
			delete(state.Packs, candidate.id)
		}
	}
	return nil
}

func (r *Registry) lookupReceipt(state RegistryState, id string) (Receipt, bool, error) {
	for _, receipt := range state.Receipts {
		if receipt.ID == id {
			return receipt, true, nil
		}
	}
	body, err := r.readArchiveFile("receipts", id)
	if errors.Is(err, os.ErrNotExist) {
		return Receipt{}, false, nil
	}
	if err != nil {
		return Receipt{}, false, err
	}
	var receipt Receipt
	if err := json.Unmarshal(body, &receipt); err != nil {
		return Receipt{}, false, fmt.Errorf("decode archived pack receipt %q: %w", id, err)
	}
	if receipt.ID != id {
		return Receipt{}, false, fmt.Errorf("archived pack receipt identity mismatch: %q", id)
	}
	return receipt, true, nil
}

func (r *Registry) lookupPackRecord(state RegistryState, id string) (PackRecord, bool, error) {
	if record, ok := state.Packs[id]; ok {
		return record, true, nil
	}
	body, err := r.readArchiveFile("packs", id)
	if errors.Is(err, os.ErrNotExist) {
		return PackRecord{}, false, nil
	}
	if err != nil {
		return PackRecord{}, false, err
	}
	var record PackRecord
	if err := json.Unmarshal(body, &record); err != nil {
		return PackRecord{}, false, fmt.Errorf("decode archived pack record %q: %w", id, err)
	}
	if record.ReceiptID != id {
		return PackRecord{}, false, fmt.Errorf("archived pack record identity mismatch: %q", id)
	}
	return record, true, nil
}

// Receipt archives are immutable except for the one monotonic transition that
// fills RegistryRevision after the first registry publish. This preserves the
// original two-phase VerifyAndRecord contract even if a receipt has already
// moved to cold storage.
func (r *Registry) writeReceiptArchive(receipt Receipt) error {
	path := r.archiveReceiptPath(receipt.ID)
	legacy := r.legacyArchivePath("receipts", receipt.ID)
	existingBody, err := r.readArchiveFile("receipts", receipt.ID)
	if errors.Is(err, os.ErrNotExist) {
		return r.writeArchiveBytes("receipts", path, legacy, receipt)
	}
	if err != nil {
		return err
	}
	var existing Receipt
	if err := json.Unmarshal(existingBody, &existing); err != nil {
		return fmt.Errorf("decode archived pack receipt %q: %w", receipt.ID, err)
	}
	if existing == receipt {
		return r.writeArchiveBytes("receipts", path, legacy, receipt)
	}
	existingWithoutRevision := existing
	existingWithoutRevision.RegistryRevision = ""
	incomingWithoutRevision := receipt
	incomingWithoutRevision.RegistryRevision = ""
	if existingWithoutRevision == incomingWithoutRevision &&
		existing.RegistryRevision == "" && receipt.RegistryRevision != "" {
		return r.writeArchiveBytes("receipts", path, legacy, receipt)
	}
	return fmt.Errorf("immutable registry receipt changed: %s", receipt.ID)
}

func (r *Registry) writeImmutableArchive(kind, path, legacy string, value any) error {
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	existing, err := readArchivePathWithLegacy(path, legacy)
	if err == nil && !bytes.Equal(existing, body) {
		return fmt.Errorf("immutable registry archive changed: %s", filepath.Base(path))
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	maxFiles, maxBytes, err := registryArchiveShardQuota(kind)
	if err != nil {
		return err
	}
	if err := recordio.WriteFileShardQuota(path, body, 0o600, maxFiles, maxBytes); err != nil {
		return fmt.Errorf("write %s archive within durable shard quota: %w", kind, err)
	}
	if legacy != path {
		_ = os.Remove(legacy)
	}
	return nil
}

func (r *Registry) writeArchiveBytes(kind, path, legacy string, value any) error {
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	maxFiles, maxBytes, err := registryArchiveShardQuota(kind)
	if err != nil {
		return err
	}
	if err := recordio.WriteFileShardQuota(path, body, 0o600, maxFiles, maxBytes); err != nil {
		return fmt.Errorf("write %s archive within durable shard quota: %w", kind, err)
	}
	if legacy != path {
		_ = os.Remove(legacy)
	}
	return nil
}

func (r *Registry) writePackArchive(id string, record PackRecord) error {
	if strings.TrimSpace(id) == "" || record.ReceiptID != id {
		return errors.New("pack archive receipt identity mismatch")
	}
	path := r.archivePackPath(id)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	body, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if err := recordio.WriteFileShardQuota(
		path, body, 0o600,
		registryPackArchiveShardMaxFiles,
		registryPackArchiveShardMaxBytes,
	); err != nil {
		return fmt.Errorf("write pack archive within durable shard quota: %w", err)
	}
	_ = os.Remove(r.legacyArchivePath("packs", id))
	return nil
}

func (r *Registry) readArchiveFile(kind, id string) ([]byte, error) {
	return readArchivePathWithLegacy(r.archivePath(kind, id), r.legacyArchivePath(kind, id))
}

func readArchivePathWithLegacy(path, legacy string) ([]byte, error) {
	body, err := recordio.ReadFileLimit(path, MaxRegistryHotBytes)
	if errors.Is(err, os.ErrNotExist) && legacy != path {
		return recordio.ReadFileLimit(legacy, MaxRegistryHotBytes)
	}
	return body, err
}

func (r *Registry) readArchivedReceipts() ([]Receipt, error) {
	var out []Receipt
	err := r.readArchiveDir(
		r.archiveRoot("receipts"),
		registryReceiptArchiveMaxFiles,
		registryReceiptArchiveMaxBytes,
		func(name string, body []byte) error {
			var value Receipt
			if err := json.Unmarshal(body, &value); err != nil {
				return err
			}
			if name != value.ID+".json" {
				return errors.New("archived receipt identity mismatch")
			}
			out = append(out, value)
			return nil
		},
	)
	return out, err
}

func (r *Registry) readArchivedAudit() ([]AuditEvent, error) {
	var out []AuditEvent
	err := r.readArchiveDir(
		r.archiveRoot("audit"),
		registryAuditArchiveMaxFiles,
		registryAuditArchiveMaxBytes,
		func(name string, body []byte) error {
			var value AuditEvent
			if err := json.Unmarshal(body, &value); err != nil {
				return err
			}
			if name != value.ID+".json" {
				return errors.New("archived audit identity mismatch")
			}
			out = append(out, value)
			return nil
		},
	)
	return out, err
}

func (r *Registry) readArchivedPacks() (map[string]PackRecord, error) {
	out := map[string]PackRecord{}
	err := r.readArchiveDir(
		r.archiveRoot("packs"),
		registryPackArchiveMaxFiles,
		registryPackArchiveMaxBytes,
		func(name string, body []byte) error {
			var value PackRecord
			if err := json.Unmarshal(body, &value); err != nil {
				return err
			}
			id := strings.TrimSuffix(name, ".json")
			if value.ReceiptID != id {
				return errors.New("archived pack identity mismatch")
			}
			out[id] = value
			return nil
		},
	)
	return out, err
}

func (r *Registry) readArchiveDir(root string, maxFiles int, maxBytes int64, consume func(string, []byte) error) error {
	seen := map[string]struct{}{}
	var files int
	var totalBytes int64
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if errors.Is(walkErr, os.ErrNotExist) {
			return nil
		}
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			return nil
		}
		name := entry.Name()
		if _, duplicate := seen[name]; duplicate {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		files++
		if files > maxFiles {
			return fmt.Errorf("registry archive hydration exceeds file limit: %d > %d", files, maxFiles)
		}
		if info.Size() < 0 || totalBytes > maxBytes-info.Size() {
			return fmt.Errorf("registry archive hydration exceeds byte limit: %d", maxBytes)
		}
		totalBytes += info.Size()
		body, err := recordio.ReadFileLimit(path, MaxRegistryHotBytes)
		if err != nil {
			return err
		}
		if err := consume(name, body); err != nil {
			return fmt.Errorf("read registry archive %s: %w", path, err)
		}
		seen[name] = struct{}{}
		return nil
	})
}

func registryArchiveShardQuota(kind string) (int, int64, error) {
	switch kind {
	case "receipts":
		return registryReceiptArchiveShardMaxFiles, registryReceiptArchiveShardMaxBytes, nil
	case "audit":
		return registryAuditArchiveShardMaxFiles, registryAuditArchiveShardMaxBytes, nil
	case "packs":
		return registryPackArchiveShardMaxFiles, registryPackArchiveShardMaxBytes, nil
	default:
		return 0, 0, fmt.Errorf("unknown registry archive kind %q", kind)
	}
}

func sortAudit(events []AuditEvent) {
	sort.SliceStable(events, func(i, j int) bool {
		if events[i].CreatedUTC != events[j].CreatedUTC {
			return events[i].CreatedUTC < events[j].CreatedUTC
		}
		return events[i].ID < events[j].ID
	})
}
