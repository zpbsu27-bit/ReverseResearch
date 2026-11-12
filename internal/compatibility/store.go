package compatibility

import (
	"context"
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

	"reverseresearch/internal/casebook"
	"reverseresearch/internal/hookplan"
	"reverseresearch/internal/recordio"
	"reverseresearch/internal/targetidentity"
)

var recordIDPattern = regexp.MustCompile(`^compat_[a-f0-9]{32}$`)

const maxCompatibilityRecordBytes = int64(1 << 20)

type HookLookup interface {
	Get(string) (hookplan.Hook, error)
}

type CaseLookup interface {
	Get(string) (casebook.Case, error)
	Verify(string) (casebook.Verification, error)
}

type Store struct {
	root  string
	hooks HookLookup
	cases CaseLookup
}

func New(root string, hooks HookLookup, cases CaseLookup) (*Store, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("compatibility store root is required")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve compatibility store root: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(absolute, "records"), 0o700); err != nil {
		return nil, fmt.Errorf("create compatibility store: %w", err)
	}
	return &Store{root: absolute, hooks: hooks, cases: cases}, nil
}

func (s *Store) Add(request AddRequest) (Record, error) {
	return s.AddContext(context.Background(), request)
}

func (s *Store) AddContext(ctx context.Context, request AddRequest) (Record, error) {
	return s.addContext(ctx, request, nil, "")
}

func (s *Store) ImportManifest(path string) (result ImportResult, err error) {
	return s.ImportManifestContext(context.Background(), path)
}

func (s *Store) ImportManifestContext(ctx context.Context, path string) (result ImportResult, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return ImportResult{}, err
	}
	absolute, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil {
		return ImportResult{}, err
	}
	body, err := recordio.ReadFileLimit(absolute, MaxImportManifestBytes)
	if err != nil {
		return ImportResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return ImportResult{}, err
	}
	info, err := os.Stat(absolute)
	if err != nil {
		return ImportResult{}, err
	}
	var manifest ImportManifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return ImportResult{}, fmt.Errorf("decode compatibility manifest: %w", err)
	}
	if len(manifest.Records) == 0 {
		return ImportResult{}, errors.New("compatibility manifest contains no records")
	}
	sum := sha256.Sum256(body)
	binding := ImportBinding{Path: absolute, SHA256: hex.EncodeToString(sum[:]), Size: info.Size()}
	prepared := make([]Record, 0, len(manifest.Records))
	base := filepath.Dir(absolute)
	for _, request := range manifest.Records {
		if err := ctx.Err(); err != nil {
			return ImportResult{}, err
		}
		if request.ModulePath != "" && !filepath.IsAbs(request.ModulePath) {
			request.ModulePath = filepath.Join(base, request.ModulePath)
		}
		record, err := s.prepareContext(ctx, request, &binding)
		if err != nil {
			return ImportResult{}, err
		}
		prepared = append(prepared, record)
	}
	release, err := recordio.AcquireContext(ctx, filepath.Join(s.root, ".import.lock"), 10*time.Second)
	if err != nil {
		return ImportResult{}, err
	}
	defer func() { err = errors.Join(err, release()) }()
	for _, record := range prepared {
		if err := s.saveIdempotent(record); err != nil {
			return ImportResult{}, err
		}
	}
	return ImportResult{Manifest: binding, Records: prepared}, nil
}

func (s *Store) Get(id string) (Record, error) {
	if !recordIDPattern.MatchString(strings.TrimSpace(id)) {
		return Record{}, ErrInvalidRecordID
	}
	body, err := recordio.ReadFileLimit(s.recordPath(id), maxCompatibilityRecordBytes)
	if err != nil {
		return Record{}, err
	}
	var record Record
	if err := json.Unmarshal(body, &record); err != nil {
		return Record{}, fmt.Errorf("decode compatibility record: %w", err)
	}
	if record.ID != id || record.Module.SHA256 == "" || !validOutcome(record.Outcome) || !validValidation(record.Validation) {
		return Record{}, errors.New("invalid persisted compatibility record")
	}
	return record, nil
}

func (s *Store) List(filter Filter) ([]Record, error) {
	if filter.Limit <= 0 {
		filter.Limit = 100
	}
	if filter.Limit > 1000 {
		filter.Limit = 1000
	}
	entries, err := os.ReadDir(filepath.Join(s.root, "records"))
	if err != nil {
		return nil, err
	}
	records := make([]Record, 0)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		if !recordIDPattern.MatchString(id) {
			continue
		}
		record, err := s.Get(id)
		if err != nil {
			return nil, err
		}
		if !matchesFilter(record, filter) {
			continue
		}
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].CreatedUTC == records[j].CreatedUTC {
			return records[i].ID < records[j].ID
		}
		return records[i].CreatedUTC > records[j].CreatedUTC
	})
	if len(records) > filter.Limit {
		records = records[:filter.Limit]
	}
	return records, nil
}

func (s *Store) Verify(id string) (Verification, error) {
	return s.VerifyContext(context.Background(), id)
}

func (s *Store) VerifyContext(ctx context.Context, id string) (Verification, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	record, err := s.Get(id)
	if err != nil {
		return Verification{}, err
	}
	result := Verification{
		RecordID:                 record.ID,
		RecordValid:              true,
		SourceCurrent:            true,
		HookBindingCurrent:       record.Hook == nil,
		CaseValid:                record.CaseID == "",
		EvidenceLinksCurrent:     record.CaseID == "",
		CompatibilityRevalidated: false,
		Issues:                   []Issue{},
	}
	issue := func(code, message string) {
		result.RecordValid = false
		result.Issues = append(result.Issues, Issue{Code: code, Message: message})
	}
	current, err := targetidentity.InspectContext(ctx, record.Module.Path)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return Verification{}, err
		}
		result.SourceCurrent = false
		issue("module_unavailable", err.Error())
	} else if current.SHA256 != record.Module.SHA256 || current.Size != record.Module.Size {
		result.SourceCurrent = false
		issue("module_changed", "module size or SHA-256 no longer matches the compatibility record")
	}
	if record.Hook != nil {
		result.HookBindingCurrent = false
		if s.hooks == nil {
			issue("hook_lookup_unavailable", "hook lookup is unavailable")
		} else if hook, err := s.hooks.Get(record.Hook.ID); err != nil {
			issue("hook_unavailable", err.Error())
		} else if !hookMatchesRecord(hook, record) {
			issue("hook_changed", "hook record no longer matches the compatibility record")
		} else {
			result.HookBindingCurrent = true
		}
	}
	if record.CaseID != "" {
		result.CaseValid = false
		result.EvidenceLinksCurrent = false
		if s.cases == nil {
			issue("case_lookup_unavailable", "case lookup is unavailable")
		} else {
			value, getErr := s.cases.Get(record.CaseID)
			if getErr != nil {
				issue("case_unavailable", getErr.Error())
			} else {
				found := map[string]casebook.Evidence{}
				for _, evidence := range value.Evidence {
					found[evidence.ID] = evidence
				}
				missing := []string{}
				runtimeEvidence := false
				for _, id := range record.EvidenceIDs {
					evidence, ok := found[id]
					if !ok {
						missing = append(missing, id)
						continue
					}
					if isRuntimeEvidenceKind(evidence.Kind) {
						runtimeEvidence = true
					}
				}
				if len(missing) != 0 {
					issue("evidence_missing", "missing evidence IDs: "+strings.Join(missing, ","))
				} else if record.Validation == ValidationRuntime && !runtimeEvidence {
					issue("runtime_evidence_missing", ErrRuntimeEvidenceKind.Error())
				} else {
					result.EvidenceLinksCurrent = true
				}
				verification, verifyErr := s.cases.Verify(record.CaseID)
				if verifyErr != nil {
					issue("case_verify_failed", verifyErr.Error())
				} else if !verification.Valid {
					issue("case_invalid", "linked research case verification failed")
				} else {
					result.CaseValid = true
				}
			}
		}
	}
	result.CheckedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	return result, nil
}

func (s *Store) addContext(ctx context.Context, request AddRequest, imported *ImportBinding, relativeBase string) (result Record, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if relativeBase != "" && request.ModulePath != "" && !filepath.IsAbs(request.ModulePath) {
		request.ModulePath = filepath.Join(relativeBase, request.ModulePath)
	}
	record, err := s.prepareContext(ctx, request, imported)
	if err != nil {
		return Record{}, err
	}
	release, err := recordio.AcquireContext(ctx, filepath.Join(s.root, ".records.lock"), 10*time.Second)
	if err != nil {
		return Record{}, err
	}
	defer func() { err = errors.Join(err, release()) }()
	if err := s.saveIdempotent(record); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (s *Store) prepareContext(ctx context.Context, request AddRequest, imported *ImportBinding) (Record, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	request, err := normalizeRequest(request)
	if err != nil {
		return Record{}, err
	}
	absolute, err := filepath.Abs(request.ModulePath)
	if err != nil {
		return Record{}, err
	}
	module, err := targetidentity.InspectContext(ctx, absolute)
	if err != nil {
		return Record{}, err
	}
	request.ModulePath = module.Path
	var hookBinding *HookBinding
	if request.HookID != "" {
		if s.hooks == nil {
			return Record{}, errors.New("hook lookup is unavailable")
		}
		hook, err := s.hooks.Get(request.HookID)
		if err != nil {
			return Record{}, err
		}
		if !samePath(hook.Path, module.Path) || hook.Baseline.SHA256 != module.SHA256 || hook.Baseline.Size != module.Size {
			return Record{}, ErrHookMismatch
		}
		hookBinding = &HookBinding{
			ID:             hook.ID,
			SourceRVA:      hook.SourceRVA,
			DestinationRVA: hook.DestinationRVA,
			OriginalHex:    hook.OriginalHex,
			PatchHex:       hook.PatchHex,
			BaselineSHA256: hook.Baseline.SHA256,
		}
	}
	if err := s.validateCaseEvidence(request); err != nil {
		return Record{}, err
	}
	idBody := struct {
		Game        string
		Build       string
		ModuleSHA   string
		ModuleRole  string
		HookID      string
		HookName    string
		Outcome     Outcome
		Validation  Validation
		CaseID      string
		EvidenceIDs []string
		Notes       string
		ImportSHA   string
	}{
		Game: request.Game, Build: request.Build, ModuleSHA: module.SHA256,
		ModuleRole: request.ModuleRole, HookID: request.HookID, HookName: request.HookName,
		Outcome: request.Outcome, Validation: request.Validation, CaseID: request.CaseID,
		EvidenceIDs: request.EvidenceIDs, Notes: request.Notes,
	}
	if imported != nil {
		idBody.ImportSHA = imported.SHA256
	}
	body, _ := json.Marshal(idBody)
	sum := sha256.Sum256(body)
	return Record{
		ID:         "compat_" + hex.EncodeToString(sum[:16]),
		CreatedUTC: time.Now().UTC().Format(time.RFC3339Nano),
		Game:       request.Game, Build: request.Build, ModuleRole: request.ModuleRole,
		Module: module, HookName: request.HookName, Hook: hookBinding,
		Outcome: request.Outcome, Validation: request.Validation,
		CaseID: request.CaseID, EvidenceIDs: append([]string(nil), request.EvidenceIDs...),
		Notes: request.Notes, ImportedFrom: imported,
	}, nil
}

func (s *Store) validateCaseEvidence(request AddRequest) error {
	if request.CaseID == "" {
		return nil
	}
	if s.cases == nil {
		return errors.New("case lookup is unavailable")
	}
	value, err := s.cases.Get(request.CaseID)
	if err != nil {
		return err
	}
	known := map[string]casebook.Evidence{}
	for _, evidence := range value.Evidence {
		known[evidence.ID] = evidence
	}
	runtimeEvidence := false
	for _, id := range request.EvidenceIDs {
		evidence, ok := known[id]
		if !ok {
			return fmt.Errorf("unknown case evidence id %q", id)
		}
		if isRuntimeEvidenceKind(evidence.Kind) {
			runtimeEvidence = true
		}
	}
	if request.Validation == ValidationRuntime && !runtimeEvidence {
		return ErrRuntimeEvidenceKind
	}
	if request.Validation != ValidationRecordOnly {
		verification, err := s.cases.Verify(request.CaseID)
		if err != nil {
			return err
		}
		if !verification.Valid {
			return errors.New("linked research case is not currently valid")
		}
	}
	return nil
}

func isRuntimeEvidenceKind(kind string) bool {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "runtime", "runtime-verification":
		return true
	default:
		return false
	}
}

func (s *Store) saveIdempotent(record Record) error {
	path := s.recordPath(record.ID)
	if existing, err := s.Get(record.ID); err == nil {
		if recordsEquivalent(existing, record) {
			return nil
		}
		return errors.New("compatibility record id collision")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	body, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if int64(len(body)) > maxCompatibilityRecordBytes {
		return fmt.Errorf("compatibility record exceeds durable size limit: %d > %d", len(body), maxCompatibilityRecordBytes)
	}
	return recordio.WriteFile(path, body, 0o600)
}

func (s *Store) recordPath(id string) string {
	return filepath.Join(s.root, "records", id+".json")
}

func matchesFilter(record Record, filter Filter) bool {
	if filter.Game != "" && !strings.EqualFold(strings.TrimSpace(filter.Game), record.Game) {
		return false
	}
	if filter.Build != "" && !strings.EqualFold(strings.TrimSpace(filter.Build), record.Build) {
		return false
	}
	if filter.ModuleSHA != "" && !strings.EqualFold(strings.TrimSpace(filter.ModuleSHA), record.Module.SHA256) {
		return false
	}
	if filter.HookID != "" && (record.Hook == nil || record.Hook.ID != strings.TrimSpace(filter.HookID)) {
		return false
	}
	if filter.Outcome != "" && record.Outcome != filter.Outcome {
		return false
	}
	if filter.Validation != "" && record.Validation != filter.Validation {
		return false
	}
	return true
}

func hookMatchesRecord(hook hookplan.Hook, record Record) bool {
	if record.Hook == nil {
		return false
	}
	return hook.ID == record.Hook.ID &&
		samePath(hook.Path, record.Module.Path) &&
		hook.Baseline.SHA256 == record.Module.SHA256 &&
		hook.SourceRVA == record.Hook.SourceRVA &&
		hook.DestinationRVA == record.Hook.DestinationRVA &&
		hook.OriginalHex == record.Hook.OriginalHex &&
		hook.PatchHex == record.Hook.PatchHex
}

func recordsEquivalent(left, right Record) bool {
	left.CreatedUTC = ""
	right.CreatedUTC = ""
	leftBody, _ := json.Marshal(left)
	rightBody, _ := json.Marshal(right)
	return string(leftBody) == string(rightBody)
}

func samePath(left, right string) bool {
	return strings.EqualFold(filepath.Clean(left), filepath.Clean(right))
}
