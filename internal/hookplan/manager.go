package hookplan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"reverseresearch/internal/patchplan"
	"reverseresearch/internal/recordio"
	"reverseresearch/internal/targetidentity"
)

var hookIDPattern = regexp.MustCompile("^hook_[a-f0-9]{32}$")

const maxHookRecordBytes = int64(1 << 20)

type Manager struct {
	root        string
	stateRoot   string
	patcher     *patchplan.Manager
	afterEffect func(string) error
}

func New(root, stateRoot string) (*Manager, error) {
	return newManagerForTest(root, stateRoot, nil)
}

func newManagerForTest(root, stateRoot string, afterEffect func(string) error) (*Manager, error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve project root: %w", err)
	}
	stateAbs, err := filepath.Abs(stateRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve hook state root: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(stateAbs, "plans"), 0o700); err != nil {
		return nil, fmt.Errorf("create hook state root: %w", err)
	}
	patchRoot := filepath.Join(filepath.Dir(stateAbs), "patches")
	patcher, err := patchplan.New(patchRoot)
	if err != nil {
		return nil, err
	}
	return &Manager{
		root:        rootAbs,
		stateRoot:   stateAbs,
		patcher:     patcher,
		afterEffect: afterEffect,
	}, nil
}

func (m *Manager) Plan(ctx context.Context, request PlanRequest) (result Hook, err error) {
	request.Path = strings.TrimSpace(request.Path)
	request.Description = strings.TrimSpace(request.Description)
	if request.Path == "" {
		return Hook{}, errors.New("hook target path is required")
	}
	if request.SourceRVA == 0 || request.DestinationRVA == 0 {
		return Hook{}, errors.New("source_rva and destination_rva are required")
	}
	if request.SourceRVA == request.DestinationRVA {
		return Hook{}, errors.New("hook source and destination must differ")
	}

	baseline, err := targetidentity.InspectContext(ctx, request.Path)
	if err != nil {
		return Hook{}, err
	}
	if baseline.Format != "pe" || baseline.PE == nil || (baseline.PE.Bits != 32 && baseline.PE.Bits != 64) {
		return Hook{}, errors.New("hook planning requires a 32-bit or 64-bit PE file")
	}
	if err := requireExecutableRVA(baseline, request.SourceRVA, "source_rva"); err != nil {
		return Hook{}, err
	}
	if err := requireExecutableRVA(baseline, request.DestinationRVA, "destination_rva"); err != nil {
		return Hook{}, err
	}

	minimum, err := buildRel32Detour(request.SourceRVA, request.DestinationRVA, 5)
	if err != nil {
		return Hook{}, err
	}
	instructions, overwriteSize, err := m.proveInstructionBoundary(ctx, baseline, request.SourceRVA, len(minimum))
	if err != nil {
		return Hook{}, err
	}
	sourceOffset, remaining, err := rvaToRawOffset(baseline, request.SourceRVA)
	if err != nil {
		return Hook{}, err
	}
	if remaining < overwriteSize {
		return Hook{}, errors.New("hook overwrite extends beyond raw section bytes")
	}
	original, err := readFileRange(baseline.Path, sourceOffset, overwriteSize)
	if err != nil {
		return Hook{}, err
	}
	if strings.TrimSpace(request.ExpectedHex) != "" {
		expected, err := decodeFlexibleHex(request.ExpectedHex)
		if err != nil {
			return Hook{}, fmt.Errorf("expected_hex: %w", err)
		}
		if len(expected) != len(original) || !bytes.Equal(expected, original) {
			return Hook{}, fmt.Errorf("%w: found %s", ErrWrongOriginalBytes, strings.ToUpper(hex.EncodeToString(original)))
		}
	}
	patch, err := buildRel32Detour(request.SourceRVA, request.DestinationRVA, overwriteSize)
	if err != nil {
		return Hook{}, err
	}
	current, err := targetidentity.InspectContext(ctx, baseline.Path)
	if err != nil {
		return Hook{}, err
	}
	if current.SHA256 != baseline.SHA256 || current.Size != baseline.Size || !samePEStructure(baseline, current) {
		return Hook{}, errors.New("hook target changed while proving instruction boundary")
	}

	idMaterial := strings.Join([]string{
		baseline.Path,
		baseline.SHA256,
		fmt.Sprintf("%X", request.SourceRVA),
		fmt.Sprintf("%X", request.DestinationRVA),
		hex.EncodeToString(original),
		hex.EncodeToString(patch),
	}, "\x00")
	sum := sha256.Sum256([]byte(idMaterial))
	hookID := "hook_" + hex.EncodeToString(sum[:16])

	releaseRegistry, err := recordio.Acquire(filepath.Join(m.stateRoot, ".registry.lock"), 10*time.Second)
	if err != nil {
		return Hook{}, err
	}
	defer func() { err = errors.Join(err, releaseRegistry()) }()

	if existing, err := m.load(hookID); err == nil {
		if sameHookCore(existing, baseline, request, original, patch) {
			return existing, nil
		}
		return Hook{}, errors.New("hook id collision")
	} else if !errors.Is(err, os.ErrNotExist) {
		return Hook{}, err
	}
	if err := m.checkConflict(baseline.Path, request.SourceRVA, overwriteSize, hookID); err != nil {
		return Hook{}, err
	}

	patchRecord, err := m.patcher.Plan(patchplan.PlanRequest{
		Path:           baseline.Path,
		Offset:         sourceOffset,
		ExpectedHex:    hex.EncodeToString(original),
		ReplacementHex: hex.EncodeToString(patch),
		Description:    "hook detour: " + request.Description,
	})
	if err != nil {
		return Hook{}, err
	}
	afterPlan, err := targetidentity.InspectContext(ctx, baseline.Path)
	if err != nil {
		return Hook{}, err
	}
	if afterPlan.SHA256 != baseline.SHA256 || afterPlan.Size != baseline.Size || !samePEStructure(baseline, afterPlan) {
		return Hook{}, errors.New("hook target changed while creating patch plan")
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	hook := Hook{
		ID:               hookID,
		Version:          1,
		State:            StatePlanned,
		CreatedUTC:       now,
		UpdatedUTC:       now,
		Path:             baseline.Path,
		Baseline:         baseline,
		SourceRVA:        request.SourceRVA,
		DestinationRVA:   request.DestinationRVA,
		SourceFileOffset: sourceOffset,
		OverwriteSize:    overwriteSize,
		OriginalHex:      hex.EncodeToString(original),
		PatchHex:         hex.EncodeToString(patch),
		Relocation:       "same-module-rva-rel32",
		Instructions:     instructions,
		PatchPlanID:      patchRecord.ID,
		Description:      request.Description,
	}
	if err := m.save(hook); err != nil {
		return Hook{}, err
	}
	return hook, nil
}

func (m *Manager) Get(hookID string) (Hook, error) {
	if !validHookID(hookID) {
		return Hook{}, ErrInvalidHookID
	}
	return m.load(hookID)
}

func (m *Manager) List(path string) ([]Hook, error) {
	hooks, err := m.listHooks()
	if err != nil {
		return nil, err
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return hooks, nil
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	filtered := make([]Hook, 0, len(hooks))
	for _, hook := range hooks {
		if samePath(hook.Path, absolute) {
			filtered = append(filtered, hook)
		}
	}
	return filtered, nil
}

func (m *Manager) Verify(hookID string) (VerifyResult, error) {
	hook, err := m.Get(hookID)
	if err != nil {
		return VerifyResult{}, err
	}
	currentIdentity, inspectErr := targetidentity.Inspect(hook.Path)
	structureMatch := inspectErr == nil && samePEStructure(hook.Baseline, currentIdentity)
	current, readErr := readFileRange(hook.Path, hook.SourceFileOffset, hook.OverwriteSize)
	result := VerifyResult{
		HookID:         hook.ID,
		State:          hook.State,
		Version:        hook.Version,
		Path:           hook.Path,
		StructureMatch: structureMatch,
		OriginalHex:    hook.OriginalHex,
		PatchHex:       hook.PatchHex,
	}
	if readErr != nil {
		result.CurrentState = "unreadable"
		return result, nil
	}
	result.CurrentHex = hex.EncodeToString(current)
	original, _ := hex.DecodeString(hook.OriginalHex)
	patch, _ := hex.DecodeString(hook.PatchHex)
	switch {
	case bytes.Equal(current, original):
		result.CurrentState = "original"
	case bytes.Equal(current, patch):
		result.CurrentState = "patch"
	default:
		result.CurrentState = "drifted"
	}
	expected := "original"
	switch hook.State {
	case StateApplying, StateApplied:
		expected = "patch"
	case StateRollingBack, StateRolledBack, StateCancelled, StatePlanned:
		expected = "original"
	}
	result.MatchesExpectedState = structureMatch && result.CurrentState == expected
	return result, nil
}

func (m *Manager) Apply(request ApplyRequest) (result Hook, err error) {
	if !validHookID(request.HookID) {
		return Hook{}, ErrInvalidHookID
	}
	if !request.ConfirmInPlace {
		return Hook{}, errors.New("hook apply requires confirm_in_place=true")
	}
	operationID, err := validateOperationID(request.OperationID)
	if err != nil {
		return Hook{}, err
	}
	release, err := recordio.Acquire(m.hookLockPath(request.HookID), 10*time.Second)
	if err != nil {
		return Hook{}, err
	}
	defer func() { err = errors.Join(err, release()) }()

	hook, err := m.load(request.HookID)
	if err != nil {
		return Hook{}, err
	}
	if hook.State == StateApplied && hook.ApplyOperationID == operationID {
		return hook, nil
	}
	if hook.State == StateApplying && hook.ApplyOperationID == operationID {
		if request.ExpectedVersion != hook.Version {
			return Hook{}, fmt.Errorf("%w: expected=%d current=%d", ErrVersionConflict, request.ExpectedVersion, hook.Version)
		}
		return m.finishApply(hook, operationID)
	}
	if hook.State != StatePlanned {
		return Hook{}, fmt.Errorf("hook state %q cannot be applied", hook.State)
	}
	if request.ExpectedVersion != hook.Version {
		return Hook{}, fmt.Errorf("%w: expected=%d current=%d", ErrVersionConflict, request.ExpectedVersion, hook.Version)
	}
	if err := m.requireStructure(hook); err != nil {
		return Hook{}, err
	}
	if err := m.requireBytes(hook, false); err != nil {
		return Hook{}, err
	}
	hook.Version++
	hook.State = StateApplying
	hook.ApplyOperationID = operationID
	hook.UpdatedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	if err := m.save(hook); err != nil {
		return Hook{}, err
	}
	return m.finishApply(hook, operationID)
}

func (m *Manager) finishApply(hook Hook, operationID string) (Hook, error) {
	if _, err := m.patcher.Apply(patchplan.ApplyRequest{
		PlanID:      hook.PatchPlanID,
		InPlace:     true,
		OperationID: hookPatchOperationID(hook.ID, "a", operationID),
	}); err != nil {
		return Hook{}, err
	}
	if m.afterEffect != nil {
		if err := m.afterEffect("apply"); err != nil {
			return Hook{}, err
		}
	}
	hook.Version++
	hook.State = StateApplied
	hook.AppliedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	hook.UpdatedUTC = hook.AppliedUTC
	if err := m.save(hook); err != nil {
		return Hook{}, err
	}
	return hook, nil
}

func (m *Manager) Rollback(request RollbackRequest) (result Hook, err error) {
	if !validHookID(request.HookID) {
		return Hook{}, ErrInvalidHookID
	}
	operationID, err := validateOperationID(request.OperationID)
	if err != nil {
		return Hook{}, err
	}
	release, err := recordio.Acquire(m.hookLockPath(request.HookID), 10*time.Second)
	if err != nil {
		return Hook{}, err
	}
	defer func() { err = errors.Join(err, release()) }()

	hook, err := m.load(request.HookID)
	if err != nil {
		return Hook{}, err
	}
	if hook.State == StateRolledBack && hook.RollbackOperationID == operationID {
		return hook, nil
	}
	if hook.State == StateRollingBack && hook.RollbackOperationID == operationID {
		if request.ExpectedVersion != hook.Version {
			return Hook{}, fmt.Errorf("%w: expected=%d current=%d", ErrVersionConflict, request.ExpectedVersion, hook.Version)
		}
		return m.finishRollback(hook, operationID)
	}
	if hook.State != StateApplied {
		return Hook{}, fmt.Errorf("hook state %q cannot be rolled back", hook.State)
	}
	if request.ExpectedVersion != hook.Version {
		return Hook{}, fmt.Errorf("%w: expected=%d current=%d", ErrVersionConflict, request.ExpectedVersion, hook.Version)
	}
	if err := m.requireStructure(hook); err != nil {
		return Hook{}, err
	}
	if err := m.requireBytes(hook, true); err != nil {
		return Hook{}, err
	}
	hook.Version++
	hook.State = StateRollingBack
	hook.RollbackOperationID = operationID
	hook.UpdatedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	if err := m.save(hook); err != nil {
		return Hook{}, err
	}
	return m.finishRollback(hook, operationID)
}

func (m *Manager) finishRollback(hook Hook, operationID string) (Hook, error) {
	if _, err := m.patcher.RollbackOperation(patchplan.RollbackRequest{
		PlanID:      hook.PatchPlanID,
		OperationID: hookPatchOperationID(hook.ID, "r", operationID),
	}); err != nil {
		return Hook{}, err
	}
	if m.afterEffect != nil {
		if err := m.afterEffect("rollback"); err != nil {
			return Hook{}, err
		}
	}
	hook.Version++
	hook.State = StateRolledBack
	hook.RolledBackUTC = time.Now().UTC().Format(time.RFC3339Nano)
	hook.UpdatedUTC = hook.RolledBackUTC
	if err := m.save(hook); err != nil {
		return Hook{}, err
	}
	return hook, nil
}

func (m *Manager) Cancel(request CancelRequest) (result Hook, err error) {
	if !validHookID(request.HookID) {
		return Hook{}, ErrInvalidHookID
	}
	release, err := recordio.Acquire(m.hookLockPath(request.HookID), 10*time.Second)
	if err != nil {
		return Hook{}, err
	}
	defer func() { err = errors.Join(err, release()) }()

	hook, err := m.load(request.HookID)
	if err != nil {
		return Hook{}, err
	}
	if hook.Version != request.ExpectedVersion {
		return Hook{}, fmt.Errorf("%w: expected=%d current=%d", ErrVersionConflict, request.ExpectedVersion, hook.Version)
	}
	if hook.State != StatePlanned {
		return Hook{}, fmt.Errorf("hook state %q cannot be cancelled", hook.State)
	}
	hook.Version++
	hook.State = StateCancelled
	hook.CancelledUTC = time.Now().UTC().Format(time.RFC3339Nano)
	hook.UpdatedUTC = hook.CancelledUTC
	if err := m.save(hook); err != nil {
		return Hook{}, err
	}
	return hook, nil
}

func (m *Manager) requireStructure(hook Hook) error {
	current, err := targetidentity.Inspect(hook.Path)
	if err != nil {
		return err
	}
	if !samePEStructure(hook.Baseline, current) {
		return ErrStructureChanged
	}
	return nil
}

func (m *Manager) requireBytes(hook Hook, patch bool) error {
	expectedHex := hook.OriginalHex
	mismatch := ErrWrongOriginalBytes
	if patch {
		expectedHex = hook.PatchHex
		mismatch = ErrWrongAppliedBytes
	}
	expected, err := hex.DecodeString(expectedHex)
	if err != nil {
		return err
	}
	current, err := readFileRange(hook.Path, hook.SourceFileOffset, len(expected))
	if err != nil {
		return err
	}
	if !bytes.Equal(current, expected) {
		return fmt.Errorf("%w: found %s", mismatch, strings.ToUpper(hex.EncodeToString(current)))
	}
	return nil
}

func (m *Manager) checkConflict(path string, sourceRVA uint64, overwriteSize int, ignoreID string) error {
	if overwriteSize <= 0 || sourceRVA > math.MaxUint64-uint64(overwriteSize) {
		return errors.New("invalid hook source interval")
	}
	end := sourceRVA + uint64(overwriteSize)
	hooks, err := m.listHooks()
	if err != nil {
		return err
	}
	for _, existing := range hooks {
		if existing.ID == ignoreID || !activeState(existing.State) || !samePath(existing.Path, path) {
			continue
		}
		existingEnd := existing.SourceRVA + uint64(existing.OverwriteSize)
		if sourceRVA < existingEnd && existing.SourceRVA < end {
			return fmt.Errorf("%w: [0x%X,0x%X) overlaps %s [0x%X,0x%X)",
				ErrConflict, sourceRVA, end, existing.ID, existing.SourceRVA, existingEnd)
		}
	}
	return nil
}

func (m *Manager) listHooks() ([]Hook, error) {
	entries, err := os.ReadDir(filepath.Join(m.stateRoot, "plans"))
	if err != nil {
		return nil, err
	}
	hooks := make([]Hook, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		if !validHookID(id) {
			continue
		}
		hook, err := m.load(id)
		if err != nil {
			return nil, err
		}
		hooks = append(hooks, hook)
	}
	sort.Slice(hooks, func(i, j int) bool { return hooks[i].ID < hooks[j].ID })
	return hooks, nil
}

func (m *Manager) save(hook Hook) error {
	body, err := json.MarshalIndent(hook, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if int64(len(body)) > maxHookRecordBytes {
		return fmt.Errorf("hook record exceeds durable size limit: %d > %d", len(body), maxHookRecordBytes)
	}
	return recordio.WriteFile(m.hookPath(hook.ID), body, 0o600)
}

func (m *Manager) load(hookID string) (Hook, error) {
	body, err := recordio.ReadFileLimit(m.hookPath(hookID), maxHookRecordBytes)
	if err != nil {
		return Hook{}, err
	}
	var hook Hook
	if err := json.Unmarshal(body, &hook); err != nil {
		return Hook{}, fmt.Errorf("decode hook %s: %w", hookID, err)
	}
	if hook.ID != hookID || hook.Version < 1 || hook.PatchPlanID == "" || hook.OverwriteSize < 5 {
		return Hook{}, errors.New("invalid persisted hook")
	}
	return hook, nil
}

func (m *Manager) hookPath(hookID string) string {
	return filepath.Join(m.stateRoot, "plans", hookID+".json")
}

func (m *Manager) hookLockPath(hookID string) string {
	return filepath.Join(m.stateRoot, "plans", "."+hookID+".lock")
}

func validHookID(value string) bool {
	return hookIDPattern.MatchString(strings.TrimSpace(value))
}

func buildRel32Detour(sourceRVA, destinationRVA uint64, overwriteSize int) ([]byte, error) {
	if overwriteSize < 5 || overwriteSize > MaxHookOverwriteBytes {
		return nil, fmt.Errorf("hook overwrite size must be between 5 and %d", MaxHookOverwriteBytes)
	}
	if sourceRVA > math.MaxUint64-5 {
		return nil, errors.New("hook source RVA overflows rel32 next instruction")
	}
	next := sourceRVA + 5
	disp, ok := signedDifference(destinationRVA, next)
	if !ok || disp < math.MinInt32 || disp > math.MaxInt32 {
		return nil, errors.New("same-module destination is outside rel32 range")
	}
	patch := make([]byte, overwriteSize)
	patch[0] = 0xE9
	binary.LittleEndian.PutUint32(patch[1:5], uint32(int32(disp)))
	for index := 5; index < len(patch); index++ {
		patch[index] = 0x90
	}
	return patch, nil
}

func requireExecutableRVA(identity targetidentity.Identity, rva uint64, field string) error {
	if identity.PE == nil {
		return errors.New("PE metadata is missing")
	}
	const imageScnMemExecute = uint32(0x20000000)
	for _, section := range identity.PE.Sections {
		start := uint64(section.VirtualAddress)
		span := uint64(section.VirtualSize)
		if raw := uint64(section.RawSize); raw > span {
			span = raw
		}
		if span == 0 || rva < start || rva-start >= span {
			continue
		}
		if section.Characteristics&imageScnMemExecute == 0 {
			return fmt.Errorf("%s RVA 0x%X is in non-executable section %q", field, rva, section.Name)
		}
		return nil
	}
	return fmt.Errorf("%s RVA 0x%X is outside mapped PE sections", field, rva)
}

func rvaToRawOffset(identity targetidentity.Identity, rva uint64) (int64, int, error) {
	if identity.PE == nil {
		return 0, 0, errors.New("PE metadata is missing")
	}
	for _, section := range identity.PE.Sections {
		start := uint64(section.VirtualAddress)
		if rva < start {
			continue
		}
		delta := rva - start
		if delta >= uint64(section.RawSize) {
			continue
		}
		fileOffset := uint64(section.RawOffset) + delta
		if fileOffset > math.MaxInt64 {
			return 0, 0, errors.New("hook file offset overflow")
		}
		return int64(fileOffset), int(uint64(section.RawSize) - delta), nil
	}
	return 0, 0, fmt.Errorf("source RVA 0x%X is not backed by raw section bytes", rva)
}

func readFileRange(path string, offset int64, size int) ([]byte, error) {
	if offset < 0 || size < 0 {
		return nil, errors.New("invalid file range")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	body := make([]byte, size)
	if size == 0 {
		return body, nil
	}
	n, err := file.ReadAt(body, offset)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if n != size {
		return nil, fmt.Errorf("short file read at 0x%X: got %d want %d", offset, n, size)
	}
	return body, nil
}

func decodeFlexibleHex(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, " ", "")
	value = strings.ReplaceAll(value, "\t", "")
	value = strings.ReplaceAll(value, "_", "")
	value = strings.TrimPrefix(strings.TrimPrefix(value, "0x"), "0X")
	if value == "" {
		return nil, errors.New("hex value is empty")
	}
	if len(value)%2 != 0 {
		return nil, errors.New("hex value must contain whole bytes")
	}
	return hex.DecodeString(value)
}

func signedDifference(target, base uint64) (int64, bool) {
	if target >= base {
		delta := target - base
		if delta > math.MaxInt64 {
			return 0, false
		}
		return int64(delta), true
	}
	delta := base - target
	if delta > uint64(math.MaxInt64)+1 {
		return 0, false
	}
	if delta == uint64(math.MaxInt64)+1 {
		return math.MinInt64, true
	}
	return -int64(delta), true
}

func hookPatchOperationID(hookID, kind, operationID string) string {
	short := strings.TrimPrefix(strings.TrimSpace(hookID), "hook_")
	if len(short) > 12 {
		short = short[:12]
	}
	return "hook" + kind + "-" + short + "-" + operationID
}

func samePEStructure(left, right targetidentity.Identity) bool {
	if left.Format != "pe" || right.Format != "pe" || left.PE == nil || right.PE == nil {
		return false
	}
	if left.Size != right.Size ||
		left.PE.Machine != right.PE.Machine ||
		left.PE.Bits != right.PE.Bits ||
		left.PE.ImageBase != right.PE.ImageBase ||
		left.PE.EntryPointRVA != right.PE.EntryPointRVA ||
		left.PE.Subsystem != right.PE.Subsystem ||
		len(left.PE.Sections) != len(right.PE.Sections) {
		return false
	}
	for index := range left.PE.Sections {
		if left.PE.Sections[index] != right.PE.Sections[index] {
			return false
		}
	}
	return true
}

func sameHookCore(existing Hook, baseline targetidentity.Identity, request PlanRequest, original, patch []byte) bool {
	return samePath(existing.Path, baseline.Path) &&
		existing.Baseline.SHA256 == baseline.SHA256 &&
		existing.SourceRVA == request.SourceRVA &&
		existing.DestinationRVA == request.DestinationRVA &&
		existing.OriginalHex == hex.EncodeToString(original) &&
		existing.PatchHex == hex.EncodeToString(patch)
}

func samePath(left, right string) bool {
	return strings.EqualFold(filepath.Clean(left), filepath.Clean(right))
}

func copyFile(source, target string) (err error) {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, input.Close()) }()
	info, err := input.Stat()
	if err != nil {
		return err
	}
	output, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(output, input); err != nil {
		return errors.Join(err, output.Close())
	}
	return output.Close()
}
