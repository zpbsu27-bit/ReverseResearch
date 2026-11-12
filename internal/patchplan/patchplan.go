package patchplan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"reverseresearch/internal/recordio"
	"reverseresearch/internal/targetidentity"
)

type Status string

const (
	StatusPlanned    Status = "planned"
	StatusApplied    Status = "applied"
	StatusCopied     Status = "copied"
	StatusRolledBack Status = "rolled_back"

	maxPatchBytes           = 1 << 20
	maxPatchPlanRecordBytes = int64(4 << 20)
)

type PatchEdit struct {
	Offset         int64  `json:"offset"`
	ExpectedHex    string `json:"expected_hex"`
	ReplacementHex string `json:"replacement_hex"`
}

type PlanRequest struct {
	Path           string      `json:"path"`
	Offset         int64       `json:"offset"`
	ExpectedHex    string      `json:"expected_hex"`
	ReplacementHex string      `json:"replacement_hex"`
	Description    string      `json:"description,omitempty"`
	Edits          []PatchEdit `json:"edits,omitempty"`
}

type ApplyRequest struct {
	PlanID      string `json:"plan_id"`
	InPlace     bool   `json:"in_place,omitempty"`
	OutputPath  string `json:"output_path,omitempty"`
	OperationID string `json:"operation_id,omitempty"`
}

type Plan struct {
	ID                    string      `json:"id"`
	Path                  string      `json:"path"`
	Offset                int64       `json:"offset"`
	ExpectedHex           string      `json:"expected_hex"`
	ReplacementHex        string      `json:"replacement_hex"`
	Edits                 []PatchEdit `json:"edits,omitempty"`
	Description           string      `json:"description,omitempty"`
	SourceSHA256          string      `json:"source_sha256"`
	SourceSize            int64       `json:"source_size"`
	ExpectedAppliedSHA256 string      `json:"expected_applied_sha256,omitempty"`
	Digest                string      `json:"digest,omitempty"`
	Status                Status      `json:"status"`
	Mode                  string      `json:"mode,omitempty"`
	OutputPath            string      `json:"output_path,omitempty"`
	AppliedSHA256         string      `json:"applied_sha256,omitempty"`
	CreatedUTC            string      `json:"created_utc"`
	AppliedUTC            string      `json:"applied_utc,omitempty"`
	RolledBackUTC         string      `json:"rolled_back_utc,omitempty"`
}

type DryRunResult struct {
	PlanID         string      `json:"plan_id"`
	Ready          bool        `json:"ready"`
	Path           string      `json:"path"`
	CurrentSHA256  string      `json:"current_sha256"`
	Offset         int64       `json:"offset"`
	ByteCount      int         `json:"byte_count"`
	EditCount      int         `json:"edit_count,omitempty"`
	TotalByteCount int         `json:"total_byte_count,omitempty"`
	Edits          []PatchEdit `json:"edits,omitempty"`
}

type VerifyResult struct {
	PlanID        string `json:"plan_id"`
	Valid         bool   `json:"valid"`
	Status        Status `json:"status"`
	Path          string `json:"path"`
	CurrentSHA256 string `json:"current_sha256"`
}

type Manager struct {
	root        string
	afterEffect func(string) error
}

func New(root string) (*Manager, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("patch state root is required")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve patch state root: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(absolute, "plans"), 0o700); err != nil {
		return nil, fmt.Errorf("create patch state root: %w", err)
	}
	return &Manager{root: absolute}, nil
}

func (m *Manager) Plan(request PlanRequest) (Plan, error) {

	if len(request.Edits) > 0 {
		return m.planCompositeLocked(request)
	}
	if request.Offset < 0 {
		return Plan{}, errors.New("patch offset must be non-negative")
	}
	expected, err := decodePatchHex(request.ExpectedHex)
	if err != nil {
		return Plan{}, fmt.Errorf("expected_hex: %w", err)
	}
	replacement, err := decodePatchHex(request.ReplacementHex)
	if err != nil {
		return Plan{}, fmt.Errorf("replacement_hex: %w", err)
	}
	if len(expected) == 0 {
		return Plan{}, errors.New("patch byte sequence must not be empty")
	}
	if len(expected) != len(replacement) {
		return Plan{}, errors.New("expected and replacement byte sequences must have the same length")
	}
	if len(expected) > maxPatchBytes {
		return Plan{}, fmt.Errorf("patch byte sequence exceeds %d bytes", maxPatchBytes)
	}
	if bytes.Equal(expected, replacement) {
		return Plan{}, errors.New("replacement bytes are identical to expected bytes")
	}

	identity, err := targetidentity.Inspect(request.Path)
	if err != nil {
		return Plan{}, err
	}
	if request.Offset > identity.Size-int64(len(expected)) {
		return Plan{}, errors.New("patch range exceeds target file size")
	}
	current, err := readRegion(identity.Path, request.Offset, len(expected))
	if err != nil {
		return Plan{}, err
	}
	if !bytes.Equal(current, expected) {
		return Plan{}, fmt.Errorf("expected bytes mismatch at offset 0x%x: found %s", request.Offset, strings.ToUpper(hex.EncodeToString(current)))
	}

	normalizedExpected := strings.ToUpper(hex.EncodeToString(expected))
	normalizedReplacement := strings.ToUpper(hex.EncodeToString(replacement))
	idHash := sha256.Sum256([]byte(strings.Join([]string{
		identity.Path,
		identity.SHA256,
		strconv.FormatInt(request.Offset, 10),
		normalizedExpected,
		normalizedReplacement,
	}, "\x00")))
	sourceHash, expectedAppliedHash, sourceSize, err := computePatchedHashes(identity.Path, request.Offset, replacement)
	if err != nil {
		return Plan{}, err
	}
	if sourceHash != identity.SHA256 || sourceSize != identity.Size {
		return Plan{}, errors.New("target changed while creating patch plan")
	}
	plan := Plan{
		ID:                    hex.EncodeToString(idHash[:16]),
		Path:                  identity.Path,
		Offset:                request.Offset,
		ExpectedHex:           normalizedExpected,
		ReplacementHex:        normalizedReplacement,
		Description:           strings.TrimSpace(request.Description),
		SourceSHA256:          sourceHash,
		SourceSize:            sourceSize,
		ExpectedAppliedSHA256: expectedAppliedHash,
		Status:                StatusPlanned,
		CreatedUTC:            time.Now().UTC().Format(time.RFC3339Nano),
	}
	plan.Digest = planDigest(plan)
	release, err := m.lockPlan(plan.ID)
	if err != nil {
		return Plan{}, err
	}
	return withRelease(release, func() (Plan, error) {
		if existing, err := m.load(plan.ID); err == nil {
			if err := ensurePlanPostcondition(&existing); err != nil {
				return Plan{}, err
			}
			if sameCore(existing, plan) {
				if err := m.save(existing); err != nil {
					return Plan{}, err
				}
				return existing, nil
			}
			return Plan{}, errors.New("patch plan ID collision")
		} else if !errors.Is(err, os.ErrNotExist) {
			return Plan{}, err
		}
		if err := m.save(plan); err != nil {
			return Plan{}, err
		}
		return plan, nil
	})
}

func (m *Manager) Get(planID string) (Plan, error) {
	planID = validatePlanID(planID)
	if planID == "" {
		return Plan{}, errors.New("valid plan_id is required")
	}
	release, err := m.lockPlan(planID)
	if err != nil {
		return Plan{}, err
	}
	return withRelease(release, func() (Plan, error) {
		plan, err := m.load(planID)
		if err != nil {
			return Plan{}, err
		}
		if err := ensurePlanPostcondition(&plan); err != nil {
			return Plan{}, err
		}
		return plan, nil
	})
}

func (m *Manager) DryRun(planID string) (DryRunResult, error) {
	planID = validatePlanID(planID)
	if planID == "" {
		return DryRunResult{}, errors.New("valid plan_id is required")
	}
	release, err := m.lockPlan(planID)
	if err != nil {
		return DryRunResult{}, err
	}
	return withRelease(release, func() (DryRunResult, error) {
		plan, err := m.load(planID)
		if err != nil {
			return DryRunResult{}, err
		}
		if err := ensurePlanPostcondition(&plan); err != nil {
			return DryRunResult{}, err
		}
		return validateSource(plan)
	})
}

func (m *Manager) Verify(planID string) (VerifyResult, error) {
	planID = validatePlanID(planID)
	if planID == "" {
		return VerifyResult{}, errors.New("valid plan_id is required")
	}
	release, err := m.lockPlan(planID)
	if err != nil {
		return VerifyResult{}, err
	}
	return withRelease(release, func() (VerifyResult, error) {
		plan, err := m.load(planID)
		if err != nil {
			return VerifyResult{}, err
		}
		if err := ensurePlanPostcondition(&plan); err != nil {
			return VerifyResult{}, err
		}
		switch plan.Status {
		case StatusPlanned:
			dry, err := validateSource(plan)
			if err != nil {
				return VerifyResult{}, err
			}
			return VerifyResult{PlanID: plan.ID, Valid: true, Status: plan.Status, Path: plan.Path, CurrentSHA256: dry.CurrentSHA256}, nil
		case StatusApplied:
			return verifyPatched(plan, plan.Path, plan.ExpectedAppliedSHA256)
		case StatusCopied:
			return verifyPatched(plan, plan.OutputPath, plan.ExpectedAppliedSHA256)
		case StatusRolledBack:
			dry, err := validateSource(plan)
			if err != nil {
				return VerifyResult{}, err
			}
			return VerifyResult{PlanID: plan.ID, Valid: true, Status: plan.Status, Path: plan.Path, CurrentSHA256: dry.CurrentSHA256}, nil
		default:
			return VerifyResult{}, fmt.Errorf("unknown patch plan status %q", plan.Status)
		}
	})
}

func (m *Manager) Rollback(planID string) (Plan, error) {
	return m.RollbackOperation(RollbackRequest{PlanID: planID})
}

func validateSource(plan Plan) (DryRunResult, error) {
	if len(plan.Edits) > 0 {
		return validateCompositeSource(plan)
	}
	identity, err := targetidentity.Inspect(plan.Path)
	if err != nil {
		return DryRunResult{}, err
	}
	if identity.SHA256 != plan.SourceSHA256 || identity.Size != plan.SourceSize {
		return DryRunResult{}, errors.New("target identity changed since plan creation")
	}
	expected, err := hex.DecodeString(plan.ExpectedHex)
	if err != nil || len(expected) == 0 {
		return DryRunResult{}, errors.New("invalid expected bytes in patch plan")
	}
	return DryRunResult{
		PlanID:        plan.ID,
		Ready:         true,
		Path:          plan.Path,
		CurrentSHA256: identity.SHA256,
		Offset:        plan.Offset,
		ByteCount:     len(expected),
	}, nil
}

func patchInPlace(plan Plan, replacement []byte) (string, error) {
	if len(plan.Edits) > 0 {
		return patchCompositeInPlace(plan)
	}
	expected, _ := hex.DecodeString(plan.ExpectedHex)
	file, err := os.OpenFile(plan.Path, os.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf("open target for patch: %w", err)
	}
	defer file.Close()

	currentHash, err := hashOpenFile(file)
	if err != nil {
		return "", err
	}
	if currentHash != plan.SourceSHA256 {
		return "", errors.New("target identity changed before patch write")
	}
	current := make([]byte, len(expected))
	if _, err := file.ReadAt(current, plan.Offset); err != nil {
		return "", fmt.Errorf("read guarded patch region: %w", err)
	}
	if !bytes.Equal(current, expected) {
		return "", errors.New("expected bytes changed before patch write")
	}
	if _, err := file.WriteAt(replacement, plan.Offset); err != nil {
		return "", fmt.Errorf("write patch bytes: %w", err)
	}
	if err := file.Sync(); err != nil {
		return "", fmt.Errorf("sync patch: %w", err)
	}
	appliedHash, err := hashOpenFile(file)
	if err != nil {
		return "", err
	}
	after := make([]byte, len(replacement))
	if _, err := file.ReadAt(after, plan.Offset); err != nil || !bytes.Equal(after, replacement) {
		restoreErr := restoreSingleEdit(file, plan.Offset, expected)
		if err != nil {
			return "", errors.Join(fmt.Errorf("verify patch read: %w", err), restoreErr)
		}
		if restoreErr != nil {
			return "", errors.Join(errors.New("patch byte verification failed; original-byte recovery failed"), restoreErr)
		}
		return "", errors.New("patch byte verification failed; original bytes were restored")
	}
	return appliedHash, nil
}

// restoreSingleEdit is the compensation step for a failed verification. A
// "restored" conclusion is only allowed after the bytes actually read back,
// because a full disk or failing device can accept WriteAt and still lose data.
func restoreSingleEdit(file *os.File, offset int64, value []byte) error {
	if _, err := file.WriteAt(value, offset); err != nil {
		return fmt.Errorf("restore bytes at 0x%x: %w", offset, err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync restored bytes at 0x%x: %w", offset, err)
	}
	confirm := make([]byte, len(value))
	if _, err := file.ReadAt(confirm, offset); err != nil {
		return fmt.Errorf("verify restored bytes at 0x%x: %w", offset, err)
	}
	if !bytes.Equal(confirm, value) {
		return fmt.Errorf("recovery postcondition failed at 0x%x: restored bytes do not read back", offset)
	}
	return nil
}

func patchCopy(plan Plan, output string, replacement []byte) (result string, err error) {
	if len(plan.Edits) > 0 {
		return patchCompositeCopy(plan, output)
	}
	if _, err := os.Stat(output); err == nil {
		return "", errors.New("output_path already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect output path: %w", err)
	}
	source, err := os.Open(plan.Path)
	if err != nil {
		return "", fmt.Errorf("open source for copy patch: %w", err)
	}
	defer func() { err = errors.Join(err, source.Close()) }()
	sourceHash, err := hashOpenFile(source)
	if err != nil {
		return "", err
	}
	if sourceHash != plan.SourceSHA256 {
		return "", errors.New("source identity changed before copy patch")
	}
	expected, _ := hex.DecodeString(plan.ExpectedHex)
	current := make([]byte, len(expected))
	if _, err := source.ReadAt(current, plan.Offset); err != nil {
		return "", fmt.Errorf("read guarded source region: %w", err)
	}
	if !bytes.Equal(current, expected) {
		return "", errors.New("expected source bytes changed before copy patch")
	}
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return "", fmt.Errorf("rewind source: %w", err)
	}

	info, err := source.Stat()
	if err != nil {
		return "", fmt.Errorf("stat source: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
		return "", fmt.Errorf("create output directory: %w", err)
	}
	temp, err := os.CreateTemp(filepath.Dir(output), ".rrpatch-*")
	if err != nil {
		return "", fmt.Errorf("create patch output temp: %w", err)
	}
	tempName := temp.Name()
	keep := false
	tempClosed := false
	defer func() {
		if !tempClosed {
			err = errors.Join(err, temp.Close())
		}
		if !keep {
			if removeErr := os.Remove(tempName); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				err = errors.Join(err, removeErr)
			}
		}
	}()
	if _, err := io.Copy(temp, source); err != nil {
		return "", fmt.Errorf("copy patch source: %w", err)
	}
	if _, err := temp.WriteAt(replacement, plan.Offset); err != nil {
		return "", fmt.Errorf("write patch output: %w", err)
	}
	if err := temp.Chmod(info.Mode().Perm()); err != nil {
		return "", fmt.Errorf("preserve output permissions: %w", err)
	}
	if err := temp.Sync(); err != nil {
		return "", fmt.Errorf("sync patch output: %w", err)
	}
	hash, err := hashOpenFile(temp)
	if err != nil {
		return "", err
	}
	if err := temp.Close(); err != nil {
		return "", fmt.Errorf("close patch output temp: %w", err)
	}
	tempClosed = true
	if err := os.Rename(tempName, output); err != nil {
		return "", fmt.Errorf("publish patch output: %w", err)
	}
	keep = true
	return hash, nil
}

func verifyPatched(plan Plan, path, expectedHash string) (VerifyResult, error) {
	identity, err := targetidentity.Inspect(path)
	if err != nil {
		return VerifyResult{}, err
	}
	if identity.SHA256 != expectedHash {
		return VerifyResult{}, errors.New("patched target identity no longer matches the recorded applied hash")
	}
	return VerifyResult{
		PlanID:        plan.ID,
		Valid:         true,
		Status:        plan.Status,
		Path:          path,
		CurrentSHA256: identity.SHA256,
	}, nil
}

func readRegion(path string, offset int64, size int) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open target region: %w", err)
	}
	defer file.Close()
	buffer := make([]byte, size)
	if _, err := file.ReadAt(buffer, offset); err != nil {
		return nil, fmt.Errorf("read target region: %w", err)
	}
	return buffer, nil
}

func hashOpenFile(file *os.File) (string, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", fmt.Errorf("rewind file for hash: %w", err)
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("hash file: %w", err)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func decodePatchHex(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errors.New("hex bytes are required")
	}
	replacer := strings.NewReplacer(" ", "", "\t", "", "\r", "", "\n", "", "_", "", ",", "", "0x", "", "0X", "")
	value = replacer.Replace(value)
	if len(value)%2 != 0 {
		return nil, errors.New("hex byte string must contain complete bytes")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, errors.New("invalid hex byte string")
	}
	return decoded, nil
}

func resolveOutput(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("output_path is required unless in_place=true")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve output path: %w", err)
	}
	return filepath.Clean(absolute), nil
}

func samePath(left, right string) bool {
	leftAbs, _ := filepath.Abs(left)
	rightAbs, _ := filepath.Abs(right)
	return strings.EqualFold(filepath.Clean(leftAbs), filepath.Clean(rightAbs))
}

func validatePlanID(id string) string {
	id = strings.TrimSpace(id)
	if len(id) != 32 {
		return ""
	}
	if _, err := hex.DecodeString(id); err != nil {
		return ""
	}
	return strings.ToLower(id)
}

func (m *Manager) planPath(id string) string {
	return filepath.Join(m.root, "plans", id+".json")
}

func (m *Manager) load(id string) (Plan, error) {
	if id == "" {
		return Plan{}, errors.New("valid plan_id is required")
	}
	body, err := recordio.ReadFileLimit(m.planPath(id), maxPatchPlanRecordBytes)
	if err != nil {
		return Plan{}, err
	}
	var plan Plan
	if err := json.Unmarshal(body, &plan); err != nil {
		return Plan{}, fmt.Errorf("decode patch plan: %w", err)
	}
	if plan.ID != id {
		return Plan{}, errors.New("patch plan identity mismatch")
	}
	if plan.Digest != "" && !strings.EqualFold(plan.Digest, planDigest(plan)) {
		return Plan{}, errors.New("patch plan digest mismatch")
	}
	return plan, nil
}

func (m *Manager) save(plan Plan) error {
	body, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if int64(len(body)) > maxPatchPlanRecordBytes {
		return fmt.Errorf("patch plan exceeds durable size limit: %d > %d", len(body), maxPatchPlanRecordBytes)
	}
	return recordio.WriteFile(m.planPath(plan.ID), body, 0o600)
}

func sameCore(left, right Plan) bool {
	return left.ID == right.ID &&
		left.Path == right.Path &&
		left.Offset == right.Offset &&
		left.ExpectedHex == right.ExpectedHex &&
		left.ReplacementHex == right.ReplacementHex &&
		patchEditsEqual(left.Edits, right.Edits) &&
		left.SourceSHA256 == right.SourceSHA256 &&
		left.SourceSize == right.SourceSize &&
		left.ExpectedAppliedSHA256 == right.ExpectedAppliedSHA256 &&
		left.Digest == right.Digest
}
