package patchplan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"reverseresearch/internal/recordio"
	"reverseresearch/internal/targetidentity"
)

const (
	operationPrepared             = "prepared"
	operationCompleted            = "completed"
	maxPatchOperationReceiptBytes = int64(256 << 10)
)

var operationIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$`)

// ErrPatchOutcomeUncertain marks the states where the target file matches
// neither the planned source nor the planned postcondition. Callers must treat
// the target as possibly modified and inspect it instead of replaying the patch.
var ErrPatchOutcomeUncertain = errors.New("patch outcome is uncertain")

type RollbackRequest struct {
	PlanID      string `json:"plan_id"`
	OperationID string `json:"operation_id,omitempty"`
}

type operationReceipt struct {
	OperationID   string `json:"operation_id"`
	Kind          string `json:"kind"`
	PlanID        string `json:"plan_id"`
	PlanDigest    string `json:"plan_digest"`
	RequestDigest string `json:"request_digest"`
	Mode          string `json:"mode,omitempty"`
	OutputPath    string `json:"output_path,omitempty"`
	Status        string `json:"status"`
	ResultStatus  Status `json:"result_status,omitempty"`
	ResultSHA256  string `json:"result_sha256,omitempty"`
	CreatedUTC    string `json:"created_utc"`
	CompletedUTC  string `json:"completed_utc,omitempty"`
}

func (m *Manager) lockPlan(planID string) (func() error, error) {
	return recordio.Acquire(filepath.Join(m.root, "plans", "."+planID+".lock"), 10*time.Second)
}

func (m *Manager) lockOperation(operationID string) (func() error, error) {
	key := sha256.Sum256([]byte(operationID))
	return recordio.Acquire(filepath.Join(m.root, "operations", "."+hex.EncodeToString(key[:])+".lock"), 10*time.Second)
}

// lockTarget serializes every in-place mutation of one target file. Plan and
// operation locks are content-scoped, so two different plans for the same file
// would otherwise patch and re-hash it concurrently and each one would observe
// the other's bytes as an unexplained postcondition failure.
// Lock order is always plan -> operation -> target.
func (m *Manager) lockTarget(path string) (func() error, error) {
	key := sha256.Sum256([]byte(strings.ToLower(filepath.Clean(path))))
	return recordio.Acquire(filepath.Join(m.root, "targets", "."+hex.EncodeToString(key[:])+".lock"), 10*time.Second)
}

func withRelease[T any](release func() error, fn func() (T, error)) (result T, err error) {
	defer func() {
		err = errors.Join(err, release())
	}()
	return fn()
}

func normalizeOperationID(explicit, fallbackSeed string) (string, error) {
	value := strings.TrimSpace(explicit)
	if value == "" {
		sum := sha256.Sum256([]byte(fallbackSeed))
		value = "auto-" + hex.EncodeToString(sum[:16])
	}
	if !operationIDPattern.MatchString(value) {
		return "", errors.New("operation_id must match [A-Za-z0-9][A-Za-z0-9._:-]{0,159}")
	}
	return value, nil
}

func applyRequestDigest(plan Plan, mode, output string) string {
	body := strings.Join([]string{
		"apply",
		plan.ID,
		plan.Digest,
		mode,
		output,
		plan.RolledBackUTC,
	}, "\x00")
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])
}

func rollbackRequestDigest(plan Plan) string {
	body := strings.Join([]string{
		"rollback",
		plan.ID,
		plan.Digest,
		plan.AppliedSHA256,
		plan.AppliedUTC,
	}, "\x00")
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])
}

func planDigest(plan Plan) string {
	payload := struct {
		ID                    string      `json:"id"`
		Path                  string      `json:"path"`
		Offset                int64       `json:"offset"`
		ExpectedHex           string      `json:"expected_hex"`
		ReplacementHex        string      `json:"replacement_hex"`
		Edits                 []PatchEdit `json:"edits,omitempty"`
		SourceSHA256          string      `json:"source_sha256"`
		SourceSize            int64       `json:"source_size"`
		ExpectedAppliedSHA256 string      `json:"expected_applied_sha256"`
	}{
		ID:                    plan.ID,
		Path:                  plan.Path,
		Offset:                plan.Offset,
		ExpectedHex:           plan.ExpectedHex,
		ReplacementHex:        plan.ReplacementHex,
		Edits:                 plan.Edits,
		SourceSHA256:          plan.SourceSHA256,
		SourceSize:            plan.SourceSize,
		ExpectedAppliedSHA256: plan.ExpectedAppliedSHA256,
	}
	body, _ := json.Marshal(payload)
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func ensurePlanPostcondition(plan *Plan) error {
	legacy := plan.Digest == ""
	if plan.ExpectedAppliedSHA256 == "" {
		switch plan.Status {
		case StatusApplied, StatusCopied:
			if len(plan.AppliedSHA256) != 64 {
				return errors.New("legacy applied patch plan lacks a valid applied hash")
			}
			plan.ExpectedAppliedSHA256 = strings.ToLower(plan.AppliedSHA256)
		case StatusPlanned, StatusRolledBack:
			var sourceHash, appliedHash string
			var size int64
			var err error
			if len(plan.Edits) > 0 {
				decoded, _, decodeErr := decodedPlanEdits(*plan)
				if decodeErr != nil {
					return decodeErr
				}
				sourceHash, appliedHash, size, err = computeCompositeHashes(plan.Path, decoded)
			} else {
				replacement, decodeErr := hex.DecodeString(plan.ReplacementHex)
				if decodeErr != nil {
					return errors.New("invalid replacement bytes in persisted plan")
				}
				sourceHash, appliedHash, size, err = computePatchedHashes(plan.Path, plan.Offset, replacement)
			}
			if err != nil {
				return err
			}
			if sourceHash != plan.SourceSHA256 || size != plan.SourceSize {
				return errors.New("target identity changed while upgrading legacy patch plan")
			}
			plan.ExpectedAppliedSHA256 = appliedHash
		default:
			return fmt.Errorf("unknown patch plan status %q", plan.Status)
		}
	}
	expectedDigest := planDigest(*plan)
	if legacy {
		if err := validateLegacyPlanState(*plan); err != nil {
			return fmt.Errorf("refuse legacy patch plan upgrade: %w", err)
		}
		plan.Digest = expectedDigest
	} else if !strings.EqualFold(plan.Digest, expectedDigest) {
		return errors.New("patch plan digest mismatch")
	}
	return nil
}

func validateLegacyPlanState(plan Plan) error {
	switch plan.Status {
	case StatusPlanned, StatusRolledBack:
		_, err := validateSource(plan)
		return err
	case StatusApplied:
		if plan.Mode != "in_place" {
			return errors.New("legacy applied plan has invalid mode")
		}
		_, err := verifyPatched(plan, plan.Path, plan.ExpectedAppliedSHA256)
		return err
	case StatusCopied:
		if plan.Mode != "copy" || strings.TrimSpace(plan.OutputPath) == "" {
			return errors.New("legacy copied plan has invalid output")
		}
		_, err := verifyPatched(plan, plan.OutputPath, plan.ExpectedAppliedSHA256)
		return err
	default:
		return fmt.Errorf("unknown patch plan status %q", plan.Status)
	}
}

func computePatchedHashes(path string, offset int64, replacement []byte) (sourceHash, appliedHash string, size int64, err error) {
	file, err := os.Open(path)
	if err != nil {
		return "", "", 0, fmt.Errorf("open target for postcondition hash: %w", err)
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		return "", "", 0, err
	}
	if !before.Mode().IsRegular() {
		return "", "", 0, errors.New("patch target must be a regular file")
	}
	if offset < 0 || offset > before.Size()-int64(len(replacement)) {
		return "", "", 0, errors.New("patch range exceeds target file size")
	}

	sourceHash, err = hashOpenFile(file)
	if err != nil {
		return "", "", 0, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", "", 0, fmt.Errorf("rewind target for postcondition hash: %w", err)
	}
	applied := sha256.New()
	if _, err := io.CopyN(applied, file, offset); err != nil {
		return "", "", 0, fmt.Errorf("hash target prefix: %w", err)
	}
	if _, err := applied.Write(replacement); err != nil {
		return "", "", 0, err
	}
	if _, err := file.Seek(int64(len(replacement)), io.SeekCurrent); err != nil {
		return "", "", 0, fmt.Errorf("skip replaced target bytes: %w", err)
	}
	if _, err := io.Copy(applied, file); err != nil {
		return "", "", 0, fmt.Errorf("hash target suffix: %w", err)
	}
	after, err := file.Stat()
	if err != nil {
		return "", "", 0, err
	}
	current, err := os.Stat(path)
	if err != nil {
		return "", "", 0, fmt.Errorf("restat target after postcondition hash: %w", err)
	}
	if !os.SameFile(before, after) || !os.SameFile(after, current) ||
		before.Size() != after.Size() || after.Size() != current.Size() ||
		!before.ModTime().Equal(after.ModTime()) || !after.ModTime().Equal(current.ModTime()) {
		return "", "", 0, errors.New("target changed while computing patch postcondition")
	}
	return sourceHash, hex.EncodeToString(applied.Sum(nil)), after.Size(), nil
}

func (m *Manager) operationPath(operationID string) string {
	sum := sha256.Sum256([]byte(operationID))
	return filepath.Join(m.root, "operations", hex.EncodeToString(sum[:])+".json")
}

func (m *Manager) loadOperation(operationID string) (operationReceipt, error) {
	body, err := recordio.ReadFileLimit(m.operationPath(operationID), maxPatchOperationReceiptBytes)
	if err != nil {
		return operationReceipt{}, err
	}
	var receipt operationReceipt
	if err := json.Unmarshal(body, &receipt); err != nil {
		return operationReceipt{}, fmt.Errorf("decode patch operation receipt: %w", err)
	}
	if receipt.OperationID != operationID {
		return operationReceipt{}, errors.New("patch operation identity mismatch")
	}
	return receipt, nil
}

func (m *Manager) saveOperation(receipt operationReceipt) error {
	body, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if int64(len(body)) > maxPatchOperationReceiptBytes {
		return fmt.Errorf("patch operation receipt exceeds durable size limit: %d > %d", len(body), maxPatchOperationReceiptBytes)
	}
	return recordio.WriteFile(m.operationPath(receipt.OperationID), body, 0o600)
}

func (m *Manager) prepareOperation(receipt operationReceipt) (operationReceipt, bool, error) {
	existing, err := m.loadOperation(receipt.OperationID)
	if err == nil {
		if existing.Kind != receipt.Kind ||
			existing.PlanID != receipt.PlanID ||
			existing.PlanDigest != receipt.PlanDigest ||
			existing.RequestDigest != receipt.RequestDigest ||
			existing.Mode != receipt.Mode ||
			existing.OutputPath != receipt.OutputPath {
			return operationReceipt{}, true, errors.New("operation_id was already used for a different patch request")
		}
		return existing, true, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return operationReceipt{}, false, err
	}
	if err := m.saveOperation(receipt); err != nil {
		return operationReceipt{}, false, err
	}
	return receipt, false, nil
}

func (m *Manager) completeOperation(receipt operationReceipt, plan Plan) error {
	receipt.Status = operationCompleted
	receipt.ResultStatus = plan.Status
	receipt.ResultSHA256 = plan.AppliedSHA256
	if plan.Status == StatusRolledBack {
		receipt.ResultSHA256 = plan.SourceSHA256
	}
	receipt.CompletedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	return m.saveOperation(receipt)
}

func (m *Manager) Apply(request ApplyRequest) (Plan, error) {

	planID := validatePlanID(request.PlanID)
	if planID == "" {
		return Plan{}, errors.New("valid plan_id is required")
	}
	release, err := m.lockPlan(planID)
	if err != nil {
		return Plan{}, err
	}
	return withRelease(release, func() (Plan, error) {
		return m.applyLocked(request, planID)
	})
}

func (m *Manager) applyLocked(request ApplyRequest, planID string) (Plan, error) {
	plan, err := m.load(planID)
	if err != nil {
		return Plan{}, err
	}
	if err := ensurePlanPostcondition(&plan); err != nil {
		return Plan{}, err
	}

	mode := "copy"
	output := ""
	if request.InPlace {
		mode = "in_place"
		if strings.TrimSpace(request.OutputPath) != "" {
			return Plan{}, errors.New("output_path must be empty when in_place is true")
		}
	} else {
		output, err = resolveOutput(request.OutputPath)
		if err != nil {
			return Plan{}, err
		}
		if samePath(output, plan.Path) {
			return Plan{}, errors.New("output_path resolves to the source; use in_place=true for source modification")
		}
	}

	requestDigest := applyRequestDigest(plan, mode, output)
	operationID, err := normalizeOperationID(request.OperationID, requestDigest)
	if err != nil {
		return Plan{}, err
	}
	opRelease, err := m.lockOperation(operationID)
	if err != nil {
		return Plan{}, err
	}
	return withRelease(opRelease, func() (result Plan, resultErr error) {
		// One file-scoped lock per transaction: in-place work serializes on the
		// target, copy work on the output path, so two transactions can never
		// write the same file concurrently.
		guardedPath := plan.Path
		if mode != "in_place" {
			guardedPath = output
		}
		targetRelease, lockErr := m.lockTarget(guardedPath)
		if lockErr != nil {
			return Plan{}, lockErr
		}
		defer func() { resultErr = errors.Join(resultErr, targetRelease()) }()

		now := time.Now().UTC().Format(time.RFC3339Nano)
		receipt, existed, err := m.prepareOperation(operationReceipt{
			OperationID:   operationID,
			Kind:          "apply",
			PlanID:        plan.ID,
			PlanDigest:    plan.Digest,
			RequestDigest: requestDigest,
			Mode:          mode,
			OutputPath:    output,
			Status:        operationPrepared,
			CreatedUTC:    now,
		})
		if err != nil {
			return Plan{}, err
		}

		if existed && receipt.Status == operationCompleted {
			if err := verifyCompletedApply(plan, mode, output); err != nil {
				return Plan{}, fmt.Errorf("completed operation postcondition no longer holds: %w", err)
			}
			return plan, nil
		}

		state, err := classifyApplyState(plan, mode, output)
		if err != nil {
			return Plan{}, err
		}
		switch state {
		case "applied":
			if plan.Status != StatusApplied && plan.Status != StatusCopied {
				plan.Status = StatusCopied
				plan.OutputPath = output
				if mode == "in_place" {
					plan.Status = StatusApplied
					plan.OutputPath = ""
				}
				plan.Mode = mode
				plan.AppliedSHA256 = plan.ExpectedAppliedSHA256
				if plan.AppliedUTC == "" {
					plan.AppliedUTC = now
				}
				plan.RolledBackUTC = ""
				if err := m.save(plan); err != nil {
					return Plan{}, err
				}
			}
			if err := m.completeOperation(receipt, plan); err != nil {
				return Plan{}, err
			}
			return plan, nil
		case "source":
			if plan.Status != StatusPlanned && plan.Status != StatusRolledBack {
				return Plan{}, fmt.Errorf("patch plan status %q disagrees with current source state", plan.Status)
			}
		default:
			return Plan{}, errors.Join(errors.New("patch operation outcome is unknown; target does not match source or planned postcondition"), ErrPatchOutcomeUncertain)
		}

		replacement, _ := hex.DecodeString(plan.ReplacementHex)
		var appliedHash string
		if mode == "in_place" {
			appliedHash, err = patchInPlace(plan, replacement)
		} else {
			appliedHash, err = patchCopy(plan, output, replacement)
		}
		if err != nil {
			return Plan{}, err
		}
		if !strings.EqualFold(appliedHash, plan.ExpectedAppliedSHA256) {
			return Plan{}, fmt.Errorf(
				"target now hashes to %s but the plan expects %s; the patch bytes were written, "+
					"other bytes changed during apply, and the plan was deliberately not recorded as applied: %w",
				appliedHash, plan.ExpectedAppliedSHA256, ErrPatchOutcomeUncertain)
		}
		if m.afterEffect != nil {
			if err := m.afterEffect("apply"); err != nil {
				return Plan{}, err
			}
		}

		plan.Status = StatusCopied
		plan.Mode = mode
		plan.OutputPath = output
		if mode == "in_place" {
			plan.Status = StatusApplied
			plan.OutputPath = ""
		}
		plan.AppliedSHA256 = appliedHash
		plan.AppliedUTC = now
		plan.RolledBackUTC = ""
		if err := m.save(plan); err != nil {
			return Plan{}, err
		}
		if err := m.completeOperation(receipt, plan); err != nil {
			return Plan{}, err
		}
		return plan, nil
	})
}

func verifyCompletedApply(plan Plan, mode, output string) error {
	switch mode {
	case "in_place":
		if plan.Status != StatusApplied || plan.Mode != "in_place" {
			return errors.New("plan is not recorded as an applied in-place patch")
		}
		_, err := verifyPatched(plan, plan.Path, plan.ExpectedAppliedSHA256)
		return err
	case "copy":
		if plan.Status != StatusCopied || plan.Mode != "copy" || !samePath(plan.OutputPath, output) {
			return errors.New("plan is not recorded as the requested copy patch")
		}
		_, err := verifyPatched(plan, output, plan.ExpectedAppliedSHA256)
		return err
	default:
		return errors.New("unknown patch mode")
	}
}

func classifyApplyState(plan Plan, mode, output string) (string, error) {
	if mode == "copy" {
		if _, err := os.Stat(output); err == nil {
			if _, verifyErr := verifyPatched(plan, output, plan.ExpectedAppliedSHA256); verifyErr == nil {
				return "applied", nil
			}
			return "other", nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("inspect patch output: %w", err)
		}
		if _, err := validateSource(plan); err == nil {
			return "source", nil
		}
		return "other", nil
	}
	identity, err := targetidentity.Inspect(plan.Path)
	if err != nil {
		return "", err
	}
	if identity.SHA256 == plan.SourceSHA256 {
		return "source", nil
	}
	if identity.SHA256 == plan.ExpectedAppliedSHA256 {
		return "applied", nil
	}
	return "other", nil
}

func bytesEqual(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func (m *Manager) RollbackOperation(request RollbackRequest) (Plan, error) {

	planID := validatePlanID(request.PlanID)
	if planID == "" {
		return Plan{}, errors.New("valid plan_id is required")
	}
	release, err := m.lockPlan(planID)
	if err != nil {
		return Plan{}, err
	}
	return withRelease(release, func() (Plan, error) {
		return m.rollbackLocked(request, planID)
	})
}

func (m *Manager) rollbackLocked(request RollbackRequest, planID string) (Plan, error) {
	plan, err := m.load(planID)
	if err != nil {
		return Plan{}, err
	}
	if err := ensurePlanPostcondition(&plan); err != nil {
		return Plan{}, err
	}
	if plan.Status != StatusApplied && plan.Status != StatusRolledBack {
		return Plan{}, errors.New("rollback is available only for an applied in-place patch")
	}
	if plan.Status == StatusApplied && plan.Mode != "in_place" {
		return Plan{}, errors.New("rollback is available only for an applied in-place patch")
	}

	requestDigest := rollbackRequestDigest(plan)
	operationID, err := normalizeOperationID(request.OperationID, requestDigest)
	if err != nil {
		return Plan{}, err
	}
	opRelease, err := m.lockOperation(operationID)
	if err != nil {
		return Plan{}, err
	}
	return withRelease(opRelease, func() (result Plan, resultErr error) {
		targetRelease, lockErr := m.lockTarget(plan.Path)
		if lockErr != nil {
			return Plan{}, lockErr
		}
		defer func() { resultErr = errors.Join(resultErr, targetRelease()) }()

		now := time.Now().UTC().Format(time.RFC3339Nano)
		receipt, existed, err := m.prepareOperation(operationReceipt{
			OperationID:   operationID,
			Kind:          "rollback",
			PlanID:        plan.ID,
			PlanDigest:    plan.Digest,
			RequestDigest: requestDigest,
			Mode:          "in_place",
			Status:        operationPrepared,
			CreatedUTC:    now,
		})
		if err != nil {
			return Plan{}, err
		}
		if plan.Status == StatusRolledBack {
			if _, err := validateSource(plan); err != nil {
				return Plan{}, errors.New("rolled-back plan no longer matches the original source")
			}
			if receipt.Status != operationCompleted {
				if err := m.completeOperation(receipt, plan); err != nil {
					return Plan{}, err
				}
			}
			return plan, nil
		}
		if existed && receipt.Status == operationCompleted {
			if _, err := validateSource(plan); err != nil {
				return Plan{}, fmt.Errorf("completed rollback postcondition no longer holds: %w", err)
			}
			if plan.Status != StatusRolledBack {
				plan.Status = StatusRolledBack
				if plan.RolledBackUTC == "" {
					plan.RolledBackUTC = now
				}
				if err := m.save(plan); err != nil {
					return Plan{}, err
				}
			}
			return plan, nil
		}

		state, err := classifyInPlaceState(plan)
		if err != nil {
			return Plan{}, err
		}
		switch state {
		case "source":
			plan.Status = StatusRolledBack
			if plan.RolledBackUTC == "" {
				plan.RolledBackUTC = now
			}
			if err := m.save(plan); err != nil {
				return Plan{}, err
			}
			if err := m.completeOperation(receipt, plan); err != nil {
				return Plan{}, err
			}
			return plan, nil
		case "applied":
		default:
			return Plan{}, errors.New("rollback outcome is unknown; target matches neither applied nor original state")
		}

		if err := rollbackInPlaceEffect(plan); err != nil {
			return Plan{}, err
		}
		if m.afterEffect != nil {
			if err := m.afterEffect("rollback"); err != nil {
				return Plan{}, err
			}
		}
		plan.Status = StatusRolledBack
		plan.RolledBackUTC = now
		if err := m.save(plan); err != nil {
			return Plan{}, err
		}
		if err := m.completeOperation(receipt, plan); err != nil {
			return Plan{}, err
		}
		return plan, nil
	})
}

func classifyInPlaceState(plan Plan) (string, error) {
	identity, err := targetidentity.Inspect(plan.Path)
	if err != nil {
		return "", err
	}
	if identity.SHA256 == plan.SourceSHA256 {
		return "source", nil
	}
	if identity.SHA256 == plan.ExpectedAppliedSHA256 {
		return "applied", nil
	}
	return "other", nil
}

func rollbackInPlaceEffect(plan Plan) error {
	if len(plan.Edits) > 0 {
		return rollbackCompositeInPlace(plan)
	}
	expected, _ := hex.DecodeString(plan.ExpectedHex)
	replacement, _ := hex.DecodeString(plan.ReplacementHex)
	file, err := os.OpenFile(plan.Path, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open target for rollback: %w", err)
	}
	defer file.Close()

	currentHash, err := hashOpenFile(file)
	if err != nil {
		return err
	}
	if currentHash != plan.ExpectedAppliedSHA256 {
		return errors.New("target changed after patch application; refusing rollback")
	}
	current := make([]byte, len(replacement))
	if _, err := file.ReadAt(current, plan.Offset); err != nil {
		return fmt.Errorf("read patched region: %w", err)
	}
	if !bytesEqual(current, replacement) {
		return errors.New("replacement bytes no longer match; refusing rollback")
	}
	if _, err := file.WriteAt(expected, plan.Offset); err != nil {
		return fmt.Errorf("restore original bytes: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync rollback: %w", err)
	}
	restoredHash, err := hashOpenFile(file)
	if err != nil {
		return err
	}
	if restoredHash != plan.SourceSHA256 {
		restoreErr := restoreSingleEdit(file, plan.Offset, replacement)
		if restoreErr != nil {
			return errors.Join(errors.New("rollback verification failed; replacement-byte recovery failed"), restoreErr)
		}
		return errors.New("rollback verification failed; replacement bytes were restored")
	}
	return nil
}
