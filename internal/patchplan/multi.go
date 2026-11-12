package patchplan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"reverseresearch/internal/targetidentity"
)

const maxPatchEdits = 4096

type decodedPatchEdit struct {
	Offset      int64
	Expected    []byte
	Replacement []byte
}

func (m *Manager) planCompositeLocked(request PlanRequest) (Plan, error) {
	if strings.TrimSpace(request.ExpectedHex) != "" || strings.TrimSpace(request.ReplacementHex) != "" || request.Offset != 0 {
		return Plan{}, errors.New("edits cannot be combined with offset/expected_hex/replacement_hex")
	}
	canonical, decoded, totalBytes, err := canonicalizePatchEdits(request.Edits)
	if err != nil {
		return Plan{}, err
	}
	identity, err := targetidentity.Inspect(request.Path)
	if err != nil {
		return Plan{}, err
	}
	sourceHash, appliedHash, size, err := computeCompositeHashes(identity.Path, decoded)
	if err != nil {
		return Plan{}, err
	}
	if sourceHash != identity.SHA256 || size != identity.Size {
		return Plan{}, errors.New("target changed while creating composite patch plan")
	}
	editBody, _ := json.Marshal(canonical)
	idHash := sha256.Sum256([]byte(strings.Join([]string{
		identity.Path,
		identity.SHA256,
		string(editBody),
		strconv.Itoa(totalBytes),
	}, "\x00")))
	plan := Plan{
		ID:                    hex.EncodeToString(idHash[:16]),
		Path:                  identity.Path,
		Edits:                 canonical,
		Description:           strings.TrimSpace(request.Description),
		SourceSHA256:          sourceHash,
		SourceSize:            size,
		ExpectedAppliedSHA256: appliedHash,
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

func canonicalizePatchEdits(edits []PatchEdit) ([]PatchEdit, []decodedPatchEdit, int, error) {
	if len(edits) == 0 {
		return nil, nil, 0, errors.New("at least one patch edit is required")
	}
	if len(edits) > maxPatchEdits {
		return nil, nil, 0, fmt.Errorf("patch edit count exceeds %d", maxPatchEdits)
	}
	decoded := make([]decodedPatchEdit, 0, len(edits))
	total := 0
	for i, edit := range edits {
		if edit.Offset < 0 {
			return nil, nil, 0, fmt.Errorf("edit %d offset must be non-negative", i)
		}
		expected, err := decodePatchHex(edit.ExpectedHex)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("edit %d expected_hex: %w", i, err)
		}
		replacement, err := decodePatchHex(edit.ReplacementHex)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("edit %d replacement_hex: %w", i, err)
		}
		if len(expected) != len(replacement) {
			return nil, nil, 0, fmt.Errorf("edit %d expected and replacement byte sequences must have the same length", i)
		}
		if edit.Offset > math.MaxInt64-int64(len(expected)) {
			return nil, nil, 0, fmt.Errorf("edit %d range overflows file offset", i)
		}
		if bytes.Equal(expected, replacement) {
			return nil, nil, 0, fmt.Errorf("edit %d replacement bytes are identical to expected bytes", i)
		}
		total += len(expected)
		if total > maxPatchBytes {
			return nil, nil, 0, fmt.Errorf("combined patch bytes exceed %d bytes", maxPatchBytes)
		}
		decoded = append(decoded, decodedPatchEdit{
			Offset: edit.Offset, Expected: expected, Replacement: replacement,
		})
	}
	sort.Slice(decoded, func(i, j int) bool { return decoded[i].Offset < decoded[j].Offset })
	for i := 1; i < len(decoded); i++ {
		previousEnd := decoded[i-1].Offset + int64(len(decoded[i-1].Expected))
		if decoded[i].Offset < previousEnd {
			return nil, nil, 0, fmt.Errorf(
				"patch edits overlap: edit at 0x%x starts before previous edit ends at 0x%x",
				decoded[i].Offset, previousEnd,
			)
		}
	}
	canonical := make([]PatchEdit, len(decoded))
	for i, edit := range decoded {
		canonical[i] = PatchEdit{
			Offset:         edit.Offset,
			ExpectedHex:    strings.ToUpper(hex.EncodeToString(edit.Expected)),
			ReplacementHex: strings.ToUpper(hex.EncodeToString(edit.Replacement)),
		}
	}
	return canonical, decoded, total, nil
}

func decodedPlanEdits(plan Plan) ([]decodedPatchEdit, int, error) {
	if len(plan.Edits) == 0 {
		expected, err := hex.DecodeString(plan.ExpectedHex)
		if err != nil || len(expected) == 0 {
			return nil, 0, errors.New("invalid expected bytes in patch plan")
		}
		replacement, err := hex.DecodeString(plan.ReplacementHex)
		if err != nil || len(replacement) != len(expected) {
			return nil, 0, errors.New("invalid replacement bytes in patch plan")
		}
		return []decodedPatchEdit{{Offset: plan.Offset, Expected: expected, Replacement: replacement}}, len(expected), nil
	}
	_, decoded, total, err := canonicalizePatchEdits(plan.Edits)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid composite patch plan: %w", err)
	}
	return decoded, total, nil
}

func patchEditsEqual(left, right []PatchEdit) bool {
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

func computeCompositeHashes(path string, edits []decodedPatchEdit) (sourceHash, appliedHash string, size int64, err error) {
	file, err := os.Open(path)
	if err != nil {
		return "", "", 0, fmt.Errorf("open target for composite hash: %w", err)
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		return "", "", 0, err
	}
	if !before.Mode().IsRegular() {
		return "", "", 0, errors.New("patch target must be a regular file")
	}
	if len(edits) == 0 {
		return "", "", 0, errors.New("composite patch has no edits")
	}
	for _, edit := range edits {
		if edit.Offset > before.Size()-int64(len(edit.Expected)) {
			return "", "", 0, fmt.Errorf("patch range at 0x%x exceeds target file size", edit.Offset)
		}
	}

	source := sha256.New()
	applied := sha256.New()
	cursor := int64(0)
	buffer := make([]byte, 64*1024)
	for _, edit := range edits {
		if edit.Offset < cursor {
			return "", "", 0, errors.New("composite patch edits are not sorted and disjoint")
		}
		if err := copyExactToBoth(file, source, applied, edit.Offset-cursor, buffer); err != nil {
			return "", "", 0, err
		}
		current := make([]byte, len(edit.Expected))
		if _, err := io.ReadFull(file, current); err != nil {
			return "", "", 0, fmt.Errorf("read expected bytes at 0x%x: %w", edit.Offset, err)
		}
		if _, err := source.Write(current); err != nil {
			return "", "", 0, err
		}
		if !bytes.Equal(current, edit.Expected) {
			return "", "", 0, fmt.Errorf(
				"expected bytes mismatch at offset 0x%x: found %s",
				edit.Offset, strings.ToUpper(hex.EncodeToString(current)),
			)
		}
		if _, err := applied.Write(edit.Replacement); err != nil {
			return "", "", 0, err
		}
		cursor = edit.Offset + int64(len(edit.Expected))
	}
	if err := copyExactToBoth(file, source, applied, before.Size()-cursor, buffer); err != nil {
		return "", "", 0, err
	}
	after, err := file.Stat()
	if err != nil {
		return "", "", 0, err
	}
	current, err := os.Stat(path)
	if err != nil {
		return "", "", 0, fmt.Errorf("restat target after composite hash: %w", err)
	}
	if !os.SameFile(before, after) || !os.SameFile(after, current) ||
		before.Size() != after.Size() || after.Size() != current.Size() ||
		!before.ModTime().Equal(after.ModTime()) || !after.ModTime().Equal(current.ModTime()) {
		return "", "", 0, errors.New("target changed while computing composite patch postcondition")
	}
	return hex.EncodeToString(source.Sum(nil)), hex.EncodeToString(applied.Sum(nil)), after.Size(), nil
}

func copyExactToBoth(file *os.File, left, right io.Writer, count int64, buffer []byte) error {
	if count < 0 {
		return errors.New("negative composite patch segment")
	}
	writer := io.MultiWriter(left, right)
	for count > 0 {
		next := int64(len(buffer))
		if count < next {
			next = count
		}
		n, err := io.ReadFull(file, buffer[:next])
		if err != nil {
			return fmt.Errorf("read composite patch segment: %w", err)
		}
		if _, err := writer.Write(buffer[:n]); err != nil {
			return err
		}
		count -= int64(n)
	}
	return nil
}

func validateCompositeSource(plan Plan) (DryRunResult, error) {
	decoded, total, err := decodedPlanEdits(plan)
	if err != nil {
		return DryRunResult{}, err
	}
	sourceHash, appliedHash, size, err := computeCompositeHashes(plan.Path, decoded)
	if err != nil {
		return DryRunResult{}, err
	}
	if sourceHash != plan.SourceSHA256 || size != plan.SourceSize {
		return DryRunResult{}, errors.New("target identity changed since plan creation")
	}
	if appliedHash != plan.ExpectedAppliedSHA256 {
		return DryRunResult{}, errors.New("composite patch postcondition no longer matches plan")
	}
	return DryRunResult{
		PlanID: plan.ID, Ready: true, Path: plan.Path, CurrentSHA256: sourceHash,
		Offset: decoded[0].Offset, ByteCount: total,
		EditCount: len(decoded), TotalByteCount: total, Edits: append([]PatchEdit(nil), plan.Edits...),
	}, nil
}

func patchCompositeInPlace(plan Plan) (string, error) {
	decoded, _, err := decodedPlanEdits(plan)
	if err != nil {
		return "", err
	}
	file, err := os.OpenFile(plan.Path, os.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf("open target for composite patch: %w", err)
	}
	defer file.Close()

	currentHash, err := hashOpenFile(file)
	if err != nil {
		return "", err
	}
	if currentHash != plan.SourceSHA256 {
		return "", errors.New("target identity changed before composite patch write")
	}
	if err := verifyOpenFileEdits(file, decoded, false); err != nil {
		return "", err
	}
	for i, edit := range decoded {
		if _, err := file.WriteAt(edit.Replacement, edit.Offset); err != nil {
			restoreErr := restoreOpenFileEdits(file, decoded[:i+1], false)
			return "", errors.Join(fmt.Errorf("write composite patch at 0x%x: %w", edit.Offset, err), restoreErr)
		}
	}
	if err := file.Sync(); err != nil {
		restoreErr := restoreOpenFileEdits(file, decoded, false)
		return "", errors.Join(fmt.Errorf("sync composite patch: %w", err), restoreErr)
	}
	appliedHash, err := hashOpenFile(file)
	if err != nil {
		return "", err
	}
	if appliedHash != plan.ExpectedAppliedSHA256 {
		restoreErr := restoreOpenFileEdits(file, decoded, false)
		return "", errors.Join(errors.New("composite patch hash verification failed"), restoreErr)
	}
	if err := verifyOpenFileEdits(file, decoded, true); err != nil {
		restoreErr := restoreOpenFileEdits(file, decoded, false)
		return "", errors.Join(err, restoreErr)
	}
	return appliedHash, nil
}

func patchCompositeCopy(plan Plan, output string) (result string, err error) {
	if _, err := os.Stat(output); err == nil {
		return "", errors.New("output_path already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect output path: %w", err)
	}
	decoded, _, err := decodedPlanEdits(plan)
	if err != nil {
		return "", err
	}
	source, err := os.Open(plan.Path)
	if err != nil {
		return "", fmt.Errorf("open source for composite copy patch: %w", err)
	}
	defer func() { err = errors.Join(err, source.Close()) }()
	sourceHash, err := hashOpenFile(source)
	if err != nil {
		return "", err
	}
	if sourceHash != plan.SourceSHA256 {
		return "", errors.New("source identity changed before composite copy patch")
	}
	if err := verifyOpenFileEdits(source, decoded, false); err != nil {
		return "", err
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
		return "", fmt.Errorf("create composite patch output temp: %w", err)
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
		return "", fmt.Errorf("copy composite patch source: %w", err)
	}
	for _, edit := range decoded {
		if _, err := temp.WriteAt(edit.Replacement, edit.Offset); err != nil {
			return "", fmt.Errorf("write composite patch output at 0x%x: %w", edit.Offset, err)
		}
	}
	if err := temp.Chmod(info.Mode().Perm()); err != nil {
		return "", fmt.Errorf("preserve output permissions: %w", err)
	}
	if err := temp.Sync(); err != nil {
		return "", fmt.Errorf("sync composite patch output: %w", err)
	}
	hash, err := hashOpenFile(temp)
	if err != nil {
		return "", err
	}
	if hash != plan.ExpectedAppliedSHA256 {
		return "", errors.New("composite patch output hash does not match planned postcondition")
	}
	if err := verifyOpenFileEdits(temp, decoded, true); err != nil {
		return "", err
	}
	if err := temp.Close(); err != nil {
		return "", fmt.Errorf("close composite patch output temp: %w", err)
	}
	tempClosed = true
	if err := os.Rename(tempName, output); err != nil {
		return "", fmt.Errorf("publish composite patch output: %w", err)
	}
	keep = true
	return hash, nil
}

func verifyOpenFileEdits(file *os.File, edits []decodedPatchEdit, replacement bool) error {
	for _, edit := range edits {
		want := edit.Expected
		label := "expected"
		if replacement {
			want = edit.Replacement
			label = "replacement"
		}
		current := make([]byte, len(want))
		if _, err := file.ReadAt(current, edit.Offset); err != nil {
			return fmt.Errorf("read %s bytes at 0x%x: %w", label, edit.Offset, err)
		}
		if !bytes.Equal(current, want) {
			return fmt.Errorf("%s bytes changed at offset 0x%x", label, edit.Offset)
		}
	}
	return nil
}

func restoreOpenFileEdits(file *os.File, edits []decodedPatchEdit, replacement bool) error {
	var result error
	for _, edit := range edits {
		value := edit.Expected
		if replacement {
			value = edit.Replacement
		}
		if _, err := file.WriteAt(value, edit.Offset); err != nil {
			result = errors.Join(result, fmt.Errorf("restore bytes at 0x%x: %w", edit.Offset, err))
		}
	}
	if err := file.Sync(); err != nil {
		result = errors.Join(result, fmt.Errorf("sync restored bytes: %w", err))
	}
	return result
}

func rollbackCompositeInPlace(plan Plan) error {
	decoded, _, err := decodedPlanEdits(plan)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(plan.Path, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open target for composite rollback: %w", err)
	}
	defer file.Close()
	currentHash, err := hashOpenFile(file)
	if err != nil {
		return err
	}
	if currentHash != plan.ExpectedAppliedSHA256 {
		return errors.New("target changed after composite patch application; refusing rollback")
	}
	if err := verifyOpenFileEdits(file, decoded, true); err != nil {
		return err
	}
	for i, edit := range decoded {
		if _, err := file.WriteAt(edit.Expected, edit.Offset); err != nil {
			restoreErr := restoreOpenFileEdits(file, decoded[:i+1], true)
			return errors.Join(fmt.Errorf("restore composite original bytes at 0x%x: %w", edit.Offset, err), restoreErr)
		}
	}
	if err := file.Sync(); err != nil {
		restoreErr := restoreOpenFileEdits(file, decoded, true)
		return errors.Join(fmt.Errorf("sync composite rollback: %w", err), restoreErr)
	}
	restoredHash, err := hashOpenFile(file)
	if err != nil {
		return err
	}
	if restoredHash != plan.SourceSHA256 {
		restoreErr := restoreOpenFileEdits(file, decoded, true)
		return errors.Join(errors.New("composite rollback verification failed; replacement bytes were restored"), restoreErr)
	}
	return nil
}
