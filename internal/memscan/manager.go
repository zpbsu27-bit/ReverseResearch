package memscan

import (
	"bytes"
	"context"
	"crypto/rand"
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

	"reverseresearch/internal/processcontrol"
	"reverseresearch/internal/recordio"
)

const (
	memoryCommit  = uint32(0x1000)
	pageNoAccess  = uint32(0x01)
	pageGuard     = uint32(0x100)
	readChunkSize = uint64(1 << 20)
)

var scanIDPattern = regexp.MustCompile(`^scan_[a-f0-9]{16}$`)

type processMemory interface {
	Query(uint64) (RegionIdentity, error)
	Read(uint64, int) ([]byte, error)
	Close() error
}

type memoryOpener func(uint32) (processMemory, error)
type processInspector func(uint32) (processcontrol.Identity, error)
type processValidator func(processcontrol.Identity) (processcontrol.Identity, error)

type Manager struct {
	dir      string
	inspect  processInspector
	validate processValidator
	open     memoryOpener
}

func New(dir string) (*Manager, error) {
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(absolute, 0o700); err != nil {
		return nil, err
	}
	return &Manager{
		dir: absolute, inspect: processcontrol.Inspect, validate: processcontrol.Validate,
		open: openProcessMemory,
	}, nil
}

func newManagerForTest(dir string, inspect processInspector, validate processValidator, open memoryOpener) (*Manager, error) {
	manager, err := New(dir)
	if err != nil {
		return nil, err
	}
	manager.inspect = inspect
	manager.validate = validate
	manager.open = open
	return manager, nil
}

func (m *Manager) Start(ctx context.Context, request StartRequest) (Summary, error) {
	if request.PID == 0 {
		return Summary{}, errors.New("memory scan pid is required")
	}
	request.ProcessKey = strings.TrimSpace(request.ProcessKey)
	if request.ProcessKey == "" {
		return Summary{}, errors.New("memory scan process_key is required")
	}
	desc, err := descriptor(request.ValueType)
	if err != nil {
		return Summary{}, err
	}
	request.ValueType = desc.name
	request.Mode = normalizeMode(request.Mode)
	if request.Mode == "" {
		request.Mode = ModeExact
	}
	if request.Mode != ModeExact && request.Mode != ModeUnknown {
		return Summary{}, fmt.Errorf("initial memory scan mode must be %q or %q", ModeExact, ModeUnknown)
	}
	timeout, err := validateTimeout(request.Timeout)
	if err != nil {
		return Summary{}, err
	}
	request.Timeout = timeout

	identity, err := m.inspect(request.PID)
	if err != nil {
		return Summary{}, err
	}
	if identity.Key != request.ProcessKey {
		return Summary{}, fmt.Errorf("%w: expected process key %s current %s", ErrProcessChanged, request.ProcessKey, identity.Key)
	}
	if identity.Image.PE == nil || (identity.Image.PE.Bits != 32 && identity.Image.PE.Bits != 64) {
		return Summary{}, errors.New("memory scan requires a 32-bit or 64-bit PE process")
	}
	if request.EndAddress == 0 {
		if identity.Image.PE.Bits == 32 {
			request.EndAddress = uint64(1) << 32
		} else {
			request.EndAddress = uint64(0x0000800000000000)
		}
	}
	if request.EndAddress <= request.StartAddress {
		return Summary{}, errors.New("memory scan end address must be greater than start address")
	}
	if request.Alignment == 0 {
		request.Alignment = desc.size
	}
	if request.Alignment < 1 || request.Alignment > desc.size || desc.size%request.Alignment != 0 {
		return Summary{}, fmt.Errorf("memory scan alignment must divide value size %d", desc.size)
	}
	if request.MaxBytes == 0 {
		request.MaxBytes = DefaultMaxBytes
	}
	if request.MaxBytes < uint64(desc.size) || request.MaxBytes > MaxScanBytes {
		return Summary{}, fmt.Errorf("memory scan max_bytes must be between %d and %d", desc.size, MaxScanBytes)
	}
	if request.MaxCandidates == 0 {
		request.MaxCandidates = DefaultMaxCandidates
	}
	if request.MaxCandidates < 1 || request.MaxCandidates > MaxCandidates {
		return Summary{}, fmt.Errorf("memory scan max_candidates must be between 1 and %d", MaxCandidates)
	}

	var target []byte
	targetValue := ""
	if request.Mode == ModeExact {
		target, targetValue, err = encodeValue(desc, request.Value)
		if err != nil {
			return Summary{}, err
		}
	}

	// Gate on the durable quota before the expensive scan. Running a scan that is
	// guaranteed to fail when it is saved wastes the whole I/O budget.
	if err := m.ensureNewScanCapacity(); err != nil {
		return Summary{}, err
	}

	memory, err := m.open(request.PID)
	if err != nil {
		return Summary{}, err
	}
	defer memory.Close()

	scanCtx, cancel := context.WithTimeout(ctx, request.Timeout)
	defer cancel()
	candidates, step, coverageComplete, partialReason, err := initialScan(
		scanCtx, memory, desc, request, target,
	)
	if err != nil {
		return Summary{}, err
	}
	if err := m.revalidate(identity); err != nil {
		return Summary{}, err
	}

	id, err := newScanID()
	if err != nil {
		return Summary{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	scan := Scan{
		ID: id, Version: 1, CreatedUTC: now, UpdatedUTC: now,
		Process: identity, ValueType: desc.name, ValueSize: desc.size,
		InitialMode: request.Mode, LastMode: request.Mode, TargetValue: targetValue,
		StartAddress: request.StartAddress, EndAddress: request.EndAddress,
		Alignment: request.Alignment, MaxBytes: request.MaxBytes, MaxCandidates: request.MaxCandidates,
		CoverageComplete: coverageComplete, StepComplete: true, PartialReason: partialReason,
		Candidates: candidates, History: []StepStats{step},
	}
	if err := m.saveNew(ctx, scan); err != nil {
		return Summary{}, err
	}
	return scan.Summary(DefaultSampleLimit), nil
}

func (m *Manager) Refine(ctx context.Context, request RefineRequest) (result Summary, err error) {
	if !validScanID(request.ScanID) {
		return Summary{}, ErrInvalidScanID
	}
	if request.ExpectedVersion < 1 {
		return Summary{}, errors.New("expected_version is required")
	}
	request.Mode = normalizeMode(request.Mode)
	switch request.Mode {
	case ModeExact, ModeChanged, ModeUnchanged, ModeIncreased, ModeDecreased:
	default:
		return Summary{}, fmt.Errorf("refine mode must be exact, changed, unchanged, increased, or decreased")
	}
	timeout, err := validateTimeout(request.Timeout)
	if err != nil {
		return Summary{}, err
	}
	request.Timeout = timeout

	lockPath := m.lockPath(request.ScanID)
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		return Summary{}, err
	}
	release, err := recordio.AcquireContext(ctx, lockPath, 10*time.Second)
	if err != nil {
		return Summary{}, err
	}
	defer func() { err = errors.Join(err, release()) }()

	scan, err := m.load(request.ScanID)
	if err != nil {
		return Summary{}, err
	}
	if scan.Version != request.ExpectedVersion {
		return Summary{}, fmt.Errorf("%w: expected=%d current=%d", ErrVersionConflict, request.ExpectedVersion, scan.Version)
	}
	if !scan.StepComplete {
		return Summary{}, ErrIncompleteStep
	}
	desc, err := descriptor(scan.ValueType)
	if err != nil {
		return Summary{}, err
	}
	var target []byte
	targetValue := ""
	if request.Mode == ModeExact {
		target, targetValue, err = encodeValue(desc, request.Value)
		if err != nil {
			return Summary{}, err
		}
	}
	current, err := m.validate(scan.Process)
	if err != nil || !processcontrol.SameInstance(scan.Process, current) {
		if err == nil {
			err = processcontrol.ErrProcessChanged
		}
		return Summary{}, fmt.Errorf("%w: %v", ErrProcessChanged, err)
	}

	memory, err := m.open(scan.Process.PID)
	if err != nil {
		return Summary{}, err
	}
	defer memory.Close()

	refineCtx, cancel := context.WithTimeout(ctx, request.Timeout)
	defer cancel()
	candidates, step, complete, partialReason, err := refineCandidates(
		refineCtx, memory, desc, scan, request.Mode, target,
	)
	if err != nil {
		return Summary{}, err
	}
	if err := m.revalidate(scan.Process); err != nil {
		return Summary{}, err
	}

	scan.Version++
	scan.UpdatedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	scan.LastMode = request.Mode
	scan.TargetValue = targetValue
	scan.StepComplete = complete
	if partialReason != "" {
		scan.PartialReason = partialReason
	}
	scan.Candidates = candidates
	step.Version = scan.Version
	scan.History = append(scan.History, step)
	if len(scan.History) > MaxHistoryEntries {
		scan.History = append([]StepStats(nil), scan.History[len(scan.History)-MaxHistoryEntries:]...)
	}
	if err := m.save(scan); err != nil {
		return Summary{}, err
	}
	return scan.Summary(DefaultSampleLimit), nil
}

func (m *Manager) Get(scanID string, sampleLimit int) (Summary, error) {
	if !validScanID(scanID) {
		return Summary{}, ErrInvalidScanID
	}
	scan, err := m.load(scanID)
	if err != nil {
		return Summary{}, err
	}
	return scan.Summary(sampleLimit), nil
}

// Delete explicitly releases persisted scan capacity. It never runs automatically
// because scan state can be research evidence needed for later review.
func (m *Manager) Delete(ctx context.Context, request DeleteRequest) (result DeleteResult, err error) {
	request.ScanID = strings.TrimSpace(request.ScanID)
	if !validScanID(request.ScanID) {
		return DeleteResult{}, ErrInvalidScanID
	}
	if request.ExpectedVersion < 1 {
		return DeleteResult{}, errors.New("expected_version is required")
	}
	storeRelease, err := recordio.AcquireContext(ctx, m.storeLockPath(), 10*time.Second)
	if err != nil {
		return DeleteResult{}, err
	}
	defer func() { err = errors.Join(err, storeRelease()) }()
	release, err := recordio.AcquireContext(ctx, m.lockPath(request.ScanID), 10*time.Second)
	if err != nil {
		return DeleteResult{}, err
	}
	defer func() { err = errors.Join(err, release()) }()
	scan, err := m.load(request.ScanID)
	if err != nil {
		return DeleteResult{}, err
	}
	if scan.Version != request.ExpectedVersion {
		return DeleteResult{}, fmt.Errorf("%w: expected=%d current=%d", ErrVersionConflict, request.ExpectedVersion, scan.Version)
	}
	var removeErr error
	for _, path := range []string{m.scanPath(request.ScanID), m.legacyScanPath(request.ScanID)} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			removeErr = errors.Join(removeErr, fmt.Errorf("remove memory scan state %s: %w", path, err))
		}
	}
	if removeErr != nil {
		return DeleteResult{}, removeErr
	}
	return DeleteResult{ScanID: request.ScanID, Version: scan.Version, Deleted: true}, nil
}

func initialScan(
	ctx context.Context,
	memory processMemory,
	desc valueDescriptor,
	request StartRequest,
	target []byte,
) ([]Candidate, StepStats, bool, string, error) {
	started := time.Now()
	stats := StepStats{
		Version: 1, Mode: request.Mode, StartedUTC: started.UTC().Format(time.RFC3339Nano),
		CandidatesBefore: 0, Complete: true,
	}
	candidates := make([]Candidate, 0, minInt(request.MaxCandidates, 4096))
	var candidateStateBytesUsed uint64
	address := request.StartAddress
	coverageComplete := true
	partialReason := ""

	for address < request.EndAddress {
		if err := ctx.Err(); err != nil {
			coverageComplete = false
			partialReason = "timeout"
			stats.Complete = false
			break
		}
		region, err := memory.Query(address)
		if err != nil {
			stats.QueryFailures++
			coverageComplete = false
			partialReason = "query_failure"
			stats.Complete = false
			break
		}
		stats.RegionsVisited++
		next := region.EndAddress()
		if next <= address {
			return nil, StepStats{}, false, "", errors.New("memory region query did not advance")
		}
		if next > request.EndAddress {
			next = request.EndAddress
		}
		if region.State == memoryCommit && region.Protect&pageGuard == 0 && region.Protect&pageNoAccess == 0 {
			regionStart := maxU64(address, region.BaseAddress)
			regionEnd := minU64(next, region.EndAddress())
			cursor := alignUp(regionStart, uint64(request.Alignment))
			readable := false
			for cursor < regionEnd && regionEnd-cursor >= uint64(desc.size) {
				if err := ctx.Err(); err != nil {
					coverageComplete = false
					partialReason = "timeout"
					stats.Complete = false
					break
				}
				if stats.BytesRead >= request.MaxBytes || request.MaxBytes-stats.BytesRead < uint64(desc.size) {
					coverageComplete = false
					partialReason = "max_bytes"
					stats.Complete = false
					break
				}
				readLen := minU64(readChunkSize, regionEnd-cursor)
				remainingBudget := request.MaxBytes - stats.BytesRead
				if readLen > remainingBudget {
					readLen = remainingBudget
				}
				if readLen < uint64(desc.size) {
					coverageComplete = false
					partialReason = "max_bytes"
					stats.Complete = false
					break
				}
				raw, readErr := memory.Read(cursor, int(readLen))
				if readErr != nil {
					stats.UnreadableRegions++
					coverageComplete = false
					if partialReason == "" {
						partialReason = "unreadable_region"
					}
					stats.Complete = false
					readable = false
					break
				}
				readable = true
				stats.BytesRead += uint64(len(raw))
				lastOffset := len(raw) - desc.size
				for offset := 0; offset <= lastOffset; offset += request.Alignment {
					stats.ValuesExamined++
					current := raw[offset : offset+desc.size]
					if request.Mode == ModeUnknown || bytes.Equal(current, target) {
						candidate, err := candidateFromRaw(cursor+uint64(offset), current, desc, region)
						if err != nil {
							return nil, StepStats{}, false, "", err
						}
						cost := estimateCandidateStateBytes(candidate)
						if !fitsStateBudget(candidateStateBytesUsed, cost, MaxCandidateStateBytes) {
							coverageComplete = false
							partialReason = "max_state_bytes"
							stats.Complete = false
							break
						}
						candidateStateBytesUsed += cost
						candidates = append(candidates, candidate)
						if len(candidates) >= request.MaxCandidates {
							coverageComplete = false
							partialReason = "max_candidates"
							stats.Complete = false
							break
						}
					}
				}
				if partialReason != "" {
					break
				}
				advance := uint64(len(raw))
				overlap := uint64(desc.size - request.Alignment)
				if advance <= overlap {
					break
				}
				cursor += advance - overlap
			}
			if readable {
				stats.ReadableRegions++
			}
			if partialReason != "" {
				break
			}
		}
		address = next
	}

	stats.CandidatesAfter = len(candidates)
	stats.DurationMS = time.Since(started).Milliseconds()
	stats.PartialReason = partialReason
	return candidates, stats, coverageComplete, partialReason, nil
}

func refineCandidates(
	ctx context.Context,
	memory processMemory,
	desc valueDescriptor,
	scan Scan,
	mode Mode,
	target []byte,
) ([]Candidate, StepStats, bool, string, error) {
	started := time.Now()
	stats := StepStats{
		Mode: mode, StartedUTC: started.UTC().Format(time.RFC3339Nano),
		CandidatesBefore: len(scan.Candidates), Complete: true,
	}
	result := scan.Candidates[:0]
	var resultStateBytes uint64
	complete := true
	partialReason := ""

	for index, candidate := range scan.Candidates {
		if err := ctx.Err(); err != nil {
			complete = false
			partialReason = "timeout"
			stats.Complete = false
			stats.UnprocessedCandidates = len(scan.Candidates) - index
			break
		}
		region, err := memory.Query(candidate.Address)
		if err != nil {
			stats.QueryFailures++
			stats.StaleRegionCandidates++
			continue
		}
		stats.RegionsVisited++
		if !candidate.Region.Same(region) {
			stats.StaleRegionCandidates++
			continue
		}
		raw, err := memory.Read(candidate.Address, desc.size)
		if err != nil {
			stats.UnreadableCandidates++
			continue
		}
		stats.BytesRead += uint64(len(raw))
		stats.ValuesExamined++
		previous, err := rawCandidate(candidate, desc.size)
		if err != nil {
			return nil, StepStats{}, false, "", err
		}
		match := false
		switch mode {
		case ModeExact:
			match = bytes.Equal(raw, target)
		case ModeChanged:
			match = !bytes.Equal(raw, previous)
		case ModeUnchanged:
			match = bytes.Equal(raw, previous)
		case ModeIncreased, ModeDecreased:
			order, err := compareValue(desc, previous, raw)
			if err != nil {
				return nil, StepStats{}, false, "", err
			}
			if mode == ModeIncreased {
				match = order > 0
			} else {
				match = order < 0
			}
		}
		if match {
			updated, err := candidateFromRaw(candidate.Address, raw, desc, region)
			if err != nil {
				return nil, StepStats{}, false, "", err
			}
			cost := estimateCandidateStateBytes(updated)
			if !fitsStateBudget(resultStateBytes, cost, MaxCandidateStateBytes) {
				complete = false
				partialReason = "max_state_bytes"
				stats.Complete = false
				stats.UnprocessedCandidates = len(scan.Candidates) - index
				break
			}
			resultStateBytes += cost
			result = append(result, updated)
		}
	}
	for index := len(result); index < len(scan.Candidates); index++ {
		scan.Candidates[index] = Candidate{}
	}
	stats.CandidatesAfter = len(result)
	stats.DurationMS = time.Since(started).Milliseconds()
	stats.PartialReason = partialReason
	return result, stats, complete, partialReason, nil
}

func (m *Manager) revalidate(expected processcontrol.Identity) error {
	current, err := m.validate(expected)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProcessChanged, err)
	}
	if !processcontrol.SameInstance(expected, current) {
		return ErrProcessChanged
	}
	return nil
}

func (m *Manager) saveNew(ctx context.Context, scan Scan) (err error) {
	storeRelease, err := recordio.AcquireContext(ctx, m.storeLockPath(), 10*time.Second)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, storeRelease()) }()

	if err := m.ensureNewScanCapacity(); err != nil {
		return err
	}
	lockPath := m.lockPath(scan.ID)
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		return err
	}
	release, err := recordio.AcquireContext(ctx, lockPath, 10*time.Second)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, release()) }()

	if _, err := os.Stat(m.scanPath(scan.ID)); err == nil {
		return errors.New("memory scan id collision")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if _, err := os.Stat(m.legacyScanPath(scan.ID)); err == nil {
		return errors.New("memory scan id collision")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return m.save(scan)
}

func (m *Manager) save(scan Scan) error {
	path := m.scanPath(scan.ID)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := recordio.WriteStream(path, 0o600, func(writer io.Writer) error {
		return json.NewEncoder(&stateLimitWriter{inner: writer, limit: MaxPersistedScanBytes}).Encode(scan)
	}); err != nil {
		return err
	}
	_ = os.Remove(m.legacyScanPath(scan.ID))
	return nil
}

// stateLimitWriter stops encoding before a record grows past the size the read
// path is willing to open again. Publishing a larger record would create state
// that can never be loaded, refined, or verified.
type stateLimitWriter struct {
	inner   io.Writer
	written int64
	limit   int64
}

func (w *stateLimitWriter) Write(p []byte) (int, error) {
	if w.written+int64(len(p)) > w.limit {
		return 0, fmt.Errorf("persisted memory scan would exceed state limit: %d > %d", w.written+int64(len(p)), w.limit)
	}
	n, err := w.inner.Write(p)
	w.written += int64(n)
	return n, err
}

func (m *Manager) load(scanID string) (Scan, error) {
	file, err := os.Open(m.scanPath(scanID))
	if errors.Is(err, os.ErrNotExist) {
		file, err = os.Open(m.legacyScanPath(scanID))
	}
	if err != nil {
		return Scan{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return Scan{}, err
	}
	if info.Size() > MaxPersistedScanBytes {
		return Scan{}, fmt.Errorf("persisted memory scan exceeds state limit: %d > %d", info.Size(), MaxPersistedScanBytes)
	}
	var scan Scan
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&scan); err != nil {
		return Scan{}, fmt.Errorf("decode memory scan %s: %w", scanID, err)
	}
	if scan.ID != scanID || scan.Version < 1 || scan.Process.PID == 0 || scan.Process.Key == "" {
		return Scan{}, errors.New("invalid persisted memory scan")
	}
	if used := estimateCandidateSliceBytes(scan.Candidates); used > MaxCandidateStateBytes {
		return Scan{}, fmt.Errorf("persisted memory scan candidate state exceeds limit: %d > %d", used, MaxCandidateStateBytes)
	}
	return scan, nil
}

func scanShard(scanID string) string {
	value := strings.TrimPrefix(scanID, "scan_")
	if len(value) >= 2 {
		return value[:2]
	}
	return "00"
}

func (m *Manager) scanPath(scanID string) string {
	return filepath.Join(m.dir, "data", scanShard(scanID), scanID+".json")
}

func (m *Manager) legacyScanPath(scanID string) string {
	return filepath.Join(m.dir, scanID+".json")
}

func (m *Manager) lockPath(scanID string) string {
	return filepath.Join(m.dir, "locks", scanShard(scanID), scanID+".lock")
}

func (m *Manager) storeLockPath() string {
	return filepath.Join(m.dir, ".store.lock")
}

func validScanID(scanID string) bool {
	return scanIDPattern.MatchString(strings.TrimSpace(scanID))
}

func newScanID() (string, error) {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "scan_" + hex.EncodeToString(raw[:]), nil
}

func alignUp(value, alignment uint64) uint64 {
	if alignment <= 1 {
		return value
	}
	remainder := value % alignment
	if remainder == 0 {
		return value
	}
	if value > ^uint64(0)-(alignment-remainder) {
		return ^uint64(0)
	}
	return value + alignment - remainder
}

func minU64(left, right uint64) uint64 {
	if left < right {
		return left
	}
	return right
}

func maxU64(left, right uint64) uint64 {
	if left > right {
		return left
	}
	return right
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}
