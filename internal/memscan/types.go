package memscan

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"reverseresearch/internal/processcontrol"
)

const (
	DefaultTimeout       = 5 * time.Second
	MaxTimeout           = 30 * time.Second
	DefaultMaxBytes      = uint64(64 << 20)
	MaxScanBytes         = uint64(1 << 30)
	DefaultMaxCandidates = 100000
	MaxCandidates        = 1000000
	DefaultSampleLimit   = 32
	MaxSampleLimit       = 200
	MaxHistoryEntries    = 128
)

var (
	ErrUnsupported     = errors.New("live memory scan is unsupported on this platform")
	ErrProcessChanged  = errors.New("memory scan process identity changed")
	ErrVersionConflict = errors.New("memory scan version conflict")
	ErrIncompleteStep  = errors.New("memory scan last refinement is incomplete")
	ErrInvalidScanID   = errors.New("invalid memory scan id")
)

type Mode string

const (
	ModeUnknown   Mode = "unknown"
	ModeExact     Mode = "exact"
	ModeChanged   Mode = "changed"
	ModeUnchanged Mode = "unchanged"
	ModeIncreased Mode = "increased"
	ModeDecreased Mode = "decreased"
)

type StartRequest struct {
	PID           uint32
	ProcessKey    string
	ValueType     string
	Mode          Mode
	Value         string
	StartAddress  uint64
	EndAddress    uint64
	Alignment     int
	MaxBytes      uint64
	MaxCandidates int
	Timeout       time.Duration
}

type RefineRequest struct {
	ScanID          string
	ExpectedVersion int
	Mode            Mode
	Value           string
	Timeout         time.Duration
}

type DeleteRequest struct {
	ScanID          string `json:"scan_id"`
	ExpectedVersion int    `json:"expected_version"`
}

type DeleteResult struct {
	ScanID  string `json:"scan_id"`
	Version int    `json:"version"`
	Deleted bool   `json:"deleted"`
}

type RegionIdentity struct {
	BaseAddress       uint64 `json:"base_address"`
	AllocationBase    uint64 `json:"allocation_base"`
	AllocationProtect uint32 `json:"allocation_protect"`
	RegionSize        uint64 `json:"region_size"`
	State             uint32 `json:"state"`
	Protect           uint32 `json:"protect"`
	Type              uint32 `json:"type"`
}

// ReadOnlyMemory is the shared query/read surface used by higher-level
// read-only process analysis such as value scans and pointer maps.
type ReadOnlyMemory interface {
	Query(uint64) (RegionIdentity, error)
	Read(uint64, int) ([]byte, error)
	Close() error
}

func OpenReadOnlyMemory(pid uint32) (ReadOnlyMemory, error) {
	return openProcessMemory(pid)
}

func (r RegionIdentity) EndAddress() uint64 {
	if r.RegionSize > ^uint64(0)-r.BaseAddress {
		return ^uint64(0)
	}
	return r.BaseAddress + r.RegionSize
}

func (r RegionIdentity) Same(other RegionIdentity) bool {
	return r.BaseAddress == other.BaseAddress &&
		r.AllocationBase == other.AllocationBase &&
		r.AllocationProtect == other.AllocationProtect &&
		r.RegionSize == other.RegionSize &&
		r.State == other.State &&
		r.Protect == other.Protect &&
		r.Type == other.Type
}

type Candidate struct {
	Address    uint64         `json:"address"`
	AddressHex string         `json:"address_hex"`
	RawHex     string         `json:"raw_hex"`
	Value      string         `json:"value"`
	Region     RegionIdentity `json:"region"`
}

type StepStats struct {
	Version               int    `json:"version"`
	Mode                  Mode   `json:"mode"`
	StartedUTC            string `json:"started_utc"`
	DurationMS            int64  `json:"duration_ms"`
	CandidatesBefore      int    `json:"candidates_before"`
	CandidatesAfter       int    `json:"candidates_after"`
	ValuesExamined        uint64 `json:"values_examined"`
	BytesRead             uint64 `json:"bytes_read"`
	RegionsVisited        int    `json:"regions_visited"`
	ReadableRegions       int    `json:"readable_regions"`
	UnreadableRegions     int    `json:"unreadable_regions"`
	QueryFailures         int    `json:"query_failures"`
	StaleRegionCandidates int    `json:"stale_region_candidates"`
	UnreadableCandidates  int    `json:"unreadable_candidates"`
	UnprocessedCandidates int    `json:"unprocessed_candidates"`
	Complete              bool   `json:"complete"`
	PartialReason         string `json:"partial_reason,omitempty"`
}

type Scan struct {
	ID               string                  `json:"id"`
	Version          int                     `json:"version"`
	CreatedUTC       string                  `json:"created_utc"`
	UpdatedUTC       string                  `json:"updated_utc"`
	Process          processcontrol.Identity `json:"process"`
	ValueType        string                  `json:"value_type"`
	ValueSize        int                     `json:"value_size"`
	InitialMode      Mode                    `json:"initial_mode"`
	LastMode         Mode                    `json:"last_mode"`
	TargetValue      string                  `json:"target_value,omitempty"`
	StartAddress     uint64                  `json:"start_address"`
	EndAddress       uint64                  `json:"end_address"`
	Alignment        int                     `json:"alignment"`
	MaxBytes         uint64                  `json:"max_bytes"`
	MaxCandidates    int                     `json:"max_candidates"`
	CoverageComplete bool                    `json:"coverage_complete"`
	StepComplete     bool                    `json:"step_complete"`
	PartialReason    string                  `json:"partial_reason,omitempty"`
	Candidates       []Candidate             `json:"candidates"`
	History          []StepStats             `json:"history"`
}

type Summary struct {
	ID               string                  `json:"id"`
	Version          int                     `json:"version"`
	CreatedUTC       string                  `json:"created_utc"`
	UpdatedUTC       string                  `json:"updated_utc"`
	Process          processcontrol.Identity `json:"process"`
	ValueType        string                  `json:"value_type"`
	ValueSize        int                     `json:"value_size"`
	InitialMode      Mode                    `json:"initial_mode"`
	LastMode         Mode                    `json:"last_mode"`
	TargetValue      string                  `json:"target_value,omitempty"`
	StartAddress     uint64                  `json:"start_address"`
	EndAddress       uint64                  `json:"end_address"`
	Alignment        int                     `json:"alignment"`
	MaxBytes         uint64                  `json:"max_bytes"`
	MaxCandidates    int                     `json:"max_candidates"`
	CoverageComplete bool                    `json:"coverage_complete"`
	StepComplete     bool                    `json:"step_complete"`
	PartialReason    string                  `json:"partial_reason,omitempty"`
	CandidateCount   int                     `json:"candidate_count"`
	CandidateSample  []Candidate             `json:"candidate_sample,omitempty"`
	History          []StepStats             `json:"history"`
}

func (s Scan) Summary(limit int) Summary {
	if limit <= 0 {
		limit = DefaultSampleLimit
	}
	if limit > MaxSampleLimit {
		limit = MaxSampleLimit
	}
	if limit > len(s.Candidates) {
		limit = len(s.Candidates)
	}
	sample := append([]Candidate(nil), s.Candidates[:limit]...)
	return Summary{
		ID: s.ID, Version: s.Version, CreatedUTC: s.CreatedUTC, UpdatedUTC: s.UpdatedUTC,
		Process: s.Process, ValueType: s.ValueType, ValueSize: s.ValueSize,
		InitialMode: s.InitialMode, LastMode: s.LastMode, TargetValue: s.TargetValue,
		StartAddress: s.StartAddress, EndAddress: s.EndAddress, Alignment: s.Alignment,
		MaxBytes: s.MaxBytes, MaxCandidates: s.MaxCandidates,
		CoverageComplete: s.CoverageComplete, StepComplete: s.StepComplete,
		PartialReason: s.PartialReason, CandidateCount: len(s.Candidates),
		CandidateSample: sample, History: append([]StepStats(nil), s.History...),
	}
}

func normalizeMode(value Mode) Mode {
	return Mode(strings.ToLower(strings.TrimSpace(string(value))))
}

func validateTimeout(timeout time.Duration) (time.Duration, error) {
	if timeout == 0 {
		return DefaultTimeout, nil
	}
	if timeout < 0 || timeout > MaxTimeout {
		return 0, fmt.Errorf("memory scan timeout must be > 0 and <= %s", MaxTimeout)
	}
	return timeout, nil
}
