package pointermap

import (
	"errors"
	"fmt"
	"time"

	"reverseresearch/internal/memscan"
	"reverseresearch/internal/processcontrol"
)

const (
	DefaultMaxOffset = uint64(4096)
	MaxOffset        = uint64(1 << 20)
	DefaultMaxDepth  = 3
	MaxDepth         = 8
	DefaultMaxBytes  = uint64(64 << 20)
	MaxBytes         = uint64(1 << 30)
	DefaultMaxNodes  = 50000
	MaxNodes         = 500000
	DefaultMaxChains = 10000
	MaxChains        = 100000
	DefaultTimeout   = 10 * time.Second
	MaxTimeout       = 60 * time.Second
	DefaultSample    = 32
	MaxSample        = 200
)

var (
	ErrUnsupported     = errors.New("pointer mapping is unsupported on this platform")
	ErrProcessChanged  = errors.New("pointer map process identity changed")
	ErrVersionConflict = errors.New("pointer map version conflict")
	ErrInvalidMapID    = errors.New("invalid pointer map id")
)

type BuildRequest struct {
	PID           uint32
	ProcessKey    string
	TargetAddress uint64
	StartAddress  uint64
	EndAddress    uint64
	MaxOffset     uint64
	MaxDepth      int
	Alignment     int
	MaxBytes      uint64
	MaxNodes      int
	MaxChains     int
	Timeout       time.Duration
}

type DeleteRequest struct {
	MapID           string `json:"map_id"`
	ExpectedVersion int    `json:"expected_version"`
}

type DeleteResult struct {
	MapID   string `json:"map_id"`
	Version int    `json:"version"`
	Deleted bool   `json:"deleted"`
}

type Module struct {
	Path string
	Base uint64
	Size uint64
}

type ModuleAnchor struct {
	ModulePath     string `json:"module_path"`
	ModuleSHA256   string `json:"module_sha256"`
	ModuleFileSize int64  `json:"module_file_size"`
	SourceBase     uint64 `json:"source_base"`
	ModuleSize     uint64 `json:"module_size"`
	RVA            uint64 `json:"rva"`
}

type Chain struct {
	Depth             int          `json:"depth"`
	SourceRootAddress uint64       `json:"source_root_address"`
	SourceRootHex     string       `json:"source_root_hex"`
	Anchor            ModuleAnchor `json:"anchor"`
	Offsets           []uint64     `json:"offsets"`
	SourceSlots       []uint64     `json:"source_slots"`
}

type DepthStats struct {
	Depth                 int    `json:"depth"`
	TargetsBefore         int    `json:"targets_before"`
	NodesAfter            int    `json:"nodes_after"`
	AnchoredChains        int    `json:"anchored_chains"`
	PointerValuesExamined uint64 `json:"pointer_values_examined"`
	BytesRead             uint64 `json:"bytes_read"`
	RegionsVisited        int    `json:"regions_visited"`
	ReadableRegions       int    `json:"readable_regions"`
	UnreadableRegions     int    `json:"unreadable_regions"`
	QueryFailures         int    `json:"query_failures"`
	Complete              bool   `json:"complete"`
	PartialReason         string `json:"partial_reason,omitempty"`
}

type Map struct {
	ID               string                  `json:"id"`
	Version          int                     `json:"version"`
	CreatedUTC       string                  `json:"created_utc"`
	SourceProcess    processcontrol.Identity `json:"source_process"`
	PointerSize      int                     `json:"pointer_size"`
	TargetAddress    uint64                  `json:"target_address"`
	TargetAddressHex string                  `json:"target_address_hex"`
	TargetRegion     memscan.RegionIdentity  `json:"target_region"`
	StartAddress     uint64                  `json:"start_address"`
	EndAddress       uint64                  `json:"end_address"`
	MaxOffset        uint64                  `json:"max_offset"`
	MaxDepth         int                     `json:"max_depth"`
	Alignment        int                     `json:"alignment"`
	MaxBytes         uint64                  `json:"max_bytes_per_depth"`
	MaxNodes         int                     `json:"max_nodes"`
	MaxChains        int                     `json:"max_chains"`
	CoverageComplete bool                    `json:"coverage_complete"`
	PartialReason    string                  `json:"partial_reason,omitempty"`
	Chains           []Chain                 `json:"chains"`
	History          []DepthStats            `json:"history"`
}

type Summary struct {
	ID               string                  `json:"id"`
	Version          int                     `json:"version"`
	CreatedUTC       string                  `json:"created_utc"`
	SourceProcess    processcontrol.Identity `json:"source_process"`
	PointerSize      int                     `json:"pointer_size"`
	TargetAddress    uint64                  `json:"target_address"`
	TargetAddressHex string                  `json:"target_address_hex"`
	TargetRegion     memscan.RegionIdentity  `json:"target_region"`
	StartAddress     uint64                  `json:"start_address"`
	EndAddress       uint64                  `json:"end_address"`
	MaxOffset        uint64                  `json:"max_offset"`
	MaxDepth         int                     `json:"max_depth"`
	Alignment        int                     `json:"alignment"`
	MaxBytes         uint64                  `json:"max_bytes_per_depth"`
	MaxNodes         int                     `json:"max_nodes"`
	MaxChains        int                     `json:"max_chains"`
	CoverageComplete bool                    `json:"coverage_complete"`
	PartialReason    string                  `json:"partial_reason,omitempty"`
	ChainCount       int                     `json:"chain_count"`
	ChainSample      []Chain                 `json:"chain_sample,omitempty"`
	History          []DepthStats            `json:"history"`
}

func (m Map) Summary(limit int) Summary {
	if limit <= 0 {
		limit = DefaultSample
	}
	if limit > MaxSample {
		limit = MaxSample
	}
	if limit > len(m.Chains) {
		limit = len(m.Chains)
	}
	return Summary{
		ID: m.ID, Version: m.Version, CreatedUTC: m.CreatedUTC,
		SourceProcess: m.SourceProcess, PointerSize: m.PointerSize,
		TargetAddress: m.TargetAddress, TargetAddressHex: m.TargetAddressHex, TargetRegion: m.TargetRegion,
		StartAddress: m.StartAddress, EndAddress: m.EndAddress, MaxOffset: m.MaxOffset,
		MaxDepth: m.MaxDepth, Alignment: m.Alignment, MaxBytes: m.MaxBytes,
		MaxNodes: m.MaxNodes, MaxChains: m.MaxChains,
		CoverageComplete: m.CoverageComplete, PartialReason: m.PartialReason,
		ChainCount: len(m.Chains), ChainSample: append([]Chain(nil), m.Chains[:limit]...),
		History: append([]DepthStats(nil), m.History...),
	}
}

type VerifyRequest struct {
	MapID         string
	PID           uint32
	ProcessKey    string
	TargetAddress uint64
	Timeout       time.Duration
	SampleLimit   int
}

type ResolveStep struct {
	Level         int    `json:"level"`
	SlotAddress   uint64 `json:"slot_address"`
	SlotHex       string `json:"slot_hex"`
	PointerValue  uint64 `json:"pointer_value"`
	PointerHex    string `json:"pointer_hex"`
	Offset        uint64 `json:"offset"`
	ResultAddress uint64 `json:"result_address"`
	ResultHex     string `json:"result_hex"`
}

type ChainVerification struct {
	ChainIndex         int           `json:"chain_index"`
	Depth              int           `json:"depth"`
	Anchor             ModuleAnchor  `json:"anchor"`
	CurrentModuleBase  uint64        `json:"current_module_base"`
	CurrentRootAddress uint64        `json:"current_root_address"`
	CurrentRootHex     string        `json:"current_root_hex"`
	ModuleRelocated    bool          `json:"module_relocated"`
	ResolvedAddress    uint64        `json:"resolved_address"`
	ResolvedHex        string        `json:"resolved_hex"`
	TargetMatch        bool          `json:"target_match"`
	Valid              bool          `json:"valid"`
	Failure            string        `json:"failure,omitempty"`
	Steps              []ResolveStep `json:"steps,omitempty"`
}

type Verification struct {
	MapID            string                  `json:"map_id"`
	SourceProcessKey string                  `json:"source_process_key"`
	CurrentProcess   processcontrol.Identity `json:"current_process"`
	CrossProcess     bool                    `json:"cross_process"`
	TargetAddress    uint64                  `json:"target_address,omitempty"`
	TargetAddressHex string                  `json:"target_address_hex,omitempty"`
	CheckedChains    int                     `json:"checked_chains"`
	ValidChains      int                     `json:"valid_chains"`
	InvalidChains    int                     `json:"invalid_chains"`
	RelocatedChains  int                     `json:"relocated_chains"`
	Complete         bool                    `json:"complete"`
	PartialReason    string                  `json:"partial_reason,omitempty"`
	ChainSample      []ChainVerification     `json:"chain_sample,omitempty"`
}

func validateTimeout(value time.Duration) (time.Duration, error) {
	if value == 0 {
		return DefaultTimeout, nil
	}
	if value < 0 || value > MaxTimeout {
		return 0, fmt.Errorf("pointer timeout must be > 0 and <= %s", MaxTimeout)
	}
	return value, nil
}
