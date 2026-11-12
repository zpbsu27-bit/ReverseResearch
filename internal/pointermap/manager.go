package pointermap

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"reverseresearch/internal/memscan"
	"reverseresearch/internal/processcontrol"
	"reverseresearch/internal/recordio"
	"reverseresearch/internal/targetidentity"
)

const (
	memoryCommit  = uint32(0x1000)
	pageNoAccess  = uint32(0x01)
	pageGuard     = uint32(0x100)
	readChunkSize = uint64(1 << 20)
)

var mapIDPattern = regexp.MustCompile(`^pmap_[a-f0-9]{16}$`)

type processInspector func(uint32) (processcontrol.Identity, error)
type processValidator func(processcontrol.Identity) (processcontrol.Identity, error)
type memoryOpener func(uint32) (memscan.ReadOnlyMemory, error)
type moduleSnapshotter func(uint32) ([]Module, error)
type imageInspector func(string) (targetidentity.Identity, error)

type Manager struct {
	dir          string
	inspect      processInspector
	validate     processValidator
	open         memoryOpener
	modules      moduleSnapshotter
	inspectImage imageInspector
}

type searchChain struct {
	RootAddress uint64
	Offsets     []uint64
	Slots       []uint64
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
		open: memscan.OpenReadOnlyMemory, modules: snapshotModules, inspectImage: targetidentity.Inspect,
	}, nil
}

func newManagerForTest(
	dir string,
	inspect processInspector,
	validate processValidator,
	open memoryOpener,
	modules moduleSnapshotter,
	inspectImage imageInspector,
) (*Manager, error) {
	manager, err := New(dir)
	if err != nil {
		return nil, err
	}
	manager.inspect = inspect
	manager.validate = validate
	manager.open = open
	manager.modules = modules
	manager.inspectImage = inspectImage
	return manager, nil
}

func (m *Manager) Build(ctx context.Context, request BuildRequest) (Summary, error) {
	if request.PID == 0 {
		return Summary{}, errors.New("pointer map pid is required")
	}
	request.ProcessKey = strings.TrimSpace(request.ProcessKey)
	if request.ProcessKey == "" {
		return Summary{}, errors.New("pointer map process_key is required")
	}
	if request.TargetAddress == 0 {
		return Summary{}, errors.New("pointer map target address is required")
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
	pointerSize, addressCeiling, err := pointerArchitecture(identity)
	if err != nil {
		return Summary{}, err
	}
	if request.EndAddress == 0 {
		request.EndAddress = addressCeiling
	}
	if request.EndAddress <= request.StartAddress {
		return Summary{}, errors.New("pointer map end address must be greater than start address")
	}
	if request.MaxOffset == 0 {
		request.MaxOffset = DefaultMaxOffset
	}
	if request.MaxOffset > MaxOffset {
		return Summary{}, fmt.Errorf("pointer map max_offset must be <= %d", MaxOffset)
	}
	if request.MaxDepth == 0 {
		request.MaxDepth = DefaultMaxDepth
	}
	if request.MaxDepth < 1 || request.MaxDepth > MaxDepth {
		return Summary{}, fmt.Errorf("pointer map max_depth must be between 1 and %d", MaxDepth)
	}
	if request.Alignment == 0 {
		request.Alignment = pointerSize
	}
	if request.Alignment < 1 || request.Alignment > pointerSize || pointerSize%request.Alignment != 0 {
		return Summary{}, fmt.Errorf("pointer map alignment must divide pointer size %d", pointerSize)
	}
	if request.MaxBytes == 0 {
		request.MaxBytes = DefaultMaxBytes
	}
	if request.MaxBytes < uint64(pointerSize) || request.MaxBytes > MaxBytes {
		return Summary{}, fmt.Errorf("pointer map max_bytes must be between %d and %d per depth", pointerSize, MaxBytes)
	}
	if request.MaxNodes == 0 {
		request.MaxNodes = DefaultMaxNodes
	}
	if request.MaxNodes < 1 || request.MaxNodes > MaxNodes {
		return Summary{}, fmt.Errorf("pointer map max_nodes must be between 1 and %d", MaxNodes)
	}
	if request.MaxChains == 0 {
		request.MaxChains = DefaultMaxChains
	}
	if request.MaxChains < 1 || request.MaxChains > MaxChains {
		return Summary{}, fmt.Errorf("pointer map max_chains must be between 1 and %d", MaxChains)
	}

	// Gate on the durable quota before the expensive traversal; a build that can
	// never be saved wastes the whole I/O budget.
	if err := m.ensureNewMapCapacity(); err != nil {
		return Summary{}, err
	}

	memory, err := m.open(request.PID)
	if err != nil {
		return Summary{}, err
	}
	defer memory.Close()

	targetRegion, err := memory.Query(request.TargetAddress)
	if err != nil {
		return Summary{}, fmt.Errorf("query pointer target 0x%X: %w", request.TargetAddress, err)
	}
	if !readableRegion(targetRegion) {
		return Summary{}, fmt.Errorf("pointer target 0x%X is not in a committed readable region", request.TargetAddress)
	}
	modules, err := m.modules(request.PID)
	if err != nil {
		return Summary{}, err
	}

	scanCtx, cancel := context.WithTimeout(ctx, request.Timeout)
	defer cancel()

	frontier := []searchChain{{RootAddress: request.TargetAddress}}
	chains := make([]Chain, 0, minInt(request.MaxChains, 1024))
	var chainStateBytesUsed uint64
	history := make([]DepthStats, 0, request.MaxDepth)
	coverageComplete := true
	partialReason := ""
	totalNodes := 0
	chainSeen := make(map[string]struct{})
	imageCache := make(map[string]targetidentity.Identity)

	for depth := 1; depth <= request.MaxDepth && len(frontier) > 0; depth++ {
		remainingNodes := request.MaxNodes - totalNodes
		if remainingNodes <= 0 {
			coverageComplete = false
			partialReason = firstReason(partialReason, "max_nodes")
			break
		}
		next, stats, complete, reason, err := scanBackrefs(
			scanCtx, memory, pointerSize, request.Alignment,
			request.StartAddress, request.EndAddress, request.MaxOffset, request.MaxBytes,
			frontier, remainingNodes, MaxFrontierStateBytes,
		)
		if err != nil {
			return Summary{}, err
		}
		stats.Depth = depth
		totalNodes += len(next)

		for _, candidate := range next {
			module, ok := moduleContaining(modules, candidate.RootAddress)
			if !ok {
				continue
			}
			anchor, err := m.anchorFor(module, candidate.RootAddress, imageCache)
			if err != nil {
				return Summary{}, err
			}
			chain := Chain{
				Depth: len(candidate.Offsets), SourceRootAddress: candidate.RootAddress,
				SourceRootHex: fmt.Sprintf("0x%X", candidate.RootAddress),
				Anchor:        anchor, Offsets: append([]uint64(nil), candidate.Offsets...),
				SourceSlots: append([]uint64(nil), candidate.Slots...),
			}
			key := chainKey(chain)
			if _, exists := chainSeen[key]; exists {
				continue
			}
			chainSeen[key] = struct{}{}
			cost := estimateChainStateBytes(chain)
			if !fitsPointerStateBudget(chainStateBytesUsed, cost, MaxChainStateBytes) {
				coverageComplete = false
				partialReason = firstReason(partialReason, "max_state_bytes")
				complete = false
				stats.Complete = false
				stats.PartialReason = firstReason(stats.PartialReason, "max_state_bytes")
				break
			}
			chainStateBytesUsed += cost
			chains = append(chains, chain)
			stats.AnchoredChains++
			if len(chains) >= request.MaxChains {
				coverageComplete = false
				partialReason = firstReason(partialReason, "max_chains")
				complete = false
				stats.Complete = false
				stats.PartialReason = firstReason(stats.PartialReason, "max_chains")
				break
			}
		}
		history = append(history, stats)
		if !complete {
			coverageComplete = false
			partialReason = firstReason(partialReason, reason)
			if partialReason == "" {
				partialReason = stats.PartialReason
			}
			break
		}
		frontier = next
	}
	if err := m.revalidate(identity); err != nil {
		return Summary{}, err
	}

	id, err := newMapID()
	if err != nil {
		return Summary{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	pointerMap := Map{
		ID: id, Version: 1, CreatedUTC: now, SourceProcess: identity,
		PointerSize: pointerSize, TargetAddress: request.TargetAddress,
		TargetAddressHex: fmt.Sprintf("0x%X", request.TargetAddress), TargetRegion: targetRegion,
		StartAddress: request.StartAddress, EndAddress: request.EndAddress,
		MaxOffset: request.MaxOffset, MaxDepth: request.MaxDepth, Alignment: request.Alignment,
		MaxBytes: request.MaxBytes, MaxNodes: request.MaxNodes, MaxChains: request.MaxChains,
		CoverageComplete: coverageComplete, PartialReason: partialReason,
		Chains: chains, History: history,
	}
	if err := m.saveNew(ctx, pointerMap); err != nil {
		return Summary{}, err
	}
	return pointerMap.Summary(DefaultSample), nil
}

func (m *Manager) Get(mapID string, sampleLimit int) (Summary, error) {
	if !validMapID(mapID) {
		return Summary{}, ErrInvalidMapID
	}
	pointerMap, err := m.load(mapID)
	if err != nil {
		return Summary{}, err
	}
	return pointerMap.Summary(sampleLimit), nil
}

// Delete explicitly releases persisted pointer-map capacity. It never runs
// automatically because map state can be research evidence needed for review.
func (m *Manager) Delete(ctx context.Context, request DeleteRequest) (result DeleteResult, err error) {
	request.MapID = strings.TrimSpace(request.MapID)
	if !validMapID(request.MapID) {
		return DeleteResult{}, ErrInvalidMapID
	}
	if request.ExpectedVersion < 1 {
		return DeleteResult{}, errors.New("expected_version is required")
	}
	storeRelease, err := recordio.AcquireContext(ctx, m.storeLockPath(), 10*time.Second)
	if err != nil {
		return DeleteResult{}, err
	}
	defer func() { err = errors.Join(err, storeRelease()) }()
	release, err := recordio.AcquireContext(ctx, m.lockPath(request.MapID), 10*time.Second)
	if err != nil {
		return DeleteResult{}, err
	}
	defer func() { err = errors.Join(err, release()) }()
	pointerMap, err := m.load(request.MapID)
	if err != nil {
		return DeleteResult{}, err
	}
	if pointerMap.Version != request.ExpectedVersion {
		return DeleteResult{}, fmt.Errorf("%w: expected=%d current=%d", ErrVersionConflict, request.ExpectedVersion, pointerMap.Version)
	}
	var removeErr error
	for _, path := range []string{m.mapPath(request.MapID), m.legacyMapPath(request.MapID)} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			removeErr = errors.Join(removeErr, fmt.Errorf("remove pointer map state %s: %w", path, err))
		}
	}
	if removeErr != nil {
		return DeleteResult{}, removeErr
	}
	return DeleteResult{MapID: request.MapID, Version: pointerMap.Version, Deleted: true}, nil
}

func (m *Manager) Verify(ctx context.Context, request VerifyRequest) (Verification, error) {
	if !validMapID(request.MapID) {
		return Verification{}, ErrInvalidMapID
	}
	if request.PID == 0 {
		return Verification{}, errors.New("pointer verification pid is required")
	}
	request.ProcessKey = strings.TrimSpace(request.ProcessKey)
	if request.ProcessKey == "" {
		return Verification{}, errors.New("pointer verification process_key is required")
	}
	timeout, err := validateTimeout(request.Timeout)
	if err != nil {
		return Verification{}, err
	}
	if request.SampleLimit <= 0 {
		request.SampleLimit = DefaultSample
	}
	if request.SampleLimit > MaxSample {
		return Verification{}, fmt.Errorf("pointer verification sample_limit must be <= %d", MaxSample)
	}

	pointerMap, err := m.load(request.MapID)
	if err != nil {
		return Verification{}, err
	}
	current, err := m.inspect(request.PID)
	if err != nil {
		return Verification{}, err
	}
	if current.Key != request.ProcessKey {
		return Verification{}, fmt.Errorf("%w: expected process key %s current %s", ErrProcessChanged, request.ProcessKey, current.Key)
	}
	currentPointerSize, _, err := pointerArchitecture(current)
	if err != nil {
		return Verification{}, err
	}
	if currentPointerSize != pointerMap.PointerSize {
		return Verification{}, fmt.Errorf("pointer width changed: map=%d current=%d", pointerMap.PointerSize, currentPointerSize)
	}
	modules, err := m.modules(request.PID)
	if err != nil {
		return Verification{}, err
	}
	memory, err := m.open(request.PID)
	if err != nil {
		return Verification{}, err
	}
	defer memory.Close()

	verifyCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	result := Verification{
		MapID: request.MapID, SourceProcessKey: pointerMap.SourceProcess.Key,
		CurrentProcess: current, CrossProcess: current.Key != pointerMap.SourceProcess.Key,
		TargetAddress: request.TargetAddress,
	}
	if request.TargetAddress != 0 {
		result.TargetAddressHex = fmt.Sprintf("0x%X", request.TargetAddress)
	}
	result.Complete = true
	imageCache := make(map[string]targetidentity.Identity)

	for index, chain := range pointerMap.Chains {
		if err := verifyCtx.Err(); err != nil {
			result.Complete = false
			result.PartialReason = "timeout"
			break
		}
		checked := m.resolveChain(memory, modules, pointerMap.PointerSize, chain, index, request.TargetAddress, imageCache)
		result.CheckedChains++
		if checked.Valid {
			result.ValidChains++
		} else {
			result.InvalidChains++
		}
		if checked.ModuleRelocated {
			result.RelocatedChains++
		}
		if len(result.ChainSample) < request.SampleLimit {
			result.ChainSample = append(result.ChainSample, checked)
		}
	}
	if err := m.revalidate(current); err != nil {
		return Verification{}, err
	}
	return result, nil
}

func (m *Manager) resolveChain(
	memory memscan.ReadOnlyMemory,
	modules []Module,
	pointerSize int,
	chain Chain,
	index int,
	target uint64,
	imageCache map[string]targetidentity.Identity,
) ChainVerification {
	result := ChainVerification{ChainIndex: index, Depth: chain.Depth, Anchor: chain.Anchor}
	module, ok := moduleByPath(modules, chain.Anchor.ModulePath)
	if !ok {
		result.Failure = "anchor module is not loaded"
		return result
	}
	identity, err := m.cachedImage(module.Path, imageCache)
	if err != nil {
		result.Failure = "inspect anchor module: " + err.Error()
		return result
	}
	if identity.SHA256 != chain.Anchor.ModuleSHA256 || identity.Size != chain.Anchor.ModuleFileSize {
		result.Failure = "anchor module file identity changed"
		return result
	}
	if chain.Anchor.RVA >= module.Size {
		result.Failure = "anchor RVA is outside current module"
		return result
	}
	root, overflow := addU64(module.Base, chain.Anchor.RVA)
	if overflow {
		result.Failure = "anchor address overflow"
		return result
	}
	result.CurrentModuleBase = module.Base
	result.CurrentRootAddress = root
	result.CurrentRootHex = fmt.Sprintf("0x%X", root)
	result.ModuleRelocated = module.Base != chain.Anchor.SourceBase

	address := root
	for level, offset := range chain.Offsets {
		region, err := memory.Query(address)
		if err != nil || !readableRegion(region) {
			if err != nil {
				result.Failure = fmt.Sprintf("level %d query: %v", level+1, err)
			} else {
				result.Failure = fmt.Sprintf("level %d slot is not readable", level+1)
			}
			return result
		}
		raw, err := memory.Read(address, pointerSize)
		if err != nil {
			result.Failure = fmt.Sprintf("level %d read: %v", level+1, err)
			return result
		}
		pointerValue := decodePointer(raw, pointerSize)
		next, overflow := addU64(pointerValue, offset)
		if overflow {
			result.Failure = fmt.Sprintf("level %d pointer offset overflow", level+1)
			return result
		}
		result.Steps = append(result.Steps, ResolveStep{
			Level: level + 1, SlotAddress: address, SlotHex: fmt.Sprintf("0x%X", address),
			PointerValue: pointerValue, PointerHex: fmt.Sprintf("0x%X", pointerValue),
			Offset: offset, ResultAddress: next, ResultHex: fmt.Sprintf("0x%X", next),
		})
		address = next
	}
	result.ResolvedAddress = address
	result.ResolvedHex = fmt.Sprintf("0x%X", address)
	result.TargetMatch = target == 0 || address == target
	if !result.TargetMatch {
		result.Failure = fmt.Sprintf("resolved 0x%X does not match target 0x%X", address, target)
		return result
	}
	result.Valid = true
	return result
}

func scanBackrefs(
	ctx context.Context,
	memory memscan.ReadOnlyMemory,
	pointerSize, alignment int,
	startAddress, endAddress, maxOffset, maxBytes uint64,
	targets []searchChain,
	maxNewNodes int,
	maxStateBytes uint64,
) ([]searchChain, DepthStats, bool, string, error) {
	stats := DepthStats{TargetsBefore: len(targets), Complete: true}
	if len(targets) == 0 || maxNewNodes <= 0 {
		return nil, stats, true, "", nil
	}
	sortedTargets := append([]searchChain(nil), targets...)
	sort.SliceStable(sortedTargets, func(i, j int) bool {
		return sortedTargets[i].RootAddress < sortedTargets[j].RootAddress
	})
	result := make([]searchChain, 0, minInt(maxNewNodes, 4096))
	var resultStateBytes uint64
	seen := make(map[string]struct{})
	address := startAddress
	partialReason := ""

	for address < endAddress {
		if err := ctx.Err(); err != nil {
			stats.Complete = false
			partialReason = "timeout"
			break
		}
		region, err := memory.Query(address)
		if err != nil {
			stats.QueryFailures++
			stats.Complete = false
			partialReason = "query_failure"
			break
		}
		stats.RegionsVisited++
		nextRegion := region.EndAddress()
		if nextRegion <= address {
			return nil, DepthStats{}, false, "", errors.New("pointer memory region query did not advance")
		}
		if nextRegion > endAddress {
			nextRegion = endAddress
		}
		if readableRegion(region) {
			cursor := alignUp(maxU64(address, region.BaseAddress), uint64(alignment))
			regionEnd := minU64(nextRegion, region.EndAddress())
			readable := false
			for cursor < regionEnd && regionEnd-cursor >= uint64(pointerSize) {
				if err := ctx.Err(); err != nil {
					stats.Complete = false
					partialReason = "timeout"
					break
				}
				if stats.BytesRead >= maxBytes || maxBytes-stats.BytesRead < uint64(pointerSize) {
					stats.Complete = false
					partialReason = "max_bytes"
					break
				}
				readLen := minU64(readChunkSize, regionEnd-cursor)
				remaining := maxBytes - stats.BytesRead
				if readLen > remaining {
					readLen = remaining
				}
				if readLen < uint64(pointerSize) {
					stats.Complete = false
					partialReason = "max_bytes"
					break
				}
				raw, readErr := memory.Read(cursor, int(readLen))
				if readErr != nil {
					stats.UnreadableRegions++
					stats.Complete = false
					partialReason = "unreadable_region"
					break
				}
				readable = true
				stats.BytesRead += uint64(len(raw))
				lastOffset := len(raw) - pointerSize
				for offset := 0; offset <= lastOffset; offset += alignment {
					stats.PointerValuesExamined++
					slot := cursor + uint64(offset)
					value := decodePointer(raw[offset:offset+pointerSize], pointerSize)
					first := sort.Search(len(sortedTargets), func(i int) bool {
						return sortedTargets[i].RootAddress >= value
					})
					var maxTarget uint64
					if value <= ^uint64(0)-maxOffset {
						maxTarget = value + maxOffset
					} else {
						maxTarget = ^uint64(0)
					}
					for index := first; index < len(sortedTargets); index++ {
						target := sortedTargets[index]
						if target.RootAddress > maxTarget {
							break
						}
						if target.RootAddress < value || slot == target.RootAddress || containsAddress(target.Slots, slot) {
							continue
						}
						delta := target.RootAddress - value
						candidate := searchChain{
							RootAddress: slot,
							Offsets:     append([]uint64{delta}, target.Offsets...),
							Slots:       append([]uint64{slot}, target.Slots...),
						}
						key := searchKey(candidate)
						if _, exists := seen[key]; exists {
							continue
						}
						seen[key] = struct{}{}
						cost := estimateSearchChainStateBytes(candidate)
						if !fitsPointerStateBudget(resultStateBytes, cost, maxStateBytes) {
							stats.Complete = false
							partialReason = "max_state_bytes"
							break
						}
						resultStateBytes += cost
						result = append(result, candidate)
						if len(result) >= maxNewNodes {
							stats.Complete = false
							partialReason = "max_nodes"
							break
						}
					}
					if partialReason == "max_nodes" || partialReason == "max_state_bytes" {
						break
					}
				}
				if partialReason != "" {
					break
				}
				advance := uint64(len(raw))
				overlap := uint64(pointerSize - alignment)
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
		address = nextRegion
	}
	stats.NodesAfter = len(result)
	stats.PartialReason = partialReason
	return result, stats, stats.Complete, partialReason, nil
}

func (m *Manager) anchorFor(module Module, address uint64, cache map[string]targetidentity.Identity) (ModuleAnchor, error) {
	identity, err := m.cachedImage(module.Path, cache)
	if err != nil {
		return ModuleAnchor{}, fmt.Errorf("inspect pointer root module %s: %w", module.Path, err)
	}
	return ModuleAnchor{
		ModulePath: identity.Path, ModuleSHA256: identity.SHA256, ModuleFileSize: identity.Size,
		SourceBase: module.Base, ModuleSize: module.Size, RVA: address - module.Base,
	}, nil
}

func (m *Manager) cachedImage(path string, cache map[string]targetidentity.Identity) (targetidentity.Identity, error) {
	key := strings.ToLower(filepath.Clean(path))
	if identity, ok := cache[key]; ok {
		return identity, nil
	}
	identity, err := m.inspectImage(path)
	if err != nil {
		return targetidentity.Identity{}, err
	}
	cache[key] = identity
	return identity, nil
}

func pointerArchitecture(identity processcontrol.Identity) (int, uint64, error) {
	if identity.Image.PE == nil {
		return 0, 0, errors.New("pointer mapping requires a PE process")
	}
	switch {
	case identity.Image.PE.Bits == 32 && strings.EqualFold(identity.Image.PE.Machine, "i386"):
		return 4, uint64(1) << 32, nil
	case identity.Image.PE.Bits == 64 && strings.EqualFold(identity.Image.PE.Machine, "amd64"):
		return 8, uint64(0x0000800000000000), nil
	default:
		return 0, 0, fmt.Errorf("unsupported pointer architecture machine=%s bits=%d", identity.Image.PE.Machine, identity.Image.PE.Bits)
	}
}

func readableRegion(region memscan.RegionIdentity) bool {
	return region.State == memoryCommit && region.Protect&pageGuard == 0 && region.Protect&pageNoAccess == 0
}

func moduleContaining(modules []Module, address uint64) (Module, bool) {
	for _, module := range modules {
		if address >= module.Base && address-module.Base < module.Size {
			return module, true
		}
	}
	return Module{}, false
}

func moduleByPath(modules []Module, path string) (Module, bool) {
	want := filepath.Clean(path)
	for _, module := range modules {
		if strings.EqualFold(filepath.Clean(module.Path), want) {
			return module, true
		}
	}
	return Module{}, false
}

func decodePointer(raw []byte, pointerSize int) uint64 {
	if pointerSize == 4 {
		return uint64(binary.LittleEndian.Uint32(raw))
	}
	return binary.LittleEndian.Uint64(raw)
}

func containsAddress(values []uint64, value uint64) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func searchKey(chain searchChain) string {
	builder := strings.Builder{}
	builder.WriteString(strconv.FormatUint(chain.RootAddress, 16))
	for _, offset := range chain.Offsets {
		builder.WriteByte(':')
		builder.WriteString(strconv.FormatUint(offset, 16))
	}
	return builder.String()
}

func chainKey(chain Chain) string {
	builder := strings.Builder{}
	builder.WriteString(chain.Anchor.ModuleSHA256)
	builder.WriteByte(':')
	builder.WriteString(strconv.FormatUint(chain.Anchor.RVA, 16))
	for _, offset := range chain.Offsets {
		builder.WriteByte(':')
		builder.WriteString(strconv.FormatUint(offset, 16))
	}
	return builder.String()
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

func (m *Manager) saveNew(ctx context.Context, pointerMap Map) (err error) {
	storeRelease, err := recordio.AcquireContext(ctx, m.storeLockPath(), 10*time.Second)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, storeRelease()) }()

	if err := m.ensureNewMapCapacity(); err != nil {
		return err
	}
	lockPath := m.lockPath(pointerMap.ID)
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		return err
	}
	release, err := recordio.AcquireContext(ctx, lockPath, 10*time.Second)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, release()) }()

	if _, err := os.Stat(m.mapPath(pointerMap.ID)); err == nil {
		return errors.New("pointer map id collision")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if _, err := os.Stat(m.legacyMapPath(pointerMap.ID)); err == nil {
		return errors.New("pointer map id collision")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	path := m.mapPath(pointerMap.ID)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return recordio.WriteStream(path, 0o600, func(writer io.Writer) error {
		return json.NewEncoder(&persistedMapLimitWriter{inner: writer, limit: MaxPersistedMapBytes}).Encode(pointerMap)
	})
}

// persistedMapLimitWriter stops encoding before a map grows past the size the
// read path is willing to open again, so a build can never publish state that
// is unopenable for refine or verify.
type persistedMapLimitWriter struct {
	inner   io.Writer
	written int64
	limit   int64
}

func (w *persistedMapLimitWriter) Write(p []byte) (int, error) {
	if w.written+int64(len(p)) > w.limit {
		return 0, fmt.Errorf("persisted pointer map would exceed state limit: %d > %d", w.written+int64(len(p)), w.limit)
	}
	n, err := w.inner.Write(p)
	w.written += int64(n)
	return n, err
}

func (m *Manager) load(mapID string) (Map, error) {
	file, err := os.Open(m.mapPath(mapID))
	if errors.Is(err, os.ErrNotExist) {
		file, err = os.Open(m.legacyMapPath(mapID))
	}
	if err != nil {
		return Map{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return Map{}, err
	}
	if info.Size() > MaxPersistedMapBytes {
		return Map{}, fmt.Errorf("persisted pointer map exceeds state limit: %d > %d", info.Size(), MaxPersistedMapBytes)
	}
	var pointerMap Map
	if err := json.NewDecoder(file).Decode(&pointerMap); err != nil {
		return Map{}, fmt.Errorf("decode pointer map %s: %w", mapID, err)
	}
	if pointerMap.ID != mapID || pointerMap.Version != 1 || pointerMap.SourceProcess.Key == "" ||
		(pointerMap.PointerSize != 4 && pointerMap.PointerSize != 8) {
		return Map{}, errors.New("invalid persisted pointer map")
	}
	if used := estimateChainSliceBytes(pointerMap.Chains); used > MaxChainStateBytes {
		return Map{}, fmt.Errorf("persisted pointer map chain state exceeds limit: %d > %d", used, MaxChainStateBytes)
	}
	return pointerMap, nil
}

func mapShard(mapID string) string {
	value := strings.TrimPrefix(mapID, "pmap_")
	if len(value) >= 2 {
		return value[:2]
	}
	return "00"
}

func (m *Manager) mapPath(mapID string) string {
	return filepath.Join(m.dir, "data", mapShard(mapID), mapID+".json")
}

func (m *Manager) legacyMapPath(mapID string) string {
	return filepath.Join(m.dir, mapID+".json")
}

func (m *Manager) lockPath(mapID string) string {
	return filepath.Join(m.dir, "locks", mapShard(mapID), mapID+".lock")
}

func (m *Manager) storeLockPath() string {
	return filepath.Join(m.dir, ".store.lock")
}

func validMapID(mapID string) bool {
	return mapIDPattern.MatchString(strings.TrimSpace(mapID))
}

func newMapID() (string, error) {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "pmap_" + hex.EncodeToString(raw[:]), nil
}

func addU64(left, right uint64) (uint64, bool) {
	if left > ^uint64(0)-right {
		return 0, true
	}
	return left + right, false
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

func firstReason(current, candidate string) string {
	if current != "" {
		return current
	}
	return candidate
}
