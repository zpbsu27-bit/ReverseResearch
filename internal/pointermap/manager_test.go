package pointermap

import (
	"context"
	"encoding/binary"
	"errors"
	"path/filepath"
	"testing"

	"reverseresearch/internal/memscan"
	"reverseresearch/internal/processcontrol"
	"reverseresearch/internal/targetidentity"
)

type fakePointerMemory struct {
	region memscan.RegionIdentity
	data   []byte
}

func (m *fakePointerMemory) Query(address uint64) (memscan.RegionIdentity, error) {
	if address < m.region.BaseAddress || address >= m.region.EndAddress() {
		return memscan.RegionIdentity{}, errors.New("address outside fake pointer region")
	}
	return m.region, nil
}

func (m *fakePointerMemory) Read(address uint64, size int) ([]byte, error) {
	if address < m.region.BaseAddress {
		return nil, errors.New("read before fake region")
	}
	offset := address - m.region.BaseAddress
	if offset > uint64(len(m.data)) || uint64(size) > uint64(len(m.data))-offset {
		return nil, errors.New("read outside fake region")
	}
	return append([]byte(nil), m.data[offset:offset+uint64(size)]...), nil
}

func (m *fakePointerMemory) Close() error { return nil }

type pointerFixtureEnv struct {
	identity  processcontrol.Identity
	memory    *fakePointerMemory
	module    Module
	moduleSHA string
}

func fakePointerIdentity(key string, moduleBase uint64, creation int64) processcontrol.Identity {
	return processcontrol.Identity{
		PID: 91, CreationUTC: "2026-10-02T00:00:00Z", CreationUnixNano: creation,
		MainModuleBase: moduleBase,
		Image: targetidentity.Identity{
			Path:   "C:\\fixture.exe",
			SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Size:   4096, Format: "pe",
			PE: &targetidentity.PEIdentity{Machine: "amd64", Bits: 64},
		},
		Key: key,
	}
}

func pointerMemory(base, target uint64) *fakePointerMemory {
	data := make([]byte, 0x100)
	rootSlot := base + 0x20
	midSlot := base + 0x40
	binary.LittleEndian.PutUint64(data[rootSlot-base:], midSlot-0x10)
	binary.LittleEndian.PutUint64(data[midSlot-base:], target-0x20)
	return &fakePointerMemory{
		region: memscan.RegionIdentity{
			BaseAddress: base, AllocationBase: base, AllocationProtect: 0x04,
			RegionSize: uint64(len(data)), State: memoryCommit, Protect: 0x04, Type: 0x20000,
		},
		data: data,
	}
}

func fakePointerManager(t *testing.T, dir string, env *pointerFixtureEnv) *Manager {
	t.Helper()
	manager, err := newManagerForTest(
		dir,
		func(pid uint32) (processcontrol.Identity, error) {
			if pid != env.identity.PID {
				return processcontrol.Identity{}, errors.New("unexpected pid")
			}
			return env.identity, nil
		},
		func(expected processcontrol.Identity) (processcontrol.Identity, error) {
			if !processcontrol.SameInstance(expected, env.identity) {
				return processcontrol.Identity{}, processcontrol.ErrProcessChanged
			}
			return env.identity, nil
		},
		func(pid uint32) (memscan.ReadOnlyMemory, error) {
			if pid != env.identity.PID {
				return nil, errors.New("unexpected pid")
			}
			return env.memory, nil
		},
		func(pid uint32) ([]Module, error) {
			if pid != env.identity.PID {
				return nil, errors.New("unexpected pid")
			}
			return []Module{env.module}, nil
		},
		func(path string) (targetidentity.Identity, error) {
			return targetidentity.Identity{
				Path: path, SHA256: env.moduleSHA, Size: 4096, Format: "pe",
				PE: &targetidentity.PEIdentity{Machine: "amd64", Bits: 64},
			}, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func TestBuildFindsModuleAnchoredDepthTwoChain(t *testing.T) {
	const sourceBase = uint64(0x1000)
	const target = uint64(0x10f0)
	env := &pointerFixtureEnv{
		identity: fakePointerIdentity(
			"1111111111111111111111111111111111111111111111111111111111111111",
			sourceBase, 100,
		),
		memory:    pointerMemory(sourceBase, target),
		module:    Module{Path: "C:\\fixture.exe", Base: sourceBase, Size: 0x1000},
		moduleSHA: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	root := t.TempDir()
	manager := fakePointerManager(t, root, env)
	result, err := manager.Build(context.Background(), BuildRequest{
		PID: env.identity.PID, ProcessKey: env.identity.Key, TargetAddress: target,
		StartAddress: sourceBase, EndAddress: sourceBase + 0x100,
		MaxOffset: 0x40, MaxDepth: 2, Alignment: 8,
		MaxBytes: 4096, MaxNodes: 100, MaxChains: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Version != 1 || !result.CoverageComplete || result.ChainCount < 2 {
		t.Fatalf("result=%+v", result)
	}
	var depthTwo *Chain
	for index := range result.ChainSample {
		if result.ChainSample[index].Depth == 2 {
			depthTwo = &result.ChainSample[index]
			break
		}
	}
	if depthTwo == nil {
		t.Fatalf("no depth-two chain: %+v", result.ChainSample)
	}
	if depthTwo.Anchor.RVA != 0x20 || len(depthTwo.Offsets) != 2 ||
		depthTwo.Offsets[0] != 0x10 || depthTwo.Offsets[1] != 0x20 {
		t.Fatalf("depth-two chain=%+v", *depthTwo)
	}
	reopened := fakePointerManager(t, filepath.Clean(root), env)
	stored, err := reopened.Get(result.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if stored.ID != result.ID || stored.ChainCount != result.ChainCount {
		t.Fatalf("stored=%+v result=%+v", stored, result)
	}
}

func TestVerifyRebasesModuleAnchorAcrossProcessRestart(t *testing.T) {
	const sourceBase = uint64(0x1000)
	const sourceTarget = uint64(0x10f0)
	env := &pointerFixtureEnv{
		identity: fakePointerIdentity(
			"1111111111111111111111111111111111111111111111111111111111111111",
			sourceBase, 100,
		),
		memory:    pointerMemory(sourceBase, sourceTarget),
		module:    Module{Path: "C:\\fixture.exe", Base: sourceBase, Size: 0x1000},
		moduleSHA: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	manager := fakePointerManager(t, t.TempDir(), env)
	built, err := manager.Build(context.Background(), BuildRequest{
		PID: env.identity.PID, ProcessKey: env.identity.Key, TargetAddress: sourceTarget,
		StartAddress: sourceBase, EndAddress: sourceBase + 0x100,
		MaxOffset: 0x40, MaxDepth: 2, Alignment: 8,
		MaxBytes: 4096, MaxNodes: 100, MaxChains: 100,
	})
	if err != nil {
		t.Fatal(err)
	}

	const currentBase = uint64(0x5000)
	const currentTarget = uint64(0x50f0)
	env.identity = fakePointerIdentity(
		"2222222222222222222222222222222222222222222222222222222222222222",
		currentBase, 200,
	)
	env.memory = pointerMemory(currentBase, currentTarget)
	env.module = Module{Path: "C:\\fixture.exe", Base: currentBase, Size: 0x1000}

	verified, err := manager.Verify(context.Background(), VerifyRequest{
		MapID: built.ID, PID: env.identity.PID, ProcessKey: env.identity.Key,
		TargetAddress: currentTarget, SampleLimit: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !verified.CrossProcess || verified.CheckedChains < 2 || verified.ValidChains != verified.CheckedChains ||
		verified.RelocatedChains != verified.CheckedChains || !verified.Complete {
		t.Fatalf("verified=%+v", verified)
	}
	var depthTwo *ChainVerification
	for index := range verified.ChainSample {
		if verified.ChainSample[index].Depth == 2 {
			depthTwo = &verified.ChainSample[index]
			break
		}
	}
	if depthTwo == nil || !depthTwo.Valid || !depthTwo.TargetMatch ||
		depthTwo.CurrentRootAddress != currentBase+0x20 || depthTwo.ResolvedAddress != currentTarget {
		t.Fatalf("depth-two verification=%+v", depthTwo)
	}
}

func TestVerifyRejectsStaleRequestAndReportsAllocationDrift(t *testing.T) {
	const base = uint64(0x1000)
	const target = uint64(0x10f0)
	env := &pointerFixtureEnv{
		identity: fakePointerIdentity(
			"1111111111111111111111111111111111111111111111111111111111111111",
			base, 100,
		),
		memory:    pointerMemory(base, target),
		module:    Module{Path: "C:\\fixture.exe", Base: base, Size: 0x1000},
		moduleSHA: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	manager := fakePointerManager(t, t.TempDir(), env)
	built, err := manager.Build(context.Background(), BuildRequest{
		PID: env.identity.PID, ProcessKey: env.identity.Key, TargetAddress: target,
		StartAddress: base, EndAddress: base + 0x100,
		MaxOffset: 0x40, MaxDepth: 2, MaxBytes: 4096, MaxNodes: 100, MaxChains: 100,
	})
	if err != nil {
		t.Fatal(err)
	}

	env.identity = fakePointerIdentity(
		"3333333333333333333333333333333333333333333333333333333333333333",
		base, 300,
	)
	if _, err := manager.Verify(context.Background(), VerifyRequest{
		MapID: built.ID, PID: env.identity.PID,
		ProcessKey: built.SourceProcess.Key, TargetAddress: target,
	}); !errors.Is(err, ErrProcessChanged) {
		t.Fatalf("stale process key err=%v", err)
	}

	env.memory = pointerMemory(base, target)
	binary.LittleEndian.PutUint64(env.memory.data[0x40:], 0x7777)
	verified, err := manager.Verify(context.Background(), VerifyRequest{
		MapID: built.ID, PID: env.identity.PID, ProcessKey: env.identity.Key,
		TargetAddress: target, SampleLimit: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if verified.InvalidChains == 0 || verified.ValidChains == verified.CheckedChains {
		t.Fatalf("allocation drift was not reported: %+v", verified)
	}
}

func TestVerifyRejectsChangedAnchorModuleIdentity(t *testing.T) {
	const base = uint64(0x1000)
	const target = uint64(0x10f0)
	env := &pointerFixtureEnv{
		identity: fakePointerIdentity(
			"1111111111111111111111111111111111111111111111111111111111111111",
			base, 100,
		),
		memory:    pointerMemory(base, target),
		module:    Module{Path: "C:\\fixture.exe", Base: base, Size: 0x1000},
		moduleSHA: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	manager := fakePointerManager(t, t.TempDir(), env)
	built, err := manager.Build(context.Background(), BuildRequest{
		PID: env.identity.PID, ProcessKey: env.identity.Key, TargetAddress: target,
		StartAddress: base, EndAddress: base + 0x100,
		MaxOffset: 0x40, MaxDepth: 1, MaxBytes: 4096, MaxNodes: 100, MaxChains: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	env.moduleSHA = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	verified, err := manager.Verify(context.Background(), VerifyRequest{
		MapID: built.ID, PID: env.identity.PID, ProcessKey: env.identity.Key,
		TargetAddress: target, SampleLimit: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if verified.ValidChains != 0 || verified.InvalidChains == 0 {
		t.Fatalf("module drift was not rejected: %+v", verified)
	}
	for _, chain := range verified.ChainSample {
		if chain.Failure != "anchor module file identity changed" {
			t.Fatalf("unexpected failure: %+v", chain)
		}
	}
}

func TestDecodePointerWidths(t *testing.T) {
	raw := make([]byte, 8)
	binary.LittleEndian.PutUint32(raw, 0x12345678)
	if got := decodePointer(raw[:4], 4); got != 0x12345678 {
		t.Fatalf("32-bit pointer=%x", got)
	}
	binary.LittleEndian.PutUint64(raw, 0x123456789abcdef0)
	if got := decodePointer(raw, 8); got != 0x123456789abcdef0 {
		t.Fatalf("64-bit pointer=%x", got)
	}
}
