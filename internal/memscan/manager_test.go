package memscan

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"reverseresearch/internal/processcontrol"
	"reverseresearch/internal/targetidentity"
)

type fakeMemory struct {
	region    RegionIdentity
	data      []byte
	failReads bool
}

func (m *fakeMemory) Query(address uint64) (RegionIdentity, error) {
	if address < m.region.BaseAddress || address >= m.region.EndAddress() {
		return RegionIdentity{}, fmt.Errorf("address 0x%X outside fake region", address)
	}
	return m.region, nil
}

func (m *fakeMemory) Read(address uint64, size int) ([]byte, error) {
	if m.failReads {
		return nil, errors.New("simulated unreadable region")
	}
	if address < m.region.BaseAddress {
		return nil, errors.New("read before fake region")
	}
	offset := address - m.region.BaseAddress
	if offset > uint64(len(m.data)) || uint64(size) > uint64(len(m.data))-offset {
		return nil, errors.New("read outside fake region")
	}
	return append([]byte(nil), m.data[offset:offset+uint64(size)]...), nil
}

func (m *fakeMemory) Close() error { return nil }

func fakeProcessIdentity() processcontrol.Identity {
	return processcontrol.Identity{
		PID: 77, CreationUTC: "2026-10-02T00:00:00Z", CreationUnixNano: 1234,
		MainModuleBase: 0x400000,
		Image: targetidentity.Identity{
			Path: "C:\\fake.exe", SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Size: 4096, Format: "pe", PE: &targetidentity.PEIdentity{Machine: "amd64", Bits: 64},
		},
		Key: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
}

func fakeU32Memory(values ...uint32) *fakeMemory {
	data := make([]byte, len(values)*4)
	for index, value := range values {
		binary.LittleEndian.PutUint32(data[index*4:], value)
	}
	return &fakeMemory{
		region: RegionIdentity{
			BaseAddress: 0x1000, AllocationBase: 0x1000, AllocationProtect: 0x04,
			RegionSize: uint64(len(data)), State: memoryCommit, Protect: 0x04, Type: 0x20000,
		},
		data: data,
	}
}

func fakeManager(t *testing.T, dir string, memory *fakeMemory) *Manager {
	t.Helper()
	identity := fakeProcessIdentity()
	manager, err := newManagerForTest(
		dir,
		func(pid uint32) (processcontrol.Identity, error) {
			if pid != identity.PID {
				return processcontrol.Identity{}, errors.New("unexpected pid")
			}
			return identity, nil
		},
		func(expected processcontrol.Identity) (processcontrol.Identity, error) {
			if !processcontrol.SameInstance(expected, identity) {
				return processcontrol.Identity{}, processcontrol.ErrProcessChanged
			}
			return identity, nil
		},
		func(pid uint32) (processMemory, error) {
			if pid != identity.PID {
				return nil, errors.New("unexpected pid")
			}
			return memory, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func startU32(t *testing.T, manager *Manager, mode Mode, value string, maxCandidates int) Summary {
	t.Helper()
	identity := fakeProcessIdentity()
	result, err := manager.Start(context.Background(), StartRequest{
		PID: identity.PID, ProcessKey: identity.Key, ValueType: "u32", Mode: mode, Value: value,
		StartAddress: 0x1000, EndAddress: 0x1010, Alignment: 4,
		MaxBytes: 4096, MaxCandidates: maxCandidates,
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestStartExactAndPersistedSummary(t *testing.T) {
	root := t.TempDir()
	memory := fakeU32Memory(10, 20, 30, 40)
	manager := fakeManager(t, root, memory)
	result := startU32(t, manager, ModeExact, "20", 100)
	if result.Version != 1 || result.CandidateCount != 1 || !result.CoverageComplete || !result.StepComplete {
		t.Fatalf("result=%+v", result)
	}
	if got := result.CandidateSample[0]; got.Address != 0x1004 || got.Value != "20" || got.AddressHex != "0x1004" {
		t.Fatalf("candidate=%+v", got)
	}
	reopened := fakeManager(t, filepath.Clean(root), memory)
	stored, err := reopened.Get(result.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if stored.ID != result.ID || stored.CandidateCount != 1 || stored.Version != 1 {
		t.Fatalf("stored=%+v", stored)
	}
}

func TestUnknownScanRefinesChangedUnchangedIncreasedDecreasedAndExact(t *testing.T) {
	root := t.TempDir()
	memory := fakeU32Memory(10, 20, 30, 40)
	manager := fakeManager(t, root, memory)

	changed := startU32(t, manager, ModeUnknown, "", 100)
	increased := startU32(t, manager, ModeUnknown, "", 100)
	decreased := startU32(t, manager, ModeUnknown, "", 100)
	unchanged := startU32(t, manager, ModeUnknown, "", 100)
	for _, scan := range []Summary{changed, increased, decreased, unchanged} {
		if scan.CandidateCount != 4 {
			t.Fatalf("initial scan=%+v", scan)
		}
	}

	binary.LittleEndian.PutUint32(memory.data[4:], 25)
	binary.LittleEndian.PutUint32(memory.data[8:], 29)

	changed2, err := manager.Refine(context.Background(), RefineRequest{ScanID: changed.ID, ExpectedVersion: 1, Mode: ModeChanged})
	if err != nil || changed2.CandidateCount != 2 {
		t.Fatalf("changed=%+v err=%v", changed2, err)
	}
	increased2, err := manager.Refine(context.Background(), RefineRequest{ScanID: increased.ID, ExpectedVersion: 1, Mode: ModeIncreased})
	if err != nil || increased2.CandidateCount != 1 || increased2.CandidateSample[0].Address != 0x1004 {
		t.Fatalf("increased=%+v err=%v", increased2, err)
	}
	decreased2, err := manager.Refine(context.Background(), RefineRequest{ScanID: decreased.ID, ExpectedVersion: 1, Mode: ModeDecreased})
	if err != nil || decreased2.CandidateCount != 1 || decreased2.CandidateSample[0].Address != 0x1008 {
		t.Fatalf("decreased=%+v err=%v", decreased2, err)
	}
	unchanged2, err := manager.Refine(context.Background(), RefineRequest{ScanID: unchanged.ID, ExpectedVersion: 1, Mode: ModeUnchanged})
	if err != nil || unchanged2.CandidateCount != 2 {
		t.Fatalf("unchanged=%+v err=%v", unchanged2, err)
	}
	exact3, err := manager.Refine(context.Background(), RefineRequest{ScanID: unchanged.ID, ExpectedVersion: 2, Mode: ModeExact, Value: "40"})
	if err != nil || exact3.CandidateCount != 1 || exact3.CandidateSample[0].Address != 0x100c || exact3.Version != 3 {
		t.Fatalf("exact=%+v err=%v", exact3, err)
	}
	if _, err := manager.Refine(context.Background(), RefineRequest{ScanID: unchanged.ID, ExpectedVersion: 1, Mode: ModeUnchanged}); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("stale version err=%v", err)
	}
}

func TestCandidateLimitMarksCoveragePartialButKeepsRefinementSafe(t *testing.T) {
	memory := fakeU32Memory(10, 20, 30, 40)
	manager := fakeManager(t, t.TempDir(), memory)
	result := startU32(t, manager, ModeUnknown, "", 2)
	if result.CandidateCount != 2 || result.CoverageComplete || !result.StepComplete || result.PartialReason != "max_candidates" {
		t.Fatalf("result=%+v", result)
	}
	refined, err := manager.Refine(context.Background(), RefineRequest{
		ScanID: result.ID, ExpectedVersion: 1, Mode: ModeUnchanged,
	})
	if err != nil || refined.CandidateCount != 2 || !refined.StepComplete {
		t.Fatalf("refined=%+v err=%v", refined, err)
	}
	if refined.CoverageComplete {
		t.Fatal("refinement must not upgrade partial initial coverage")
	}
}

func TestRefineDropsCandidatesWhenRegionIdentityChanges(t *testing.T) {
	memory := fakeU32Memory(10, 20, 30, 40)
	manager := fakeManager(t, t.TempDir(), memory)
	result := startU32(t, manager, ModeUnknown, "", 100)
	memory.region.Protect = 0x20
	refined, err := manager.Refine(context.Background(), RefineRequest{
		ScanID: result.ID, ExpectedVersion: 1, Mode: ModeUnchanged,
	})
	if err != nil {
		t.Fatal(err)
	}
	if refined.CandidateCount != 0 || refined.History[len(refined.History)-1].StaleRegionCandidates != 4 {
		t.Fatalf("refined=%+v", refined)
	}
}

func TestUnreadableRegionProducesExplicitPartialResult(t *testing.T) {
	memory := fakeU32Memory(10, 20, 30, 40)
	memory.failReads = true
	manager := fakeManager(t, t.TempDir(), memory)
	result := startU32(t, manager, ModeUnknown, "", 100)
	if result.CoverageComplete || !result.StepComplete || result.PartialReason != "unreadable_region" {
		t.Fatalf("result=%+v", result)
	}
	if len(result.History) != 1 || result.History[0].UnreadableRegions != 1 || result.History[0].Complete {
		t.Fatalf("history=%+v", result.History)
	}
}

func TestStartRejectsWrongProcessKey(t *testing.T) {
	memory := fakeU32Memory(10, 20, 30, 40)
	manager := fakeManager(t, t.TempDir(), memory)
	_, err := manager.Start(context.Background(), StartRequest{
		PID: 77, ProcessKey: "wrong", ValueType: "u32", Mode: ModeUnknown,
		StartAddress: 0x1000, EndAddress: 0x1010, MaxBytes: 4096, MaxCandidates: 100,
	})
	if !errors.Is(err, ErrProcessChanged) {
		t.Fatalf("err=%v", err)
	}
}
