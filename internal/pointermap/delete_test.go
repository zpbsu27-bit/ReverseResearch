package pointermap

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestDeleteRequiresCurrentVersionAndReleasesMapState(t *testing.T) {
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
	manager := fakePointerManager(t, t.TempDir(), env)
	pointerMap, err := manager.Build(context.Background(), BuildRequest{
		PID: env.identity.PID, ProcessKey: env.identity.Key, TargetAddress: target,
		StartAddress: sourceBase, EndAddress: sourceBase + 0x100,
		MaxOffset: 0x40, MaxDepth: 2, Alignment: 8,
		MaxBytes: 4096, MaxNodes: 100, MaxChains: 100,
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := manager.Delete(context.Background(), DeleteRequest{
		MapID: pointerMap.ID, ExpectedVersion: pointerMap.Version + 1,
	}); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("stale delete err=%v want ErrVersionConflict", err)
	}
	if _, err := manager.Get(pointerMap.ID, 1); err != nil {
		t.Fatalf("stale delete removed pointer map: %v", err)
	}

	deleted, err := manager.Delete(context.Background(), DeleteRequest{
		MapID: pointerMap.ID, ExpectedVersion: pointerMap.Version,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !deleted.Deleted || deleted.MapID != pointerMap.ID || deleted.Version != pointerMap.Version {
		t.Fatalf("delete result=%+v", deleted)
	}
	if _, err := manager.Get(pointerMap.ID, 1); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("deleted pointer map Get err=%v want not-exist", err)
	}
}
