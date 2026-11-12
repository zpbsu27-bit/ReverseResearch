package hookplan

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"reverseresearch/internal/targetidentity"
)

func hookFixture(t *testing.T) (string, string, targetidentity.Identity) {
	t.Helper()
	root := filepath.Clean(filepath.Join("..", ".."))
	source := filepath.Join(root, "testdata", "mcp-smoke.exe")
	target := filepath.Join(t.TempDir(), "hook-fixture.exe")
	if err := copyFile(source, target); err != nil {
		t.Fatal(err)
	}
	identity, err := targetidentity.Inspect(target)
	if err != nil {
		t.Fatal(err)
	}
	if identity.PE == nil || identity.PE.EntryPointRVA == 0 {
		t.Fatalf("fixture identity=%+v", identity)
	}
	return root, target, identity
}

func newHookManager(t *testing.T, root string, afterEffect func(string) error) *Manager {
	t.Helper()
	manager, err := newManagerForTest(root, filepath.Join(t.TempDir(), "state", "hooks"), afterEffect)
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func planEntryHook(t *testing.T, manager *Manager, target string, identity targetidentity.Identity) Hook {
	t.Helper()
	hook, err := manager.Plan(context.Background(), PlanRequest{
		Path:           target,
		SourceRVA:      uint64(identity.PE.EntryPointRVA),
		DestinationRVA: uint64(identity.PE.EntryPointRVA) + 0x30,
		Description:    "entry detour test",
	})
	if err != nil {
		t.Fatal(err)
	}
	return hook
}

func TestPlanUsesWholeInstructionBoundaryAndRel32RVA(t *testing.T) {
	root, target, identity := hookFixture(t)
	manager := newHookManager(t, root, nil)
	hook := planEntryHook(t, manager, target, identity)

	if hook.State != StatePlanned || hook.Version != 1 || hook.Relocation != "same-module-rva-rel32" {
		t.Fatalf("hook=%+v", hook)
	}
	if hook.OverwriteSize != 7 || len(hook.Instructions) != 2 {
		t.Fatalf("whole-instruction proof=%+v", hook.Instructions)
	}
	if hook.Instructions[0].Size != 2 || hook.Instructions[1].Size != 5 ||
		hook.Instructions[0].RVA != hook.SourceRVA || hook.Instructions[1].RVA != hook.SourceRVA+2 {
		t.Fatalf("instructions=%+v", hook.Instructions)
	}
	patch, err := hex.DecodeString(hook.PatchHex)
	if err != nil {
		t.Fatal(err)
	}
	if len(patch) != hook.OverwriteSize || patch[0] != 0xE9 || patch[5] != 0x90 || patch[6] != 0x90 {
		t.Fatalf("patch=%x", patch)
	}
	stored, err := manager.Get(hook.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.ID != hook.ID || stored.SourceFileOffset != hook.SourceFileOffset {
		t.Fatalf("stored=%+v", stored)
	}
}

func TestPlanRejectsMidInstructionAndWrongOriginalBytes(t *testing.T) {
	root, target, identity := hookFixture(t)
	manager := newHookManager(t, root, nil)
	source := uint64(identity.PE.EntryPointRVA)

	if _, err := manager.Plan(context.Background(), PlanRequest{
		Path:           target,
		SourceRVA:      source + 1,
		DestinationRVA: source + 0x30,
	}); err == nil {
		t.Fatal("mid-instruction hook source was accepted")
	}
	if _, err := manager.Plan(context.Background(), PlanRequest{
		Path:           target,
		SourceRVA:      source,
		DestinationRVA: source + 0x30,
		ExpectedHex:    "90 90 90 90 90 90 90",
	}); !errors.Is(err, ErrWrongOriginalBytes) {
		t.Fatalf("wrong expected bytes err=%v", err)
	}
}

func TestIntervalConflictCancelAndAdjacentPlan(t *testing.T) {
	root, target, identity := hookFixture(t)
	manager := newHookManager(t, root, nil)
	first := planEntryHook(t, manager, target, identity)
	source := uint64(identity.PE.EntryPointRVA)

	if _, err := manager.Plan(context.Background(), PlanRequest{
		Path:           target,
		SourceRVA:      source + 2,
		DestinationRVA: source + 0x30,
		Description:    "overlap",
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("overlap err=%v", err)
	}

	cancelled, err := manager.Cancel(CancelRequest{HookID: first.ID, ExpectedVersion: first.Version})
	if err != nil {
		t.Fatal(err)
	}
	if cancelled.State != StateCancelled || cancelled.Version != 2 {
		t.Fatalf("cancelled=%+v", cancelled)
	}
	overlapAfterCancel, err := manager.Plan(context.Background(), PlanRequest{
		Path:           target,
		SourceRVA:      source + 2,
		DestinationRVA: source + 0x30,
		Description:    "overlap",
	})
	if err != nil {
		t.Fatal(err)
	}
	if overlapAfterCancel.SourceRVA != source+2 {
		t.Fatalf("replanned=%+v", overlapAfterCancel)
	}

	adjacentManager := newHookManager(t, root, nil)
	adjacentFirst := planEntryHook(t, adjacentManager, target, identity)
	adjacent, err := adjacentManager.Plan(context.Background(), PlanRequest{
		Path:           target,
		SourceRVA:      source + uint64(adjacentFirst.OverwriteSize),
		DestinationRVA: source + 0x30,
		Description:    "adjacent",
	})
	if err != nil {
		t.Fatal(err)
	}
	if adjacent.SourceRVA != source+uint64(adjacentFirst.OverwriteSize) {
		t.Fatalf("adjacent=%+v", adjacent)
	}
}

func TestApplyVerifyRollbackAndWrongByteRejection(t *testing.T) {
	root, target, identity := hookFixture(t)
	manager := newHookManager(t, root, nil)
	originalFile, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	hook := planEntryHook(t, manager, target, identity)

	applied, err := manager.Apply(ApplyRequest{
		HookID:          hook.ID,
		ExpectedVersion: hook.Version,
		OperationID:     "apply-entry-1",
		ConfirmInPlace:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if applied.State != StateApplied || applied.Version != 3 {
		t.Fatalf("applied=%+v", applied)
	}
	verifyApplied, err := manager.Verify(hook.ID)
	if err != nil {
		t.Fatal(err)
	}
	if verifyApplied.CurrentState != "patch" || !verifyApplied.MatchesExpectedState || !verifyApplied.StructureMatch {
		t.Fatalf("verify applied=%+v", verifyApplied)
	}
	replay, err := manager.Apply(ApplyRequest{
		HookID:          hook.ID,
		ExpectedVersion: hook.Version,
		OperationID:     "apply-entry-1",
		ConfirmInPlace:  true,
	})
	if err != nil || replay.Version != applied.Version {
		t.Fatalf("apply replay=%+v err=%v", replay, err)
	}

	rolledBack, err := manager.Rollback(RollbackRequest{
		HookID:          hook.ID,
		ExpectedVersion: applied.Version,
		OperationID:     "rollback-entry-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if rolledBack.State != StateRolledBack || rolledBack.Version != 5 {
		t.Fatalf("rolled back=%+v", rolledBack)
	}
	after, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, originalFile) {
		t.Fatal("rollback did not restore the exact fixture")
	}
	verifyRolledBack, err := manager.Verify(hook.ID)
	if err != nil {
		t.Fatal(err)
	}
	if verifyRolledBack.CurrentState != "original" || !verifyRolledBack.MatchesExpectedState {
		t.Fatalf("verify rollback=%+v", verifyRolledBack)
	}

	root2, target2, identity2 := hookFixture(t)
	manager2 := newHookManager(t, root2, nil)
	hook2 := planEntryHook(t, manager2, target2, identity2)
	file, err := os.OpenFile(target2, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	originalRegion, _ := hex.DecodeString(hook2.OriginalHex)
	originalRegion[0] ^= 0xFF
	if _, err := file.WriteAt(originalRegion, hook2.SourceFileOffset); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := manager2.Apply(ApplyRequest{
		HookID:          hook2.ID,
		ExpectedVersion: hook2.Version,
		OperationID:     "apply-drift-1",
		ConfirmInPlace:  true,
	}); !errors.Is(err, ErrWrongOriginalBytes) {
		t.Fatalf("drift apply err=%v", err)
	}
	stillPlanned, err := manager2.Get(hook2.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stillPlanned.State != StatePlanned || stillPlanned.Version != 1 {
		t.Fatalf("drift mutated state=%+v", stillPlanned)
	}
}

func TestApplyAndRollbackRecoverAfterEffect(t *testing.T) {
	root, target, identity := hookFixture(t)
	failApply := true
	failRollback := true
	injectedApply := errors.New("simulated apply crash after effect")
	injectedRollback := errors.New("simulated rollback crash after effect")
	manager := newHookManager(t, root, func(kind string) error {
		switch kind {
		case "apply":
			if failApply {
				failApply = false
				return injectedApply
			}
		case "rollback":
			if failRollback {
				failRollback = false
				return injectedRollback
			}
		}
		return nil
	})
	hook := planEntryHook(t, manager, target, identity)
	_, err := manager.Apply(ApplyRequest{
		HookID:          hook.ID,
		ExpectedVersion: 1,
		OperationID:     "recover-apply-1",
		ConfirmInPlace:  true,
	})
	if !errors.Is(err, injectedApply) {
		t.Fatalf("apply crash err=%v", err)
	}
	applying, err := manager.Get(hook.ID)
	if err != nil {
		t.Fatal(err)
	}
	if applying.State != StateApplying || applying.Version != 2 {
		t.Fatalf("applying=%+v", applying)
	}
	recoveredApply, err := manager.Apply(ApplyRequest{
		HookID:          hook.ID,
		ExpectedVersion: applying.Version,
		OperationID:     "recover-apply-1",
		ConfirmInPlace:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if recoveredApply.State != StateApplied || recoveredApply.Version != 3 {
		t.Fatalf("recovered apply=%+v", recoveredApply)
	}

	_, err = manager.Rollback(RollbackRequest{
		HookID:          hook.ID,
		ExpectedVersion: recoveredApply.Version,
		OperationID:     "recover-rollback-1",
	})
	if !errors.Is(err, injectedRollback) {
		t.Fatalf("rollback crash err=%v", err)
	}
	rollingBack, err := manager.Get(hook.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rollingBack.State != StateRollingBack || rollingBack.Version != 4 {
		t.Fatalf("rolling back=%+v", rollingBack)
	}
	recoveredRollback, err := manager.Rollback(RollbackRequest{
		HookID:          hook.ID,
		ExpectedVersion: rollingBack.Version,
		OperationID:     "recover-rollback-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if recoveredRollback.State != StateRolledBack || recoveredRollback.Version != 5 {
		t.Fatalf("recovered rollback=%+v", recoveredRollback)
	}
}

func TestPlanRejectsNonExecutableDestinationRVA(t *testing.T) {
	root, target, identity := hookFixture(t)
	manager := newHookManager(t, root, nil)
	_, err := manager.Plan(context.Background(), PlanRequest{
		Path:           target,
		SourceRVA:      uint64(identity.PE.EntryPointRVA),
		DestinationRVA: 0x2000,
		Description:    "non-executable destination",
	})
	if err == nil || !strings.Contains(err.Error(), "non-executable section") {
		t.Fatalf("non-executable destination err=%v", err)
	}
}

func TestRel32DetourRejectsOutOfRange(t *testing.T) {
	if _, err := buildRel32Detour(0, uint64(^uint32(0)), 5); err == nil {
		t.Fatal("out-of-range rel32 detour was accepted")
	}
}
