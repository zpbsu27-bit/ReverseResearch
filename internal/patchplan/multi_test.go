package patchplan

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCompositePlanCanonicalizesEditsAndRejectsOverlap(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "sample.bin")
	original := []byte{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80}
	if err := os.WriteFile(target, original, 0o600); err != nil {
		t.Fatal(err)
	}
	manager, err := New(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := manager.Plan(PlanRequest{
		Path: target,
		Edits: []PatchEdit{
			{Offset: 6, ExpectedHex: "70", ReplacementHex: "A7"},
			{Offset: 1, ExpectedHex: "20 30", ReplacementHex: "A2 A3"},
		},
		Description: "two disjoint edits",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Edits) != 2 || plan.Edits[0].Offset != 1 || plan.Edits[1].Offset != 6 {
		t.Fatalf("edits not canonicalized: %+v", plan.Edits)
	}
	if plan.Edits[0].ExpectedHex != "2030" || plan.Edits[0].ReplacementHex != "A2A3" {
		t.Fatalf("edit hex not normalized: %+v", plan.Edits[0])
	}
	if plan.ExpectedHex != "" || plan.ReplacementHex != "" || len(plan.Digest) != 64 || len(plan.ExpectedAppliedSHA256) != 64 {
		t.Fatalf("composite plan identity incomplete: %+v", plan)
	}
	dry, err := manager.DryRun(plan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !dry.Ready || dry.EditCount != 2 || dry.TotalByteCount != 3 || dry.ByteCount != 3 || len(dry.Edits) != 2 {
		t.Fatalf("dry run=%+v", dry)
	}

	_, err = manager.Plan(PlanRequest{
		Path: target,
		Edits: []PatchEdit{
			{Offset: 1, ExpectedHex: "20 30", ReplacementHex: "A2 A3"},
			{Offset: 2, ExpectedHex: "30 40", ReplacementHex: "B3 B4"},
		},
	})
	if err == nil {
		t.Fatal("overlapping composite edits were accepted")
	}
	after, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, original) {
		t.Fatalf("planning changed target: %x", after)
	}
}

func TestCompositePlanIdentityIsStableAcrossInputOrder(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "sample.bin")
	if err := os.WriteFile(target, []byte{0x10, 0x20, 0x30, 0x40, 0x50}, 0o600); err != nil {
		t.Fatal(err)
	}
	manager, err := New(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	left, err := manager.Plan(PlanRequest{
		Path: target,
		Edits: []PatchEdit{
			{Offset: 3, ExpectedHex: "40", ReplacementHex: "A4"},
			{Offset: 0, ExpectedHex: "10 20", ReplacementHex: "A1 A2"},
		},
		Description: "first ordering",
	})
	if err != nil {
		t.Fatal(err)
	}
	right, err := manager.Plan(PlanRequest{
		Path: target,
		Edits: []PatchEdit{
			{Offset: 0, ExpectedHex: "10 20", ReplacementHex: "A1 A2"},
			{Offset: 3, ExpectedHex: "40", ReplacementHex: "A4"},
		},
		Description: "second ordering must resolve to same mutation identity",
	})
	if err != nil {
		t.Fatal(err)
	}
	if left.ID != right.ID || left.Digest != right.Digest {
		t.Fatalf("composite identity depends on input order: left=%s/%s right=%s/%s", left.ID, left.Digest, right.ID, right.Digest)
	}
	if len(right.Edits) != 2 || right.Edits[0].Offset != 0 || right.Edits[1].Offset != 3 {
		t.Fatalf("canonical edits=%+v", right.Edits)
	}
}

func TestCompositePlanExpectedMismatchFailsBeforePersist(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "sample.bin")
	if err := os.WriteFile(target, []byte{0x10, 0x20, 0x30, 0x40}, 0o600); err != nil {
		t.Fatal(err)
	}
	manager, err := New(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = manager.Plan(PlanRequest{
		Path: target,
		Edits: []PatchEdit{
			{Offset: 0, ExpectedHex: "10", ReplacementHex: "11"},
			{Offset: 3, ExpectedHex: "99", ReplacementHex: "44"},
		},
	})
	if err == nil {
		t.Fatal("expected mismatch was accepted")
	}
	entries, err := os.ReadDir(filepath.Join(root, "state", "plans"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("mismatched plan persisted records: %v", entries)
	}
}

func TestCompositeCopyApplyLeavesSourceUnchanged(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "source.bin")
	output := filepath.Join(root, "patched.bin")
	original := []byte{0x10, 0x20, 0x30, 0x40, 0x50}
	if err := os.WriteFile(target, original, 0o600); err != nil {
		t.Fatal(err)
	}
	manager, err := New(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := manager.Plan(PlanRequest{
		Path: target,
		Edits: []PatchEdit{
			{Offset: 0, ExpectedHex: "10", ReplacementHex: "A0"},
			{Offset: 3, ExpectedHex: "40 50", ReplacementHex: "B4 B5"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	applied, err := manager.Apply(ApplyRequest{
		PlanID: plan.ID, OutputPath: output, OperationID: "composite-copy",
	})
	if err != nil {
		t.Fatal(err)
	}
	if applied.Status != StatusCopied || applied.OutputPath != output {
		t.Fatalf("applied=%+v", applied)
	}
	sourceBytes, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sourceBytes, original) {
		t.Fatalf("copy mode changed source: %x", sourceBytes)
	}
	patched, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0xA0, 0x20, 0x30, 0xB4, 0xB5}
	if !bytes.Equal(patched, want) {
		t.Fatalf("patched copy=%x want=%x", patched, want)
	}
	verified, err := manager.Verify(plan.ID)
	if err != nil || !verified.Valid {
		t.Fatalf("verify=%+v err=%v", verified, err)
	}
}

func TestCompositeInPlaceRecoversApplyAndRollbackCrashWindows(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "sample.bin")
	original := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	if err := os.WriteFile(target, original, 0o600); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(root, "state")
	manager, err := New(state)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := manager.Plan(PlanRequest{
		Path: target,
		Edits: []PatchEdit{
			{Offset: 1, ExpectedHex: "01 02", ReplacementHex: "A1 A2"},
			{Offset: 6, ExpectedHex: "06", ReplacementHex: "B6"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	applyCrash := errors.New("composite apply crash after effect")
	manager.afterEffect = func(kind string) error {
		if kind == "apply" {
			return applyCrash
		}
		return nil
	}
	_, err = manager.Apply(ApplyRequest{
		PlanID: plan.ID, InPlace: true, OperationID: "composite-apply",
	})
	if !errors.Is(err, applyCrash) {
		t.Fatalf("apply crash err=%v", err)
	}
	patched, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	wantPatched := []byte{0x00, 0xA1, 0xA2, 0x03, 0x04, 0x05, 0xB6, 0x07}
	if !bytes.Equal(patched, wantPatched) {
		t.Fatalf("partial/incorrect composite effect: %x", patched)
	}

	recovered, err := New(state)
	if err != nil {
		t.Fatal(err)
	}
	applied, err := recovered.Apply(ApplyRequest{
		PlanID: plan.ID, InPlace: true, OperationID: "composite-apply",
	})
	if err != nil || applied.Status != StatusApplied {
		t.Fatalf("recover apply=%+v err=%v", applied, err)
	}
	if verified, err := recovered.Verify(plan.ID); err != nil || !verified.Valid {
		t.Fatalf("verify after recovery=%+v err=%v", verified, err)
	}

	rollbackCrash := errors.New("composite rollback crash after effect")
	recovered.afterEffect = func(kind string) error {
		if kind == "rollback" {
			return rollbackCrash
		}
		return nil
	}
	_, err = recovered.RollbackOperation(RollbackRequest{
		PlanID: plan.ID, OperationID: "composite-rollback",
	})
	if !errors.Is(err, rollbackCrash) {
		t.Fatalf("rollback crash err=%v", err)
	}
	restored, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored, original) {
		t.Fatalf("rollback effect incomplete: %x", restored)
	}

	finalManager, err := New(state)
	if err != nil {
		t.Fatal(err)
	}
	rolledBack, err := finalManager.RollbackOperation(RollbackRequest{
		PlanID: plan.ID, OperationID: "composite-rollback",
	})
	if err != nil || rolledBack.Status != StatusRolledBack {
		t.Fatalf("recover rollback=%+v err=%v", rolledBack, err)
	}
}
