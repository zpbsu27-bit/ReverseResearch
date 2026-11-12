package patchplan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPlanDryRunApplyVerifyRollbackInPlace(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "sample.bin")
	original := []byte{0x10, 0x20, 0x30, 0x40, 0x50}
	if err := os.WriteFile(target, original, 0o600); err != nil {
		t.Fatal(err)
	}

	manager, err := New(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := manager.Plan(PlanRequest{
		Path:           target,
		Offset:         1,
		ExpectedHex:    "20 30",
		ReplacementHex: "AA BB",
		Description:    "test patch",
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.ID == "" || plan.SourceSHA256 == "" || plan.Status != StatusPlanned {
		t.Fatalf("plan=%+v", plan)
	}

	dry, err := manager.DryRun(plan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !dry.Ready {
		t.Fatalf("dry-run not ready: %+v", dry)
	}

	applied, err := manager.Apply(ApplyRequest{PlanID: plan.ID, InPlace: true})
	if err != nil {
		t.Fatal(err)
	}
	if applied.Status != StatusApplied || applied.AppliedSHA256 == "" {
		t.Fatalf("applied=%+v", applied)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if got[1] != 0xAA || got[2] != 0xBB {
		t.Fatalf("patched bytes=%x", got)
	}

	verified, err := manager.Verify(plan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !verified.Valid {
		t.Fatalf("verify=%+v", verified)
	}

	rolled, err := manager.Rollback(plan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rolled.Status != StatusRolledBack {
		t.Fatalf("rolled=%+v", rolled)
	}
	got, err = os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(original) {
		t.Fatalf("rollback bytes=%x want=%x", got, original)
	}
}

func TestApplyFailsClosedAfterTargetDrift(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "sample.bin")
	if err := os.WriteFile(target, []byte{1, 2, 3, 4}, 0o600); err != nil {
		t.Fatal(err)
	}
	manager, err := New(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := manager.Plan(PlanRequest{
		Path:           target,
		Offset:         1,
		ExpectedHex:    "02 03",
		ReplacementHex: "F2 F3",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte{9, 2, 3, 4}, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Apply(ApplyRequest{PlanID: plan.ID, InPlace: true}); err == nil {
		t.Fatal("expected currentness failure after target drift")
	}
}

func TestCopyApplyRequiresExplicitOutputAndDoesNotModifySource(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "sample.bin")
	original := []byte{0x01, 0x02, 0x03}
	if err := os.WriteFile(target, original, 0o600); err != nil {
		t.Fatal(err)
	}
	manager, err := New(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := manager.Plan(PlanRequest{
		Path:           target,
		Offset:         1,
		ExpectedHex:    "02",
		ReplacementHex: "FE",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Apply(ApplyRequest{PlanID: plan.ID}); err == nil {
		t.Fatal("copy apply without output path must fail")
	}
	output := filepath.Join(root, "patched.bin")
	applied, err := manager.Apply(ApplyRequest{PlanID: plan.ID, OutputPath: output})
	if err != nil {
		t.Fatal(err)
	}
	if applied.Status != StatusCopied || applied.OutputPath != output {
		t.Fatalf("copy result=%+v", applied)
	}
	sourceNow, _ := os.ReadFile(target)
	if string(sourceNow) != string(original) {
		t.Fatalf("source changed: %x", sourceNow)
	}
	outputNow, _ := os.ReadFile(output)
	if outputNow[1] != 0xFE {
		t.Fatalf("output not patched: %x", outputNow)
	}
}
