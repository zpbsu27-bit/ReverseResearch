package patchplan

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestApplyRecoversAfterEffectBeforePlanCommit(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "sample.bin")
	original := []byte{0x10, 0x20, 0x30, 0x40}
	if err := os.WriteFile(target, original, 0o600); err != nil {
		t.Fatal(err)
	}
	manager, err := New(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := manager.Plan(PlanRequest{
		Path: target, Offset: 1, ExpectedHex: "20 30", ReplacementHex: "AA BB",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.ExpectedAppliedSHA256) != 64 || len(plan.Digest) != 64 {
		t.Fatalf("plan lacks immutable postcondition: %+v", plan)
	}

	injected := errors.New("simulated crash after target write")
	manager.afterEffect = func(kind string) error {
		if kind == "apply" {
			return injected
		}
		return nil
	}
	_, err = manager.Apply(ApplyRequest{
		PlanID: plan.ID, InPlace: true, OperationID: "apply-crash-recovery",
	})
	if !errors.Is(err, injected) {
		t.Fatalf("first apply err=%v want injected crash", err)
	}
	patched, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(patched, original) || patched[1] != 0xAA || patched[2] != 0xBB {
		t.Fatalf("effect did not happen before simulated crash: %x", patched)
	}

	recovered, err := New(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := recovered.Apply(ApplyRequest{
		PlanID: plan.ID, InPlace: true, OperationID: "apply-crash-recovery",
	})
	if err != nil {
		t.Fatalf("recover apply: %v", err)
	}
	if got.Status != StatusApplied || got.AppliedSHA256 != plan.ExpectedAppliedSHA256 {
		t.Fatalf("recovered plan=%+v", got)
	}
	persisted, err := recovered.Get(plan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Status != StatusApplied || persisted.AppliedSHA256 != plan.ExpectedAppliedSHA256 {
		t.Fatalf("persisted recovery=%+v", persisted)
	}
}

func TestRollbackRecoversAfterEffectBeforePlanCommit(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "sample.bin")
	original := []byte{0x01, 0x02, 0x03, 0x04}
	if err := os.WriteFile(target, original, 0o600); err != nil {
		t.Fatal(err)
	}
	manager, err := New(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := manager.Plan(PlanRequest{
		Path: target, Offset: 1, ExpectedHex: "02 03", ReplacementHex: "F2 F3",
	})
	if err != nil {
		t.Fatal(err)
	}
	applied, err := manager.Apply(ApplyRequest{
		PlanID: plan.ID, InPlace: true, OperationID: "initial-apply",
	})
	if err != nil {
		t.Fatal(err)
	}

	injected := errors.New("simulated crash after rollback write")
	manager.afterEffect = func(kind string) error {
		if kind == "rollback" {
			return injected
		}
		return nil
	}
	_, err = manager.RollbackOperation(RollbackRequest{
		PlanID: applied.ID, OperationID: "rollback-crash-recovery",
	})
	if !errors.Is(err, injected) {
		t.Fatalf("first rollback err=%v want injected crash", err)
	}
	restored, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored, original) {
		t.Fatalf("rollback effect not visible before simulated crash: %x", restored)
	}

	recovered, err := New(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := recovered.RollbackOperation(RollbackRequest{
		PlanID: applied.ID, OperationID: "rollback-crash-recovery",
	})
	if err != nil {
		t.Fatalf("recover rollback: %v", err)
	}
	if got.Status != StatusRolledBack {
		t.Fatalf("rollback recovery=%+v", got)
	}
}

func TestOperationIDCannotBeReusedForDifferentPatchRequest(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state")
	manager, err := New(state)
	if err != nil {
		t.Fatal(err)
	}
	makePlan := func(name string, initial byte) Plan {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte{initial, 0x22}, 0o600); err != nil {
			t.Fatal(err)
		}
		plan, err := manager.Plan(PlanRequest{
			Path: path, Offset: 0,
			ExpectedHex:    fmt.Sprintf("%02X", initial),
			ReplacementHex: "FE",
		})
		if err != nil {
			t.Fatal(err)
		}
		return plan
	}
	first := makePlan("first.bin", 0x11)
	second := makePlan("second.bin", 0x33)
	if _, err := manager.Apply(ApplyRequest{
		PlanID: first.ID, InPlace: true, OperationID: "shared-operation",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Apply(ApplyRequest{
		PlanID: second.ID, InPlace: true, OperationID: "shared-operation",
	}); err == nil {
		t.Fatal("operation ID was reused for a different patch request")
	}
	secondBytes, err := os.ReadFile(second.Path)
	if err != nil {
		t.Fatal(err)
	}
	if secondBytes[0] != 0x33 {
		t.Fatalf("second target changed despite rejected replay: %x", secondBytes)
	}
}

func TestSeparateProcessesSerializeSamePatchOperation(t *testing.T) {
	if os.Getenv("RR_PATCH_WORKER") == "1" {
		manager, err := New(os.Getenv("RR_PATCH_STATE"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := manager.Apply(ApplyRequest{
			PlanID:      os.Getenv("RR_PATCH_PLAN"),
			InPlace:     true,
			OperationID: os.Getenv("RR_PATCH_OPERATION"),
		}); err != nil {
			t.Fatal(err)
		}
		return
	}

	root := t.TempDir()
	state := filepath.Join(root, "state")
	target := filepath.Join(root, "sample.bin")
	if err := os.WriteFile(target, []byte{0x10, 0x20, 0x30, 0x40}, 0o600); err != nil {
		t.Fatal(err)
	}
	manager, err := New(state)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := manager.Plan(PlanRequest{
		Path: target, Offset: 1, ExpectedHex: "20 30", ReplacementHex: "AA BB",
	})
	if err != nil {
		t.Fatal(err)
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	const workers = 6
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cmd := exec.Command(exe, "-test.run=^TestSeparateProcessesSerializeSamePatchOperation$")
			cmd.Env = append(os.Environ(),
				"RR_PATCH_WORKER=1",
				"RR_PATCH_STATE="+state,
				"RR_PATCH_PLAN="+plan.ID,
				"RR_PATCH_OPERATION=same-operation",
			)
			if out, err := cmd.CombinedOutput(); err != nil {
				errs <- fmt.Errorf("%v: %s", err, out)
				return
			}
			errs <- nil
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("worker: %v", err)
		}
	}
	got, err := manager.Get(plan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusApplied || got.AppliedSHA256 != got.ExpectedAppliedSHA256 {
		t.Fatalf("final plan=%+v", got)
	}
}

func TestPlanUpgradesLegacyMatchingRecord(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "sample.bin")
	if err := os.WriteFile(target, []byte{0x10, 0x20, 0x30}, 0o600); err != nil {
		t.Fatal(err)
	}
	manager, err := New(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := manager.Plan(PlanRequest{
		Path: target, Offset: 1, ExpectedHex: "20", ReplacementHex: "AA",
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(manager.planPath(plan.ID))
	if err != nil {
		t.Fatal(err)
	}
	var legacy map[string]any
	if err := json.Unmarshal(body, &legacy); err != nil {
		t.Fatal(err)
	}
	delete(legacy, "expected_applied_sha256")
	delete(legacy, "digest")
	body, err = json.MarshalIndent(legacy, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	body = append(body, '\n')
	if err := os.WriteFile(manager.planPath(plan.ID), body, 0o600); err != nil {
		t.Fatal(err)
	}

	reopened, err := New(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := reopened.Plan(PlanRequest{
		Path: target, Offset: 1, ExpectedHex: "20", ReplacementHex: "AA",
	})
	if err != nil {
		t.Fatalf("legacy plan was not upgraded: %v", err)
	}
	if got.ID != plan.ID || len(got.Digest) != 64 || len(got.ExpectedAppliedSHA256) != 64 {
		t.Fatalf("upgraded plan=%+v", got)
	}
}

func TestGetRejectsLegacyAppliedPlanWhenTargetDrifted(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "sample.bin")
	if err := os.WriteFile(target, []byte{0x10, 0x20, 0x30}, 0o600); err != nil {
		t.Fatal(err)
	}
	manager, err := New(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := manager.Plan(PlanRequest{
		Path: target, Offset: 1, ExpectedHex: "20", ReplacementHex: "AA",
	})
	if err != nil {
		t.Fatal(err)
	}
	applied, err := manager.Apply(ApplyRequest{
		PlanID: plan.ID, InPlace: true, OperationID: "legacy-applied",
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(manager.planPath(applied.ID))
	if err != nil {
		t.Fatal(err)
	}
	var legacy map[string]any
	if err := json.Unmarshal(body, &legacy); err != nil {
		t.Fatal(err)
	}
	delete(legacy, "expected_applied_sha256")
	delete(legacy, "digest")
	body, err = json.MarshalIndent(legacy, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	body = append(body, '\n')
	if err := os.WriteFile(manager.planPath(applied.ID), body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte{0x99, 0xAA, 0x30}, 0o600); err != nil {
		t.Fatal(err)
	}

	reopened, err := New(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Get(applied.ID); err == nil {
		t.Fatal("legacy applied plan was upgraded despite target drift")
	}
}

func TestRollbackCompletesPreparedReceiptAfterPlanCommit(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "sample.bin")
	if err := os.WriteFile(target, []byte{0x10, 0x20, 0x30}, 0o600); err != nil {
		t.Fatal(err)
	}
	manager, err := New(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := manager.Plan(PlanRequest{
		Path: target, Offset: 1, ExpectedHex: "20", ReplacementHex: "AA",
	})
	if err != nil {
		t.Fatal(err)
	}
	applied, err := manager.Apply(ApplyRequest{
		PlanID: plan.ID, InPlace: true, OperationID: "receipt-apply",
	})
	if err != nil {
		t.Fatal(err)
	}

	const operationID = "rollback-plan-committed"
	requestDigest := rollbackRequestDigest(applied)
	receipt := operationReceipt{
		OperationID:   operationID,
		Kind:          "rollback",
		PlanID:        applied.ID,
		PlanDigest:    applied.Digest,
		RequestDigest: requestDigest,
		Mode:          "in_place",
		Status:        operationPrepared,
		CreatedUTC:    time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := manager.saveOperation(receipt); err != nil {
		t.Fatal(err)
	}
	if err := rollbackInPlaceEffect(applied); err != nil {
		t.Fatal(err)
	}
	applied.Status = StatusRolledBack
	applied.RolledBackUTC = time.Now().UTC().Format(time.RFC3339Nano)
	if err := manager.save(applied); err != nil {
		t.Fatal(err)
	}

	if _, err := manager.RollbackOperation(RollbackRequest{
		PlanID: plan.ID, OperationID: operationID,
	}); err != nil {
		t.Fatal(err)
	}
	got, err := manager.loadOperation(operationID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != operationCompleted || got.ResultStatus != StatusRolledBack {
		t.Fatalf("receipt not completed: %+v", got)
	}
}
