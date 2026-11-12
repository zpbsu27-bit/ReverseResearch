package core

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"reverseresearch/internal/patchplan"
	"reverseresearch/internal/sandbox"
)

func TestServiceTargetAndPatchLifecycle(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "sample.bin")
	original := []byte{0x10, 0x20, 0x30, 0x40}
	if err := os.WriteFile(target, original, 0o600); err != nil {
		t.Fatal(err)
	}

	service, err := New(root)
	if err != nil {
		t.Fatal(err)
	}

	identity, err := service.Identify(target)
	if err != nil {
		t.Fatal(err)
	}
	if len(identity.SHA256) != 64 || identity.Size != int64(len(original)) {
		t.Fatalf("identity=%+v", identity)
	}

	comparison, err := service.Compare(target, target)
	if err != nil {
		t.Fatal(err)
	}
	if !comparison.SameContent {
		t.Fatalf("comparison=%+v", comparison)
	}

	plan, err := service.PlanPatch(patchplan.PlanRequest{
		Path: target, Offset: 1,
		ExpectedHex: "20 30", ReplacementHex: "AA BB",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.DryRunPatch(plan.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ApplyPatch(patchplan.ApplyRequest{PlanID: plan.ID, InPlace: true}); err != nil {
		t.Fatal(err)
	}
	verified, err := service.VerifyPatch(plan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !verified.Valid {
		t.Fatalf("verify=%+v", verified)
	}
	if _, err := service.RollbackPatch(plan.ID); err != nil {
		t.Fatal(err)
	}
	now, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(now) != string(original) {
		t.Fatalf("rollback=%x want=%x", now, original)
	}
}

func TestServiceRoutesAndPersistsToolIndex(t *testing.T) {
	root, _ := isolatedCoreRoot(t)
	service, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	routed, err := service.Route("把旧版分兵函数迁移到新版")
	if err != nil {
		t.Fatal(err)
	}
	if routed.Route.ID != "binary-diff" {
		t.Fatalf("route=%+v", routed)
	}
	index, err := service.ScanTools()
	if err != nil {
		t.Fatal(err)
	}
	if tool, ok := index.ByName("ghidra"); !ok || !tool.Available {
		t.Fatalf("ghidra=%+v ok=%v", tool, ok)
	}
	loaded, err := service.LoadToolIndex()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Tools) != len(index.Tools) {
		t.Fatalf("loaded=%d index=%d", len(loaded.Tools), len(index.Tools))
	}
}

func TestServiceCapabilityStatus(t *testing.T) {
	root, _ := isolatedCoreRoot(t)
	service, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	status, err := service.CapabilityStatus("native-static")
	if err != nil {
		t.Fatal(err)
	}
	if status.RouteID != "native-static" || len(status.Tools) == 0 {
		t.Fatalf("status=%+v", status)
	}
	if !status.Runnable {
		t.Fatalf("native-static should be runnable on the bundled runtime: %+v", status)
	}
	all, err := service.CapabilityStatuses()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) < 10 {
		t.Fatalf("capability count=%d", len(all))
	}
}

func TestServicePlansProvisioningAndSandbox(t *testing.T) {
	root, _ := isolatedCoreRoot(t)
	service, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := service.PlanTools([]string{"frida", "ghidra"})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Items) != 2 {
		t.Fatalf("plan=%+v", plan)
	}
	sandboxPlan, err := service.PlanSandbox(sandbox.PlanRequest{
		Name: "analysis lab", Route: "ctf-sandbox", Kind: sandbox.KindFilesystem,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !sandboxPlan.Ready {
		t.Fatalf("sandbox plan=%+v", sandboxPlan)
	}
	created, err := service.CreateSandbox(sandboxPlan)
	if err != nil {
		t.Fatal(err)
	}
	if created.Root == "" {
		t.Fatalf("created=%+v", created)
	}
}

func TestServicePrepareBuildsReadOnlyWorkPlan(t *testing.T) {
	root, _ := isolatedCoreRoot(t)
	service, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := service.Prepare("做一道 CTF Pwn 题，先看保护再分析 ROP")
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Route.Route.ID != "pwn-exploit" {
		t.Fatalf("route=%+v", prepared.Route)
	}
	if prepared.Capability.RouteID != "pwn-exploit" {
		t.Fatalf("capability=%+v", prepared.Capability)
	}
	if prepared.Sandbox.Kind != sandbox.KindWSL {
		t.Fatalf("sandbox=%+v", prepared.Sandbox)
	}
	if len(prepared.Provision.Items) != len(prepared.Route.Route.Tools) {
		t.Fatalf("provision=%+v route tools=%v", prepared.Provision, prepared.Route.Route.Tools)
	}
}

func TestServicePrepareSelectsThreePlatformPlaybooksAndDoesNotForceFit(t *testing.T) {
	root, _ := isolatedCoreRoot(t)
	service, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		task       string
		routeID    string
		playbookID string
	}{
		{"查字符串引用并反编译这个本地二进制", "native-static", "windows-native"},
		{"analyze this Android APK DEX with JADX", "android", "android"},
		{"trace the browser JavaScript signature chain", "js-web", "js-web"},
	}
	for _, tc := range tests {
		prepared, err := service.Prepare(tc.task)
		if err != nil {
			t.Fatalf("prepare %q: %v", tc.task, err)
		}
		if prepared.Route.Route.ID != tc.routeID || prepared.Playbook == nil || prepared.Playbook.ID != tc.playbookID {
			t.Fatalf("prepare %q=%+v", tc.task, prepared)
		}
		if len(prepared.Playbook.Gates) < 4 || len(prepared.Playbook.Done) < 4 {
			t.Fatalf("playbook incomplete for %q: %+v", tc.task, prepared.Playbook)
		}
	}

	unknown, err := service.Prepare("一项现有分类都不匹配的未知对象研究")
	if err != nil {
		t.Fatal(err)
	}
	if unknown.Route.Route.ID != "unclassified" || unknown.Playbook != nil {
		t.Fatalf("unknown task must remain unclassified without forced playbook: %+v", unknown)
	}
}

func TestServiceBinaryDiff(t *testing.T) {
	root, sourceRoot := isolatedCoreRoot(t)
	service, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(sourceRoot, "testdata", "mcp-smoke.exe")
	quick, err := service.QuickDiff(context.Background(), target, target)
	if err != nil {
		t.Fatal(err)
	}
	if !quick.Comparison.SameContent || quick.ChangeCount != 0 {
		t.Fatalf("quick=%+v", quick)
	}
	functions, err := service.FunctionDiff(context.Background(), target, target, 70)
	if err != nil {
		t.Fatal(err)
	}
	if functions.Exact == 0 || len(functions.Matches) == 0 {
		t.Fatalf("functions=%+v", functions)
	}
}
