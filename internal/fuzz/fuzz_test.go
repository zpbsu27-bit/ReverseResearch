package fuzz

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCrashFingerprintUsesModuleExceptionInstructionAndStack(t *testing.T) {
	base := Crash{
		Exception: "Access Violation", Module: "C:\\app\\target.dll", FaultInstruction: "mov [rax], rcx",
		Frames: []Frame{{Module: "target.dll", Function: "parse", Offset: 0x10}, {Module: "target.dll", Function: "decode", Offset: 0x20}},
	}
	same := base
	same.InputSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	fp1, err := FingerprintCrash(base)
	if err != nil {
		t.Fatal(err)
	}
	fp2, err := FingerprintCrash(same)
	if err != nil {
		t.Fatal(err)
	}
	if fp1.ID != fp2.ID || fp1.StackFingerprint == "" {
		t.Fatalf("fingerprints differ: %+v %+v", fp1, fp2)
	}
	changed := base
	changed.FaultInstruction = "call rax"
	fp3, err := FingerprintCrash(changed)
	if err != nil {
		t.Fatal(err)
	}
	if fp3.ID == fp1.ID {
		t.Fatal("different fault instruction collapsed into same fingerprint")
	}
}

func TestDedupeGroupsEquivalentCrashes(t *testing.T) {
	crash := Crash{
		Exception: "SIGSEGV", Module: "/tmp/libparser.so", FaultInstruction: "load",
		Frames:      []Frame{{Module: "libparser.so", Function: "parse", Offset: 1}},
		InputSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	other := crash
	other.InputSHA256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	groups, err := Dedupe([]Crash{crash, other})
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || groups[0].Count != 2 || len(groups[0].InputSHA256) != 2 {
		t.Fatalf("groups=%+v", groups)
	}
}

func TestBuildPlanPinsTargetAndDoesNotExecute(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.bin")
	harness := filepath.Join(root, "harness.exe")
	corpus := filepath.Join(root, "corpus")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(harness, []byte("harness"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(corpus, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(corpus, "seed.bin"), []byte("seed"), 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err := BuildPlan(PlanRequest{
		TargetPath: target, Harness: harness, CorpusDir: corpus, Engine: EngineLibFuzzer,
		Sanitizers: []string{"asan", "ubsan", "asan"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Target.SHA256 == "" || plan.Harness.SHA256 == "" || plan.Corpus.SHA256 == "" || plan.Corpus.FileCount != 1 ||
		plan.Execution != "planned-only" || plan.EffectClass != "runtime mutation" || len(plan.Sanitizers) != 2 {
		t.Fatalf("plan=%+v", plan)
	}
}

func TestBuildPlanContextHonorsCancellation(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.bin")
	harness := filepath.Join(root, "harness.exe")
	corpus := filepath.Join(root, "corpus")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(harness, []byte("harness"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(corpus, 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := BuildPlanContext(ctx, PlanRequest{TargetPath: target, Harness: harness, CorpusDir: corpus, Engine: EngineLibFuzzer})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v want context.Canceled", err)
	}
}
