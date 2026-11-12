package compatibility

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"reverseresearch/internal/casebook"
	"reverseresearch/internal/hookplan"
	"reverseresearch/internal/targetidentity"
)

type fakeHooks struct {
	hooks map[string]hookplan.Hook
}

func (f fakeHooks) Get(id string) (hookplan.Hook, error) {
	hook, ok := f.hooks[id]
	if !ok {
		return hookplan.Hook{}, os.ErrNotExist
	}
	return hook, nil
}

func fixtureCopy(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "testdata", "mcp-smoke.exe")
	body, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "game.dll")
	if err := os.WriteFile(target, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return target
}

func TestRecordOnlyCandidateBindsModuleWithoutClaimingCompatibility(t *testing.T) {
	module := fixtureCopy(t)
	cases, err := casebook.New(filepath.Join(t.TempDir(), "cases"))
	if err != nil {
		t.Fatal(err)
	}
	store, err := New(filepath.Join(t.TempDir(), "compat"), fakeHooks{hooks: map[string]hookplan.Hook{}}, cases)
	if err != nil {
		t.Fatal(err)
	}
	record, err := store.Add(AddRequest{
		Game: "Example Game", Build: "1.0", ModulePath: module, ModuleRole: "renderer",
		Outcome: OutcomeCandidate, Validation: ValidationRecordOnly, Notes: "imported legacy note",
	})
	if err != nil {
		t.Fatal(err)
	}
	if record.ID == "" || record.Module.SHA256 == "" || record.Outcome != OutcomeCandidate || record.Validation != ValidationRecordOnly {
		t.Fatalf("record=%+v", record)
	}
	verification, err := store.Verify(record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !verification.RecordValid || !verification.SourceCurrent || verification.CompatibilityRevalidated {
		t.Fatalf("verification=%+v", verification)
	}
}

func TestCompatibleRequiresRuntimeEvidence(t *testing.T) {
	module := fixtureCopy(t)
	store, err := New(filepath.Join(t.TempDir(), "compat"), fakeHooks{hooks: map[string]hookplan.Hook{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Add(AddRequest{
		Game: "Example", Build: "1", ModulePath: module,
		Outcome: OutcomeCompatible, Validation: ValidationStatic,
	})
	if err == nil || !strings.Contains(err.Error(), "runtime-verified") {
		t.Fatalf("err=%v", err)
	}
}

func TestRuntimeValidationRejectsCaseEvidenceWithoutRuntimeKind(t *testing.T) {
	module := fixtureCopy(t)
	caseStore, err := casebook.New(filepath.Join(t.TempDir(), "cases"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := caseStore.Create(casebook.CreateRequest{Title: "static-only evidence"})
	if err != nil {
		t.Fatal(err)
	}
	e, err := caseStore.AddEvidence(c.ID, casebook.EvidenceRequest{Summary: "static note", Kind: "static", SourcePath: module})
	if err != nil {
		t.Fatal(err)
	}
	store, err := New(filepath.Join(t.TempDir(), "compat"), fakeHooks{hooks: map[string]hookplan.Hook{}}, caseStore)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Add(AddRequest{
		Game: "Example", Build: "1", ModulePath: module,
		Outcome: OutcomeCompatible, Validation: ValidationRuntime,
		CaseID: c.ID, EvidenceIDs: []string{e.ID},
	})
	if !errors.Is(err, ErrRuntimeEvidenceKind) {
		t.Fatalf("err=%v", err)
	}
}

func TestRuntimeCompatibleRequiresValidCaseEvidenceAndDetectsModuleDrift(t *testing.T) {
	module := fixtureCopy(t)
	caseStore, err := casebook.New(filepath.Join(t.TempDir(), "cases"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := caseStore.Create(casebook.CreateRequest{Title: "runtime compatibility"})
	if err != nil {
		t.Fatal(err)
	}
	e, err := caseStore.AddEvidence(c.ID, casebook.EvidenceRequest{Summary: "runtime smoke", Kind: "runtime", SourcePath: module})
	if err != nil {
		t.Fatal(err)
	}
	store, err := New(filepath.Join(t.TempDir(), "compat"), fakeHooks{hooks: map[string]hookplan.Hook{}}, caseStore)
	if err != nil {
		t.Fatal(err)
	}
	record, err := store.Add(AddRequest{
		Game: "Example", Build: "1", ModulePath: module,
		Outcome: OutcomeCompatible, Validation: ValidationRuntime,
		CaseID: c.ID, EvidenceIDs: []string{e.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	verification, err := store.Verify(record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !verification.RecordValid || !verification.CaseValid || !verification.EvidenceLinksCurrent || verification.CompatibilityRevalidated {
		t.Fatalf("verification=%+v", verification)
	}
	file, err := os.OpenFile(module, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte{0xCC}, 0x200); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	_ = file.Close()
	verification, err = store.Verify(record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if verification.RecordValid || verification.SourceCurrent {
		t.Fatalf("drift verification=%+v", verification)
	}
}

func TestHookBindingMustMatchExactModuleIdentity(t *testing.T) {
	module := fixtureCopy(t)
	identity, err := targetidentity.Inspect(module)
	if err != nil {
		t.Fatal(err)
	}
	hook := hookplan.Hook{
		ID:             "hook_0123456789abcdef0123456789abcdef",
		Path:           module,
		Baseline:       identity,
		SourceRVA:      0x1000,
		DestinationRVA: 0x1030,
		OriginalHex:    "5589e5",
		PatchHex:       "e92b000000",
	}
	store, err := New(filepath.Join(t.TempDir(), "compat"), fakeHooks{hooks: map[string]hookplan.Hook{hook.ID: hook}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	record, err := store.Add(AddRequest{
		Game: "Example", Build: "1", ModulePath: module, HookID: hook.ID, HookName: "render hook",
		Outcome: OutcomeCandidate, Validation: ValidationRecordOnly,
	})
	if err != nil {
		t.Fatal(err)
	}
	if record.Hook == nil || record.Hook.BaselineSHA256 != identity.SHA256 {
		t.Fatalf("record hook=%+v", record.Hook)
	}
	hook.Baseline.SHA256 = strings.Repeat("f", 64)
	store.hooks = fakeHooks{hooks: map[string]hookplan.Hook{hook.ID: hook}}
	verification, err := store.Verify(record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if verification.RecordValid || verification.HookBindingCurrent {
		t.Fatalf("hook drift verification=%+v", verification)
	}
}

func TestManifestImportResolvesRelativeModulePathAndStaysRecordOnly(t *testing.T) {
	module := fixtureCopy(t)
	dir := filepath.Dir(module)
	manifestPath := filepath.Join(dir, "compat.json")
	manifest := ImportManifest{Records: []AddRequest{{
		Game: "Example", Build: "legacy", ModulePath: filepath.Base(module),
		Outcome: OutcomeCandidate, Validation: ValidationRecordOnly,
	}}}
	body, _ := json.Marshal(manifest)
	if err := os.WriteFile(manifestPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := New(filepath.Join(t.TempDir(), "compat"), fakeHooks{hooks: map[string]hookplan.Hook{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := store.ImportManifest(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Records) != 1 || result.Records[0].ImportedFrom == nil ||
		result.Records[0].Validation != ValidationRecordOnly || result.Records[0].Outcome != OutcomeCandidate {
		t.Fatalf("result=%+v", result)
	}
}

func TestAddContextHonorsCancellationBeforePersist(t *testing.T) {
	module := fixtureCopy(t)
	store, err := New(filepath.Join(t.TempDir(), "compat"), fakeHooks{hooks: map[string]hookplan.Hook{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = store.AddContext(ctx, AddRequest{
		Game: "Example", Build: "cancelled", ModulePath: module,
		Outcome: OutcomeCandidate, Validation: ValidationRecordOnly,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v want context.Canceled", err)
	}
	entries, err := os.ReadDir(filepath.Join(store.root, "records"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("cancelled add persisted %d records", len(entries))
	}
}

func TestVerifyContextHonorsCancellation(t *testing.T) {
	module := fixtureCopy(t)
	store, err := New(filepath.Join(t.TempDir(), "compat"), fakeHooks{hooks: map[string]hookplan.Hook{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	record, err := store.Add(AddRequest{
		Game: "Example", Build: "1", ModulePath: module,
		Outcome: OutcomeCandidate, Validation: ValidationRecordOnly,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.VerifyContext(ctx, record.ID); !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v want context.Canceled", err)
	}
}
