package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	researchcore "reverseresearch/internal/core"
	"reverseresearch/internal/migration"
)

func TestCLIMigrationCandidatePlan(t *testing.T) {
	root, _ := isolatedCLIRoot(t)
	service, err := researchcore.New(root)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "testdata", "mcp-smoke.exe")
	diff, err := service.FunctionDiff(context.Background(), target, target, 70)
	if err != nil {
		t.Fatal(err)
	}
	var anchor *migration.Anchor
	for _, match := range diff.Matches {
		if match.Match == "MATCH" && match.Similarity >= .7 {
			rva := match.OldRVA
			anchor = &migration.Anchor{Label: "fixture-function", OldRVA: &rva}
			break
		}
	}
	if anchor == nil {
		t.Fatal("real radiff2 fixture produced no eligible match")
	}
	body, err := json.Marshal([]migration.Anchor{*anchor})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "anchors.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	var result migration.Result
	if err := json.Unmarshal(recordCLI(t, root, "diff", "migrate", target, target, "--anchors", path), &result); err != nil {
		t.Fatal(err)
	}
	if result.Mapped != 1 || result.Validation != "candidate-only" || result.RuntimeVerified || result.Entries[0].NewRVA != *anchor.OldRVA {
		t.Fatalf("migration=%+v", result)
	}
}

func TestMigrationAnchorInputValidation(t *testing.T) {
	for _, body := range []string{`[]`, `null`, `[{}]`, `[{"label":"x","old_name":"f","typo":1}]`, `[{"label":"x","old_rva":1}] []`} {
		path := filepath.Join(t.TempDir(), "anchors.json")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadMigrationAnchors(path); err == nil {
			t.Errorf("invalid anchors accepted: %s", body)
		}
	}
}
