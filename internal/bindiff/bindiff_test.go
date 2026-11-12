package bindiff

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func testAnalyzer(t *testing.T) *Analyzer {
	t.Helper()
	root := filepath.Clean(filepath.Join("..", ".."))
	matches, err := filepath.Glob(filepath.Join(root, "runtime", "radare2", "engine", "radare2-*-w64", "bin", "radiff2.exe"))
	if err != nil || len(matches) == 0 {
		t.Fatalf("radiff2 not found: %v", err)
	}
	analyzer, err := New(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	return analyzer
}

func TestQuickIdenticalFile(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	target := filepath.Join(root, "testdata", "mcp-smoke.exe")
	result, err := testAnalyzer(t).Quick(context.Background(), target, target)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Comparison.SameContent || result.ChangeCount != 0 {
		t.Fatalf("result=%+v", result)
	}
}

func TestFunctionsMapsRVAAndConfidence(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	target := filepath.Join(root, "testdata", "mcp-smoke.exe")
	result, err := testAnalyzer(t).Functions(context.Background(), target, target, 70)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Matches) == 0 {
		t.Fatal("no function matches")
	}
	var smoke *FunctionMatch
	for i := range result.Matches {
		if strings.Contains(strings.ToLower(result.Matches[i].OldName), "smokemix") {
			smoke = &result.Matches[i]
			break
		}
	}
	if smoke == nil {
		t.Fatalf("SmokeMix not found: %+v", result.Matches)
	}
	if smoke.OldRVA != 0x1030 || smoke.NewRVA != 0x1030 {
		t.Fatalf("SmokeMix rva old=%#x new=%#x", smoke.OldRVA, smoke.NewRVA)
	}
	if smoke.Similarity != 1 || smoke.Confidence != "exact" {
		t.Fatalf("SmokeMix=%+v", *smoke)
	}
	if result.Exact == 0 {
		t.Fatalf("summary=%+v", result)
	}
}

func TestFunctionsRejectsInvalidThreshold(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	target := filepath.Join(root, "testdata", "mcp-smoke.exe")
	if _, err := testAnalyzer(t).Functions(context.Background(), target, target, 101); err == nil {
		t.Fatal("expected threshold error")
	}
}
