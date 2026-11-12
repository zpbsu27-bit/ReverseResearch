package migration

import (
	"testing"

	"reverseresearch/internal/bindiff"
	"reverseresearch/internal/targetidentity"
)

func u64(value uint64) *uint64 { return &value }

func fixtureDiff() bindiff.FunctionResult {
	return bindiff.FunctionResult{
		Comparison: targetidentity.Comparison{
			Left:  targetidentity.Identity{SHA256: "oldhash", Path: "old.exe"},
			Right: targetidentity.Identity{SHA256: "newhash", Path: "new.exe"},
		},
		Threshold: 70,
		Matches: []bindiff.FunctionMatch{
			{OldRVA: 0x1030, OldName: "sym.SplitArmy", NewRVA: 0x2050, NewName: "fcn.402050", Similarity: 0.96, Confidence: "high", Match: "MATCH"},
			{OldRVA: 0x1100, OldName: "sym.Duplicate", NewRVA: 0x3100, NewName: "fcn.403100", Similarity: 0.92, Confidence: "high", Match: "MATCH"},
			{OldRVA: 0x1200, OldName: "sym.Duplicate", NewRVA: 0x3200, NewName: "fcn.403200", Similarity: 0.91, Confidence: "high", Match: "MATCH"},
		},
	}
}

func TestResolveAnchorsByRVAAndName(t *testing.T) {
	result, err := Resolve(fixtureDiff(), []Anchor{
		{Label: "split-army", OldRVA: u64(0x1030)},
		{Label: "split-by-name", OldName: "sym.SplitArmy"},
		{Label: "missing", OldRVA: u64(0x9999)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Mapped != 2 || result.Unmapped != 1 || result.Ambiguous != 0 {
		t.Fatalf("summary=%+v", result)
	}
	if result.Entries[0].Status != StatusMapped || result.Entries[0].NewRVA != 0x2050 {
		t.Fatalf("rva mapping=%+v", result.Entries[0])
	}
	if result.Entries[1].Status != StatusMapped || result.Entries[1].OldRVA != 0x1030 {
		t.Fatalf("name mapping=%+v", result.Entries[1])
	}
	if result.Entries[2].Status != StatusUnmapped || result.Entries[2].Reason == "" {
		t.Fatalf("missing=%+v", result.Entries[2])
	}
}

func TestResolveMarksAmbiguousName(t *testing.T) {
	result, err := Resolve(fixtureDiff(), []Anchor{{Label: "dup", OldName: "sym.Duplicate"}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Ambiguous != 1 || result.Entries[0].Status != StatusAmbiguous {
		t.Fatalf("result=%+v", result)
	}
	if len(result.Entries[0].Candidates) != 2 {
		t.Fatalf("candidates=%+v", result.Entries[0].Candidates)
	}
}

func TestResolveRequiresSelectorAndUniqueLabels(t *testing.T) {
	if _, err := Resolve(fixtureDiff(), []Anchor{{Label: "bad"}}); err == nil {
		t.Fatal("anchor without selector must fail")
	}
	if _, err := Resolve(fixtureDiff(), []Anchor{
		{Label: "same", OldRVA: u64(0x1030)},
		{Label: "same", OldRVA: u64(0x1100)},
	}); err == nil {
		t.Fatal("duplicate labels must fail")
	}
}
