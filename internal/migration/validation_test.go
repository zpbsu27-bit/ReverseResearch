package migration

import (
	"testing"

	"reverseresearch/internal/bindiff"
)

func TestResolveDoesNotPromoteUnmatchedOrBelowThresholdRows(t *testing.T) {
	for _, row := range []bindiff.FunctionMatch{
		{OldRVA: 0x1030, NewRVA: 0x2050, Similarity: 0.99, Match: "UNMATCH", Confidence: "high"},
		{OldRVA: 0x1030, NewRVA: 0x2050, Similarity: 0.2, Match: "MATCH", Confidence: "low"},
		{OldRVA: 0x1030, NewRVA: 0x2050, Similarity: 1.2, Match: "MATCH", Confidence: "exact"},
	} {
		diff := fixtureDiff()
		diff.Matches = []bindiff.FunctionMatch{row}
		result, err := Resolve(diff, []Anchor{{Label: "candidate", OldRVA: u64(0x1030)}})
		if err != nil {
			t.Fatal(err)
		}
		if result.Mapped != 0 || result.Unmapped != 1 {
			t.Errorf("unsafe candidate promoted: row=%+v result=%+v", row, result)
		}
	}
}

func TestResolveFunctionNamesAreCaseSensitive(t *testing.T) {
	result, err := Resolve(fixtureDiff(), []Anchor{{Label: "different symbol", OldName: "sym.splitarmy"}})
	if err != nil || result.Mapped != 0 || result.Unmapped != 1 {
		t.Fatalf("case-distinct symbols conflated: %+v %v", result, err)
	}
}

func TestResolveRejectsInvalidThreshold(t *testing.T) {
	diff := fixtureDiff()
	diff.Threshold = 101
	if _, err := Resolve(diff, []Anchor{{Label: "test", OldRVA: u64(0x1030)}}); err == nil {
		t.Fatal("invalid threshold accepted")
	}
}
