package migration

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"

	"reverseresearch/internal/bindiff"
	"reverseresearch/internal/targetidentity"
)

type Status string

const (
	StatusMapped    Status = "mapped"
	StatusUnmapped  Status = "unmapped"
	StatusAmbiguous Status = "ambiguous"
)

type Anchor struct {
	Label   string  `json:"label"`
	OldRVA  *uint64 `json:"old_rva,omitempty"`
	OldName string  `json:"old_name,omitempty"`
}

type Candidate struct {
	OldRVA     uint64  `json:"old_rva"`
	OldName    string  `json:"old_name,omitempty"`
	NewRVA     uint64  `json:"new_rva"`
	NewName    string  `json:"new_name,omitempty"`
	Similarity float64 `json:"similarity"`
	Confidence string  `json:"confidence"`
	Match      string  `json:"match,omitempty"`
}

type Entry struct {
	Label         string      `json:"label"`
	Status        Status      `json:"status"`
	RequestedRVA  *uint64     `json:"requested_rva,omitempty"`
	RequestedName string      `json:"requested_name,omitempty"`
	OldRVA        uint64      `json:"old_rva,omitempty"`
	OldName       string      `json:"old_name,omitempty"`
	NewRVA        uint64      `json:"new_rva,omitempty"`
	NewName       string      `json:"new_name,omitempty"`
	Similarity    float64     `json:"similarity,omitempty"`
	Confidence    string      `json:"confidence,omitempty"`
	Match         string      `json:"match,omitempty"`
	Reason        string      `json:"reason,omitempty"`
	Candidates    []Candidate `json:"candidates,omitempty"`
}

type Result struct {
	OldTarget       targetidentity.Identity `json:"old_target"`
	NewTarget       targetidentity.Identity `json:"new_target"`
	Threshold       int                     `json:"threshold"`
	Entries         []Entry                 `json:"entries"`
	Mapped          int                     `json:"mapped"`
	Unmapped        int                     `json:"unmapped"`
	Ambiguous       int                     `json:"ambiguous"`
	Validation      string                  `json:"validation"`
	RuntimeVerified bool                    `json:"runtime_verified"`
}

func Resolve(diff bindiff.FunctionResult, anchors []Anchor) (Result, error) {
	if diff.Threshold < 1 || diff.Threshold > 100 {
		return Result{}, errors.New("migration threshold must be between 1 and 100")
	}
	if err := ValidateAnchors(anchors); err != nil {
		return Result{}, err
	}
	result := Result{
		OldTarget:  diff.Comparison.Left,
		NewTarget:  diff.Comparison.Right,
		Threshold:  diff.Threshold,
		Validation: "candidate-only",
		Entries:    make([]Entry, 0, len(anchors)),
	}
	for _, anchor := range anchors {
		label := strings.TrimSpace(anchor.Label)
		name := strings.TrimSpace(anchor.OldName)

		entry := Entry{
			Label:         label,
			RequestedRVA:  cloneUint64(anchor.OldRVA),
			RequestedName: name,
		}
		matches := selectMatches(diff.Matches, anchor.OldRVA, name, diff.Threshold)
		switch len(matches) {
		case 0:
			entry.Status = StatusUnmapped
			entry.Reason = "no eligible MATCH satisfies the old-version anchor and similarity threshold"
			result.Unmapped++
		case 1:
			entry.Status = StatusMapped
			fillMapped(&entry, matches[0])
			result.Mapped++
		default:
			entry.Status = StatusAmbiguous
			entry.Reason = "multiple function matches satisfy the old-version anchor"
			entry.Candidates = make([]Candidate, 0, len(matches))
			for _, match := range matches {
				entry.Candidates = append(entry.Candidates, candidateFrom(match))
			}
			sort.SliceStable(entry.Candidates, func(i, j int) bool {
				if entry.Candidates[i].Similarity != entry.Candidates[j].Similarity {
					return entry.Candidates[i].Similarity > entry.Candidates[j].Similarity
				}
				if entry.Candidates[i].OldRVA != entry.Candidates[j].OldRVA {
					return entry.Candidates[i].OldRVA < entry.Candidates[j].OldRVA
				}
				return entry.Candidates[i].NewRVA < entry.Candidates[j].NewRVA
			})
			result.Ambiguous++
		}
		result.Entries = append(result.Entries, entry)
	}
	return result, nil
}

func ValidateAnchors(anchors []Anchor) error {
	if len(anchors) == 0 || len(anchors) > 1000 {
		return errors.New("migration requires between 1 and 1000 anchors")
	}
	seen := make(map[string]bool, len(anchors))
	for index, anchor := range anchors {
		label := strings.TrimSpace(anchor.Label)
		if label == "" {
			return fmt.Errorf("anchor %d requires a label", index)
		}
		key := strings.ToLower(label)
		if seen[key] {
			return fmt.Errorf("duplicate anchor label %q", label)
		}
		seen[key] = true
		if anchor.OldRVA == nil && strings.TrimSpace(anchor.OldName) == "" {
			return fmt.Errorf("anchor %q requires old_rva and/or old_name", label)
		}
	}
	return nil
}

func selectMatches(matches []bindiff.FunctionMatch, oldRVA *uint64, oldName string, threshold int) []bindiff.FunctionMatch {
	normalizedName := strings.TrimSpace(oldName)
	result := make([]bindiff.FunctionMatch, 0, 1)
	for _, match := range matches {
		if match.Match != "MATCH" || math.IsNaN(match.Similarity) || math.IsInf(match.Similarity, 0) || match.Similarity < float64(threshold)/100 || match.Similarity > 1 {
			continue
		}
		if oldRVA != nil && match.OldRVA != *oldRVA {
			continue
		}
		if normalizedName != "" && strings.TrimSpace(match.OldName) != normalizedName {
			continue
		}
		result = append(result, match)
	}
	return result
}

func fillMapped(entry *Entry, match bindiff.FunctionMatch) {
	entry.OldRVA = match.OldRVA
	entry.OldName = match.OldName
	entry.NewRVA = match.NewRVA
	entry.NewName = match.NewName
	entry.Similarity = match.Similarity
	entry.Confidence = candidateConfidence(match.Similarity)
	entry.Match = match.Match
}

func candidateFrom(match bindiff.FunctionMatch) Candidate {
	return Candidate{
		OldRVA:     match.OldRVA,
		OldName:    match.OldName,
		NewRVA:     match.NewRVA,
		NewName:    match.NewName,
		Similarity: match.Similarity,
		Confidence: candidateConfidence(match.Similarity),
		Match:      match.Match,
	}
}

// Confidence describes the engine score only, never a runtime validation.
func candidateConfidence(score float64) string {
	switch {
	case score == 1:
		return "exact"
	case score >= 0.9:
		return "high"
	case score >= 0.75:
		return "medium"
	default:
		return "low"
	}
}

func cloneUint64(value *uint64) *uint64 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
