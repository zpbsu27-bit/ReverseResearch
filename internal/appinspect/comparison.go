package appinspect

import (
	"encoding/json"
	"errors"
	"reverseresearch/internal/recordio"
	"sort"
	"strings"
)

type CompareOptions struct {
	PageOptions
	ExpectedLeftSHA256  string `json:"expected_left_sha256,omitempty"`
	ExpectedRightSHA256 string `json:"expected_right_sha256,omitempty"`
}
type StaticChange struct {
	Kind         string `json:"kind"`
	Identity     string `json:"identity"`
	LeftCount    int    `json:"left_count"`
	RightCount   int    `json:"right_count"`
	LeftToken    string `json:"left_token,omitempty"`
	RightToken   string `json:"right_token,omitempty"`
	ILComparable bool   `json:"il_comparable"`
	SameILBytes  bool   `json:"same_il_bytes"`
}
type StaticComparison struct {
	LeftPath           string         `json:"left_path"`
	RightPath          string         `json:"right_path"`
	LeftSHA256         string         `json:"left_sha256"`
	RightSHA256        string         `json:"right_sha256"`
	ComparisonSHA256   string         `json:"comparison_sha256"`
	TotalItems         int            `json:"total_items"`
	Offset             int            `json:"offset"`
	Items              []StaticChange `json:"items"`
	NextOffset         *int           `json:"next_offset,omitempty"`
	CoverageComplete   bool           `json:"coverage_complete"`
	EvidenceAuthority  string         `json:"evidence_authority"`
	ExecutionPerformed bool           `json:"execution_performed"`
	Limitations        []string       `json:"limitations"`
}

func compareResult(lp, rp, lh, rh, kind string, o CompareOptions, items []StaticChange) (StaticComparison, error) {
	body, _ := json.Marshal([]string{"rr-static-comparison-v2", kind, lp, rp, lh, rh})
	hash := digest(body)
	if err := recordio.CheckExpectedSHA256(hash, o.ExpectedSHA256); err != nil {
		return StaticComparison{}, err
	}
	start, end, err := page(o.PageOptions, len(items))
	if err != nil {
		return StaticComparison{}, err
	}
	r := StaticComparison{LeftPath: lp, RightPath: rp, LeftSHA256: lh, RightSHA256: rh, ComparisonSHA256: hash, TotalItems: len(items), Offset: start, Items: items[start:end], CoverageComplete: start == 0 && end == len(items), EvidenceAuthority: "static-artifact-comparison", Limitations: []string{"declaration matches are candidates, not proven cross-build function identity or behavior equivalence", "IL byte equality excludes headers/locals/EH and is not a semantic fingerprint across token reassignment", "JavaScript comparison covers the declared AST vocabulary only, not full exports/control flow"}}
	if end < len(items) {
		r.NextOffset = &end
	}
	return r, projectionLimit(r)
}
func readPair(l, r string, o CompareOptions) ([]byte, []byte, string, string, string, string, error) {
	lb, lp, lh, err := readArtifact(l, MaxArtifactBytes, o.ExpectedLeftSHA256)
	if err != nil {
		return nil, nil, "", "", "", "", err
	}
	rb, rp, rh, err := readArtifact(r, MaxArtifactBytes, o.ExpectedRightSHA256)
	if err != nil {
		return nil, nil, "", "", "", "", err
	}
	return lb, rb, lp, rp, lh, rh, nil
}
func CompareJavaScript(l, r string, o CompareOptions) (StaticComparison, error) {
	lb, rb, lp, rp, lh, rh, err := readPair(l, r, o)
	if err != nil {
		return StaticComparison{}, err
	}
	lf, err := javascriptFacts(lb)
	if err != nil {
		return StaticComparison{}, err
	}
	rf, err := javascriptFacts(rb)
	if err != nil {
		return StaticComparison{}, err
	}
	left, right := map[string]int{}, map[string]int{}
	key := func(f JavaScriptFact) string {
		bundleKey := func(b *JavaScriptBundle) *JavaScriptBundle {
			if b == nil {
				return nil
			}
			copy := *b
			copy.SourceRange = nil
			copy.Registration = 0
			copy.ModuleIndex = nil
			if strings.HasPrefix(copy.Runtime, "webpack-bootstrap@ast:") {
				copy.Runtime = "webpack-bootstrap"
			}
			return &copy
		}
		b, _ := json.Marshal([]any{f.Kind, f.Callee, f.Value, f.Dynamic, f.LocalName, f.ExportName, f.Module, f.ValueKind, bundleKey(f.Bundle), bundleKey(f.BundleTarget)})
		return string(b)
	}
	for _, f := range lf {
		left[key(f)]++
	}
	for _, f := range rf {
		right[key(f)]++
	}
	keys := map[string]bool{}
	for k := range left {
		keys[k] = true
	}
	for k := range right {
		keys[k] = true
	}
	sorted := []string{}
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	items := []StaticChange{}
	for _, k := range sorted {
		kind := "same-declaration-count"
		if left[k] != right[k] {
			kind = "changed-declaration-count"
		}
		items = append(items, StaticChange{Kind: kind, Identity: k, LeftCount: left[k], RightCount: right[k]})
	}
	return compareResult(lp, rp, lh, rh, "javascript-bundle-v3", o, items)
}
func CompareManaged(l, r string, o CompareOptions) (StaticComparison, error) {
	lb, rb, lp, rp, lh, rh, err := readPair(l, r, o)
	if err != nil {
		return StaticComparison{}, err
	}
	lm, err := parseMetadata(lb)
	if err != nil {
		return StaticComparison{}, err
	}
	rm, err := parseMetadata(rb)
	if err != nil {
		return StaticComparison{}, err
	}
	if lm.table == nil || rm.table == nil {
		return StaticComparison{}, errors.New("both artifacts require admitted CLI metadata")
	}
	lf, err := lm.methods()
	if err != nil {
		return StaticComparison{}, err
	}
	rf, err := rm.methods()
	if err != nil {
		return StaticComparison{}, err
	}
	left, right := map[string][]ManagedMethod{}, map[string][]ManagedMethod{}
	key := func(m ManagedMethod) string {
		b, _ := json.Marshal([]string{m.DeclaringType, m.Name, m.SignatureSHA256})
		return string(b)
	}
	for _, f := range lf {
		left[key(f)] = append(left[key(f)], f)
	}
	for _, f := range rf {
		right[key(f)] = append(right[key(f)], f)
	}
	keys := map[string]bool{}
	for k := range left {
		keys[k] = true
	}
	for k := range right {
		keys[k] = true
	}
	sorted := []string{}
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	items := []StaticChange{}
	budget := 0
	start, end, err := page(o.PageOptions, len(sorted))
	if err != nil {
		return StaticComparison{}, err
	}
	for _, k := range sorted {
		ls, rs := left[k], right[k]
		item := StaticChange{Identity: k, LeftCount: len(ls), RightCount: len(rs), Kind: "candidate-match"}
		switch {
		case len(ls) > 1 || len(rs) > 1:
			item.Kind = "ambiguous-declaration"
		case len(ls) == 0:
			item.Kind = "added-declaration"
		case len(rs) == 0:
			item.Kind = "removed-declaration"
		default:
			item.LeftToken = ls[0].Token
			item.RightToken = rs[0].Token
			// Inspect the selected page's bodies only; inventory does not promise
			// whole-assembly IL validation. Never resolve ambiguity by name alone.
			if len(items) >= start && len(items) < end {
				a, _, err := lm.methodBody(ls[0])
				if err != nil {
					return StaticComparison{}, err
				}
				b, _, err := rm.methodBody(rs[0])
				if err != nil {
					return StaticComparison{}, err
				}
				budget += len(a) + len(b)
				if budget > 32<<20 {
					return StaticComparison{}, errors.New("comparison IL byte budget exceeded; reduce limit")
				}
				item.ILComparable = a != nil && b != nil
				item.SameILBytes = item.ILComparable && digest(a) == digest(b)
			}
		}
		items = append(items, item)
	}
	return compareResult(lp, rp, lh, rh, "managed", o, items)
}
