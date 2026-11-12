package router

import (
	"path/filepath"
	"testing"
)

func TestNativeFieldTrialDoesNotAcquireCTIFromFunctionSubstring(t *testing.T) {
	engine, err := Load(filepath.Join("..", "..", "config", "routes.json"))
	if err != nil {
		t.Fatal(err)
	}
	text := "Read-only x86 PE H3 HD_SOD.dll function branch and callback provenance static reverse engineering"
	result := engine.Route(text)
	if result.Route.ID != "unclassified" {
		t.Fatalf("unrecognized query must remain unclassified, got %+v", result)
	}
	if len(result.MatchedKeywords) != 0 || len(result.Candidates) != 0 {
		t.Fatalf("route invented keyword evidence: %+v", result)
	}
	for _, text := range []string{"CTI analysis", "function then CTI", "CTI分析", "分析CTI", "function_cti_mode"} {
		result := engine.Route(text)
		if result.Route.ID != "cti-analysis" {
			t.Fatalf("explicit CTI request %q lost its route: %+v", text, result)
		}
	}
	result = engine.Route("native binary function analysis HD_SOD.dll")
	if result.Route.ID != "native-static" {
		t.Fatalf("explicit native question lost its route: %+v", result)
	}
}

func TestKeywordBoundariesKeepChinesePunctuationAndLaterRealMatches(t *testing.T) {
	for _, tc := range []struct {
		text, keyword string
		want          bool
	}{
		{"function", "cti", false},
		{"functions", "cti", false},
		{"option", "opt", false},
		{"open", "pe", false},
		{"httpx", "http", false},
		{"notfunction", "function", false},
		{"function2", "function", false},
		{"function and cti", "cti", true},
		{"function then function analysis", "function analysis", true},
		{"cti_mode", "cti", true},
		{"report.stix", "stix", true},
		{"stix2", "stix", false},
		{"HD_SOD.dll", ".dll", true},
		{"HD_SOD.dllx", ".dll", false},
		{"分析cti来源", "cti", true},
		{"需要函数分析结果", "函数分析", true},
		{"", "cti", false},
		{"cti", "", false},
		{"x", "longer", false},
	} {
		if got := keywordMatches(tc.text, tc.keyword); got != tc.want {
			t.Errorf("%q / %q = %v, want %v", tc.text, tc.keyword, got, tc.want)
		}
	}
}
