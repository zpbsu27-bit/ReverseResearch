package reporting

import (
	"encoding/json"
	"reverseresearch/internal/casebook"
	"strings"
	"testing"
	"time"
)

func TestBuildAndRenderProjectionFormats(t *testing.T) {
	c := casebook.Case{ID: "case_1", Title: "Demo", Route: "vuln-research", EngagementID: "eng_1",
		Findings: []casebook.Finding{{ID: "f1", Title: "Bounds issue", Conclusion: "observed crash", Strength: "observed", Severity: "high", CWE: []string{"CWE-787"}, EvidenceIDs: []string{"e1"}}},
		Evidence: []casebook.Evidence{{ID: "e1", Summary: "crash dump", SourceSHA256: strings.Repeat("a", 64)}},
		TTPs:     []casebook.TTP{{ID: "t1", Technique: "T1053"}},
		IOCs:     []casebook.IOC{{ID: "ioc1", Type: "domain-name", Value: "example.invalid"}},
	}
	doc, err := Build(c, strings.Repeat("b", 64), "vulnerability", "internal")
	if err != nil {
		t.Fatal(err)
	}
	if doc.Summary.Observed != 1 || doc.Summary.Findings != 1 {
		t.Fatalf("doc=%+v", doc.Summary)
	}
	for _, format := range SupportedFormats() {
		body, err := Render(doc, format)
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		if len(body) == 0 {
			t.Fatalf("%s empty", format)
		}
		if format == "sarif" {
			var v map[string]any
			if err := json.Unmarshal(body, &v); err != nil {
				t.Fatal(err)
			}
			if v["version"] != "2.1.0" {
				t.Fatalf("sarif=%v", v)
			}
		}
	}
}
func TestReportOmitsRawEvidenceExcerpt(t *testing.T) {
	c := casebook.Case{ID: "c", Title: "x", Evidence: []casebook.Evidence{{ID: "e", Summary: "safe", RawExcerpt: "SECRET"}}}
	doc, _ := Build(c, strings.Repeat("c", 64), "general", "internal")
	body, _ := Render(doc, "json")
	if strings.Contains(string(body), "SECRET") {
		t.Fatal("raw evidence excerpt leaked into report projection")
	}
}

func TestProjectionIdentityIgnoresGenerationTimeButTracksTemplateAndSections(t *testing.T) {
	c := casebook.Case{ID: "case_det", Title: "Deterministic", Findings: []casebook.Finding{{ID: "f1", Title: "x", Conclusion: "y", Strength: "observed"}}}
	caseSHA := strings.Repeat("d", 64)
	first, err := Build(c, caseSHA, "general", "internal")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond)
	second, err := Build(c, caseSHA, "general", "internal")
	if err != nil {
		t.Fatal(err)
	}
	if first.GeneratedUTC == second.GeneratedUTC {
		t.Fatal("expected independent generation timestamps")
	}
	if first.ProjectionSHA256 == "" || first.ProjectionSHA256 != second.ProjectionSHA256 {
		t.Fatalf("projection identity changed across generation time: %q vs %q", first.ProjectionSHA256, second.ProjectionSHA256)
	}
	if first.TemplateID != "builtin/general" || first.TemplateVersion != TemplateVersion || first.RendererVersion != RendererVersion {
		t.Fatalf("template metadata=%+v", first)
	}
	filtered, err := FilterSections(first, []string{"summary"})
	if err != nil {
		t.Fatal(err)
	}
	if filtered.ProjectionSHA256 == first.ProjectionSHA256 {
		t.Fatal("section selection did not change projection identity")
	}
}
