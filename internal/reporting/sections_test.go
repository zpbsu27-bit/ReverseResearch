package reporting

import (
	"strings"
	"testing"

	"reverseresearch/internal/casebook"
)

func TestFilterSectionsValidatesAndPrunes(t *testing.T) {
	doc := Document{
		Summary:  Summary{Findings: 2, Evidence: 1},
		Findings: []casebook.Finding{{ID: "f1"}},
		Evidence: []EvidenceRef{{ID: "e1", Summary: "proof"}},
	}
	got, err := FilterSections(doc, []string{"summary", "evidence"})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Includes("summary") || got.Includes("findings") {
		t.Fatalf("sections=%v", got.Sections)
	}
	if got.Findings != nil {
		t.Fatalf("findings were not pruned: %+v", got.Findings)
	}
	if len(got.Evidence) != 1 {
		t.Fatalf("evidence=%+v", got.Evidence)
	}
	if _, err := FilterSections(doc, []string{"shell"}); err == nil {
		t.Fatal("unknown section accepted")
	}
}

func TestFilteredMarkdownOmitsExcludedSections(t *testing.T) {
	doc := Document{
		Title: "demo", CaseID: "c", CaseSHA256: strings.Repeat("a", 64),
		Profile: "general", Classification: "internal",
		Summary:  Summary{Findings: 1, Evidence: 1},
		Findings: []casebook.Finding{{ID: "f1", Title: "issue", Conclusion: "x"}},
		Evidence: []EvidenceRef{{ID: "e1", Summary: "proof"}},
	}
	filtered, err := FilterSections(doc, []string{"summary", "evidence"})
	if err != nil {
		t.Fatal(err)
	}
	body, err := Render(filtered, "markdown")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if strings.Contains(text, "## Findings") {
		t.Fatalf("excluded findings section leaked: %s", text)
	}
	if !strings.Contains(text, "## Evidence") || !strings.Contains(text, "## Summary") {
		t.Fatalf("required sections missing: %s", text)
	}
}
