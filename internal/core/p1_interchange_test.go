package core

import (
	"os"
	"path/filepath"
	"testing"

	"reverseresearch/internal/casebook"
)

func TestP1InterchangeOwnersPreserveCandidateSemantics(t *testing.T) {
	root, _ := isolatedCoreRoot(t)
	service, err := New(root)
	if err != nil {
		t.Fatal(err)
	}

	sourceCase, err := service.CreateCase(casebook.CreateRequest{Title: "source", Route: "source-code-audit"})
	if err != nil {
		t.Fatal(err)
	}
	sarifPath := filepath.Join(root, "result.sarif")
	sarif := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Semgrep","semanticVersion":"1.0.0"}},"results":[{"ruleId":"CWE-79","level":"warning","message":{"text":"candidate XSS"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"web.go"},"region":{"startLine":12}}}]}]}]}`
	if err := os.WriteFile(sarifPath, []byte(sarif), 0o600); err != nil {
		t.Fatal(err)
	}
	imported, err := service.ImportSARIF(SARIFImportRequest{Path: sarifPath, CaseID: sourceCase.ID})
	if err != nil {
		t.Fatal(err)
	}
	if imported.Artifact == nil || imported.Evidence == nil || len(imported.Findings) != 1 {
		t.Fatalf("sarif=%+v", imported)
	}
	if imported.Findings[0].Strength != "unverified" || imported.Findings[0].Status != "candidate" || len(imported.Findings[0].CWE) != 1 {
		t.Fatalf("finding=%+v", imported.Findings[0])
	}

	supplyCase, err := service.CreateCase(casebook.CreateRequest{Title: "sbom", Route: "supply-chain"})
	if err != nil {
		t.Fatal(err)
	}
	sbomPath := filepath.Join(root, "bom.json")
	sbom := `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"demo","version":"1.2.3","purl":"pkg:generic/demo@1.2.3"}]}`
	if err := os.WriteFile(sbomPath, []byte(sbom), 0o600); err != nil {
		t.Fatal(err)
	}
	sbomResult, err := service.ImportSBOM(SBOMImportRequest{Path: sbomPath, CaseID: supplyCase.ID})
	if err != nil {
		t.Fatal(err)
	}
	if sbomResult.Artifact == nil || sbomResult.Evidence == nil || sbomResult.Observation == nil || len(sbomResult.Report.Components) != 1 {
		t.Fatalf("sbom=%+v", sbomResult)
	}
	got, err := service.GetCase(supplyCase.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Findings) != 0 {
		t.Fatalf("SBOM inventory incorrectly created vulnerability findings: %+v", got.Findings)
	}
}

func TestProtocolIndependentValidationPersistsBothCorpusIdentities(t *testing.T) {
	root, _ := isolatedCoreRoot(t)
	service, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	c, err := service.CreateCase(casebook.CreateRequest{Title: "protocol", Route: "traffic-protocol"})
	if err != nil {
		t.Fatal(err)
	}
	model := filepath.Join(root, "model.json")
	fixtures := filepath.Join(root, "fixtures.json")
	if err := os.WriteFile(model, []byte(`[
		{"name":"a","hex":"05001020aa"},
		{"name":"b","hex":"0600102122b9"},
		{"name":"c","hex":"070010303132aa"}
	]`), 0o600); err != nil {
		t.Fatal(err)
	}
	// Fixture checks need valid total-length and sum8 final byte.
	if err := os.WriteFile(fixtures, []byte(`[
		{"name":"v1","hex":"0600556677d8"},
		{"name":"v2","hex":"070099aabbccdd09"}
	]`), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := service.ValidateProtocol(ProtocolValidationRequest{ModelSamplesPath: model, FixturesPath: fixtures, CaseID: c.ID, Name: "demo"})
	if err != nil {
		t.Fatal(err)
	}
	if result.ModelSource.ID == result.FixtureSource.ID || len(result.Artifacts) != 2 || len(result.Evidence) != 2 || result.Observation == nil {
		t.Fatalf("validation=%+v", result)
	}
	if result.Validation.FixtureCorpusSHA256 == result.Analysis.CorpusSHA256 {
		t.Fatal("validation corpus was not independent")
	}
}
