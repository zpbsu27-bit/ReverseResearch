package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	researchcore "reverseresearch/internal/core"
)

func TestP1InterchangeCLI(t *testing.T) {
	root, _ := isolatedCLIRoot(t)

	sarifPath := filepath.Join(root, "result.sarif")
	sarif := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Semgrep"}},"results":[{"ruleId":"CWE-79","message":{"text":"candidate"}}]}]}`
	if err := os.WriteFile(sarifPath, []byte(sarif), 0o600); err != nil {
		t.Fatal(err)
	}
	var sarifResult researchcore.SARIFImportResult
	if err := json.Unmarshal(p0CLI(t, root, "source", "sarif", sarifPath), &sarifResult); err != nil {
		t.Fatal(err)
	}
	if len(sarifResult.Report.Candidates) != 1 || sarifResult.Report.Candidates[0].Strength != "unverified" {
		t.Fatalf("sarif=%+v", sarifResult)
	}

	sbomPath := filepath.Join(root, "bom.json")
	if err := os.WriteFile(sbomPath, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"demo","version":"1"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var sbomResult researchcore.SBOMImportResult
	if err := json.Unmarshal(p0CLI(t, root, "source", "sbom", sbomPath), &sbomResult); err != nil {
		t.Fatal(err)
	}
	if sbomResult.Report.Format != "cyclonedx" || len(sbomResult.Report.Components) != 1 {
		t.Fatalf("sbom=%+v", sbomResult)
	}

	model := filepath.Join(root, "model.json")
	fixtures := filepath.Join(root, "fixtures.json")
	if err := os.WriteFile(model, []byte(`[{"hex":"0500102035"},{"hex":"060010212258"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixtures, []byte(`[{"hex":"060055667738"},{"hex":"070099aabbccdd72"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	var protocol researchcore.ProtocolValidationResult
	if err := json.Unmarshal(p0CLI(t, root, "protocol", "validate", "--model", model, "--fixtures", fixtures, "--name", "demo"), &protocol); err != nil {
		t.Fatal(err)
	}
	if protocol.Validation.FixtureCorpusSHA256 == protocol.Analysis.CorpusSHA256 || len(protocol.Validation.Checks) == 0 {
		t.Fatalf("protocol=%+v", protocol)
	}
}
