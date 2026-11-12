package sourceaudit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestImportSARIFProducesUnverifiedCandidates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "results.sarif")
	body := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Semgrep","semanticVersion":"1.0.0"}},"results":[{"ruleId":"CWE-79","level":"warning","message":{"text":"candidate XSS"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"web.go"},"region":{"startLine":12}}}],"partialFingerprints":{"primaryLocationLineHash":"abc"}}]}]}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ImportSARIF(path, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != "2.1.0" || len(got.Candidates) != 1 || got.Candidates[0].Strength != "unverified" || got.Candidates[0].ToolName != "Semgrep" || got.Candidates[0].Locations[0].StartLine != 12 {
		t.Fatalf("sarif=%+v", got)
	}
}

func TestImportCycloneDXAndSPDX(t *testing.T) {
	root := t.TempDir()
	cdx := filepath.Join(root, "bom.json")
	if err := os.WriteFile(cdx, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"demo","version":"1.2.3","purl":"pkg:generic/demo@1.2.3","licenses":[{"license":{"id":"MIT"}}]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ImportSBOM(cdx, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got.Format != "cyclonedx" || len(got.Components) != 1 || got.Components[0].License != "MIT" {
		t.Fatalf("cdx=%+v", got)
	}

	spdx := filepath.Join(root, "spdx.json")
	if err := os.WriteFile(spdx, []byte(`{"spdxVersion":"SPDX-2.3","packages":[{"name":"demo","versionInfo":"1.2.3","licenseDeclared":"Apache-2.0","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:generic/demo@1.2.3"}]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = ImportSBOM(spdx, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got.Format != "spdx" || len(got.Components) != 1 || got.Components[0].PURL != "pkg:generic/demo@1.2.3" {
		t.Fatalf("spdx=%+v", got)
	}
}
