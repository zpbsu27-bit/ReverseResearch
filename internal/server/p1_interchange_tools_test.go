package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestP1InterchangeToolsStayObservationOnly(t *testing.T) {
	root, _ := isolatedServerRoot(t)
	runtime, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	go func() { _ = runtime.Run(ctx, serverTransport) }()
	client := mcp.NewClient(&mcp.Implementation{Name: "p1-interchange-test", Version: "1.0.0"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	call := func(name string, args map[string]any, out any) {
		t.Helper()
		result, callErr := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if callErr != nil || result == nil || result.IsError {
			t.Fatalf("%s failed: result=%#v err=%v", name, result, callErr)
		}
		if out != nil {
			decodeStructured(t, result.StructuredContent, out)
		}
	}

	sarifPath := filepath.Join(root, "result.sarif")
	if err := os.WriteFile(sarifPath, []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Semgrep"}},"results":[{"ruleId":"CWE-79","message":{"text":"candidate"}}]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var sarif struct {
		Report struct {
			Candidates []struct {
				Strength string `json:"strength"`
			} `json:"candidates"`
		} `json:"report"`
	}
	call("sarif_import", map[string]any{"path": sarifPath}, &sarif)
	if len(sarif.Report.Candidates) != 1 || sarif.Report.Candidates[0].Strength != "unverified" {
		t.Fatalf("sarif=%+v", sarif)
	}

	sbomPath := filepath.Join(root, "bom.json")
	if err := os.WriteFile(sbomPath, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"demo","version":"1"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var sbom struct {
		Report struct {
			Format     string `json:"format"`
			Components []any  `json:"components"`
		} `json:"report"`
	}
	call("sbom_import", map[string]any{"path": sbomPath}, &sbom)
	if sbom.Report.Format != "cyclonedx" || len(sbom.Report.Components) != 1 {
		t.Fatalf("sbom=%+v", sbom)
	}

	model := filepath.Join(root, "model.json")
	fixtures := filepath.Join(root, "fixtures.json")
	if err := os.WriteFile(model, []byte(`[{"hex":"0500102035"},{"hex":"060010212258"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixtures, []byte(`[{"hex":"060055667738"},{"hex":"070099aabbccdd72"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	var protocol struct {
		Analysis struct {
			CorpusSHA256 string `json:"corpus_sha256"`
		} `json:"analysis"`
		Validation struct {
			FixtureCorpusSHA256 string `json:"fixture_corpus_sha256"`
			Checks              []any  `json:"checks"`
		} `json:"validation"`
	}
	call("protocol_validate", map[string]any{"model_samples_path": model, "fixtures_path": fixtures, "name": "demo"}, &protocol)
	if protocol.Analysis.CorpusSHA256 == protocol.Validation.FixtureCorpusSHA256 || len(protocol.Validation.Checks) == 0 {
		t.Fatalf("protocol=%+v", protocol)
	}
}
