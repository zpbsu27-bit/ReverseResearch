package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"reverseresearch/internal/casebook"
	researchcore "reverseresearch/internal/core"
	"reverseresearch/internal/fuzz"
)

func TestP1ResearchCLIFlows(t *testing.T) {
	root, _ := isolatedCLIRoot(t)

	var dfirCase casebook.Case
	if err := json.Unmarshal(p0CLI(t, root, "case", "create", "--title", "dfir", "--route", "dfir-forensics"), &dfirCase); err != nil {
		t.Fatal(err)
	}
	evtx := filepath.Join(root, "fixture.evtx")
	if err := os.WriteFile(evtx, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	var inspected researchcore.DFIRInspectResult
	if err := json.Unmarshal(p0CLI(t, root, "dfir", "inspect", evtx, "--case", dfirCase.ID), &inspected); err != nil {
		t.Fatal(err)
	}
	if inspected.CaseArtifact == nil || inspected.Evidence == nil || !inspected.Artifact.ReadOnly {
		t.Fatalf("dfir=%+v", inspected)
	}

	var vulnCase casebook.Case
	if err := json.Unmarshal(p0CLI(t, root, "case", "create", "--title", "fuzz", "--route", "vuln-research"), &vulnCase); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target.bin")
	harness := filepath.Join(root, "harness.bin")
	corpus := filepath.Join(root, "corpus")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(harness, []byte("harness"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(corpus, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(corpus, "seed"), []byte("seed"), 0o600); err != nil {
		t.Fatal(err)
	}
	var plan researchcore.FuzzPlanResult
	if err := json.Unmarshal(p0CLI(t, root, "fuzz", "plan",
		"--target", target, "--harness", harness, "--corpus", corpus, "--engine", "libfuzzer", "--sanitizers", "asan", "--case", vulnCase.ID,
	), &plan); err != nil {
		t.Fatal(err)
	}
	if plan.Plan.Execution != "planned-only" || plan.Plan.EffectClass != "runtime mutation" || len(plan.Artifacts) != 3 {
		t.Fatalf("plan=%+v", plan)
	}

	crashPath := filepath.Join(root, "crash.json")
	crash := fuzz.Crash{Exception: "SIGSEGV", Module: "target", FaultInstruction: "load", Frames: []fuzz.Frame{{Module: "target", Function: "parse", Offset: 1}}}
	body, _ := json.Marshal(crash)
	if err := os.WriteFile(crashPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	var fingerprint fuzz.Fingerprint
	if err := json.Unmarshal(p0CLI(t, root, "crash", "fingerprint", "--json", crashPath), &fingerprint); err != nil {
		t.Fatal(err)
	}
	if fingerprint.ID == "" {
		t.Fatalf("fingerprint=%+v", fingerprint)
	}

	var protocolCase casebook.Case
	if err := json.Unmarshal(p0CLI(t, root, "case", "create", "--title", "protocol", "--route", "traffic-protocol"), &protocolCase); err != nil {
		t.Fatal(err)
	}
	samplesPath := filepath.Join(root, "samples.json")
	if err := os.WriteFile(samplesPath, []byte(`[{"name":"a","hex":"05001020aa"},{"name":"b","hex":"0600102122b9"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	var protocol researchcore.ProtocolFileResult
	if err := json.Unmarshal(p0CLI(t, root, "protocol", "infer", "--samples", samplesPath, "--case", protocolCase.ID, "--name", "fixture"), &protocol); err != nil {
		t.Fatal(err)
	}
	if protocol.Analysis.CorpusSHA256 == "" || protocol.Evidence == nil {
		t.Fatalf("protocol=%+v", protocol)
	}

	var sourceCase casebook.Case
	if err := json.Unmarshal(p0CLI(t, root, "case", "create", "--title", "source", "--route", "source-code-audit"), &sourceCase); err != nil {
		t.Fatal(err)
	}
	repo := filepath.Join(root, "repo")
	if err := os.MkdirAll(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "go.mod"), []byte("module demo\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "main.go"), []byte("package main\nvar apiKey = \"super-secret-value\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var audit researchcore.SourceAuditResult
	if err := json.Unmarshal(p0CLI(t, root, "source", "audit", repo, "--case", sourceCase.ID), &audit); err != nil {
		t.Fatal(err)
	}
	if audit.Artifact == nil || len(audit.Report.SnapshotSHA256) != 64 || len(audit.Report.SecretCandidates) != 1 {
		t.Fatalf("audit=%+v", audit)
	}
}

func TestP1PurpleCLIReadOnlyCoverage(t *testing.T) {
	root, _ := isolatedCLIRoot(t)
	var c casebook.Case
	if err := json.Unmarshal(p0CLI(t, root, "case", "create", "--title", "purple", "--route", "purple-validation"), &c); err != nil {
		t.Fatal(err)
	}
	p0CLI(t, root, "case", "ttp", c.ID, "--technique", "T1053", "--tactic", "Persistence")
	var coverage map[string]any
	if err := json.Unmarshal(p0CLI(t, root, "purple", "coverage", c.ID), &coverage); err != nil {
		t.Fatal(err)
	}
	if coverage["total_techniques"] == nil {
		t.Fatalf("coverage=%+v", coverage)
	}
}
