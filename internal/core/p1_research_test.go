package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"reverseresearch/internal/casebook"
	"reverseresearch/internal/fuzz"
)

func TestPrepareSelectsP1ResearchPacks(t *testing.T) {
	root, _ := isolatedCoreRoot(t)
	service, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct{ task, route, playbook, pack string }{
		{"analyze this Linux ELF and record GNU build-id", "linux-native", "linux-native", "linux-native"},
		{"build a libFuzzer harness and dedupe sanitizer crashes", "vuln-research", "vuln-research", "vuln-research"},
		{"ingest EVTX MFT and Prefetch into a forensic timeline", "dfir-forensics", "dfir-forensics", "dfir"},
		{"reverse this pcap network protocol", "traffic-protocol", "protocol-reverse", "protocol"},
		{"audit this source repository with Semgrep and export SARIF", "source-code-audit", "source-code-audit", "code-audit"},
		{"inventory SBOM dependencies and secret candidates", "supply-chain", "source-code-audit", "code-audit"},
	}
	for _, tc := range tests {
		got, err := service.Prepare(tc.task)
		if err != nil {
			t.Fatalf("%s: %v", tc.task, err)
		}
		if got.Route.Route.ID != tc.route || got.Playbook == nil || got.Playbook.ID != tc.playbook ||
			got.DomainPack == nil || got.DomainPack.ID != tc.pack || len(got.KnowledgePacks) == 0 {
			t.Fatalf("%s prepare=%+v", tc.task, got)
		}
	}
}

func TestP1ResearchOwnersPersistBoundedCaseEvidence(t *testing.T) {
	root, _ := isolatedCoreRoot(t)
	service, err := New(root)
	if err != nil {
		t.Fatal(err)
	}

	dfirCase, err := service.CreateCase(casebook.CreateRequest{Title: "dfir", Route: "dfir-forensics"})
	if err != nil {
		t.Fatal(err)
	}
	evtx := filepath.Join(root, "fixture.evtx")
	if err := os.WriteFile(evtx, []byte("evtx-fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	dfirResult, err := service.InspectDFIRArtifact(DFIRInspectRequest{Path: evtx, CaseID: dfirCase.ID})
	if err != nil {
		t.Fatal(err)
	}
	if dfirResult.CaseArtifact == nil || dfirResult.Evidence == nil || dfirResult.Observation == nil {
		t.Fatalf("dfir=%+v", dfirResult)
	}

	timelinePath := filepath.Join(root, "events.jsonl")
	if err := os.WriteFile(timelinePath, []byte("{\"timestamp\":\"2026-10-02T10:00:00Z\",\"event\":\"process-start\",\"pid\":42}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	timelineResult, err := service.ImportDFIRTimeline(DFIRTimelineRequest{Path: timelinePath, Format: "generic-jsonl", CaseID: dfirCase.ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(timelineResult.Timeline.Entries) != 1 || timelineResult.Evidence == nil {
		t.Fatalf("timeline=%+v", timelineResult)
	}

	vulnCase, err := service.CreateCase(casebook.CreateRequest{Title: "vuln", Route: "vuln-research"})
	if err != nil {
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
	planResult, err := service.BuildFuzzPlan(FuzzPlanRequest{CaseID: vulnCase.ID, PlanRequest: fuzz.PlanRequest{
		TargetPath: target, Harness: harness, CorpusDir: corpus, Engine: fuzz.EngineLibFuzzer, Sanitizers: []string{"asan"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if planResult.Plan.Execution != "planned-only" || len(planResult.Artifacts) != 3 || planResult.Observation == nil {
		t.Fatalf("plan=%+v", planResult)
	}

	crashInput := filepath.Join(root, "crash.bin")
	if err := os.WriteFile(crashInput, []byte("crash"), 0o600); err != nil {
		t.Fatal(err)
	}
	crashResult, err := service.RecordCrash(CrashRecordRequest{CaseID: vulnCase.ID, InputPath: crashInput, Crash: fuzz.Crash{
		Exception: "SIGSEGV", Module: "libparser.so", FaultInstruction: "load", Frames: []fuzz.Frame{{Module: "libparser.so", Function: "parse", Offset: 1}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if crashResult.Fingerprint.ID == "" || crashResult.Evidence.ID == "" {
		t.Fatalf("crash=%+v", crashResult)
	}

	protocolCase, err := service.CreateCase(casebook.CreateRequest{Title: "protocol", Route: "traffic-protocol"})
	if err != nil {
		t.Fatal(err)
	}
	samplesPath := filepath.Join(root, "messages.json")
	samples := []map[string]string{{"name": "a", "hex": "05001020aa"}, {"name": "b", "hex": "0600102122b9"}}
	body, _ := json.Marshal(samples)
	if err := os.WriteFile(samplesPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	protocolResult, err := service.InferProtocolFile(ProtocolFileRequest{SamplesPath: samplesPath, CaseID: protocolCase.ID, Name: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	if protocolResult.Analysis.CorpusSHA256 == "" || protocolResult.Artifact == nil || protocolResult.Evidence == nil {
		t.Fatalf("protocol=%+v", protocolResult)
	}

	sourceCase, err := service.CreateCase(casebook.CreateRequest{Title: "source", Route: "source-code-audit"})
	if err != nil {
		t.Fatal(err)
	}
	repo := filepath.Join(root, "repo")
	if err := os.MkdirAll(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "go.mod"), []byte("module fixture\n\ngo 1.24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "main.go"), []byte("package fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sourceResult, err := service.AuditSource(SourceAuditRequest{Root: repo, CaseID: sourceCase.ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(sourceResult.Report.SnapshotSHA256) != 64 || sourceResult.Artifact == nil || sourceResult.Evidence == nil {
		t.Fatalf("source=%+v", sourceResult)
	}

	for _, caseID := range []string{dfirCase.ID, vulnCase.ID, protocolCase.ID, sourceCase.ID} {
		got, err := service.GetCase(caseID)
		if err != nil {
			t.Fatal(err)
		}
		if len(got.Evidence) == 0 || len(got.Observations) == 0 || len(got.Artifacts) == 0 {
			t.Fatalf("case %s missing persisted P1 objects: %+v", caseID, got)
		}
	}
}
