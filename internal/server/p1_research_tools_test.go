package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"reverseresearch/internal/casebook"
	"reverseresearch/internal/engagement"
)

func TestP1ResearchToolsAreBoundedAndPurplePlanDoesNotExecute(t *testing.T) {
	root, _ := isolatedServerRoot(t)
	runtime, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	go func() { _ = runtime.Run(ctx, serverTransport) }()
	client := mcp.NewClient(&mcp.Implementation{Name: "p1-research-test", Version: "1.0.0"}, nil)
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

	evtx := filepath.Join(root, "fixture.evtx")
	if err := os.WriteFile(evtx, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	var inspected struct {
		Artifact struct {
			ReadOnly bool   `json:"read_only"`
			Kind     string `json:"kind"`
		} `json:"artifact"`
	}
	call("dfir_artifact_inspect", map[string]any{"path": evtx}, &inspected)
	if !inspected.Artifact.ReadOnly || inspected.Artifact.Kind != "evtx" {
		t.Fatalf("dfir=%+v", inspected)
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
	var plan struct {
		Plan struct {
			Execution   string `json:"execution"`
			EffectClass string `json:"effect_class"`
		} `json:"plan"`
	}
	call("fuzz_plan", map[string]any{
		"target_path": target, "harness": harness, "corpus_dir": corpus,
		"engine": "libfuzzer", "sanitizers": []string{"asan"},
	}, &plan)
	if plan.Plan.Execution != "planned-only" || plan.Plan.EffectClass != "runtime mutation" {
		t.Fatalf("fuzz plan=%+v", plan)
	}

	var fp struct {
		ID string `json:"id"`
	}
	call("crash_fingerprint", map[string]any{
		"exception": "SIGSEGV", "module": "target", "fault_instruction": "load",
		"frames": []map[string]any{{"module": "target", "function": "parse", "offset": 1}},
	}, &fp)
	if fp.ID == "" {
		t.Fatal("missing crash fingerprint")
	}

	samplesPath := filepath.Join(root, "samples.json")
	if err := os.WriteFile(samplesPath, []byte(`[{"name":"a","hex":"05001020aa"},{"name":"b","hex":"0600102122b9"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	var protocol struct {
		Analysis struct {
			CorpusSHA256 string `json:"corpus_sha256"`
			Strength     string `json:"strength"`
		} `json:"analysis"`
	}
	call("protocol_infer", map[string]any{"samples_path": samplesPath, "name": "fixture"}, &protocol)
	if len(protocol.Analysis.CorpusSHA256) != 64 || protocol.Analysis.Strength != "candidate" {
		t.Fatalf("protocol=%+v", protocol)
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
	var audit struct {
		Report struct {
			SnapshotSHA256   string `json:"snapshot_sha256"`
			SecretCandidates []struct {
				Redacted string `json:"redacted"`
			} `json:"secret_candidates"`
		} `json:"report"`
	}
	call("source_audit", map[string]any{"root": repo}, &audit)
	if len(audit.Report.SnapshotSHA256) != 64 || len(audit.Report.SecretCandidates) != 1 || audit.Report.SecretCandidates[0].Redacted == "super-secret-value" {
		t.Fatalf("source audit=%+v", audit)
	}

	eng, err := runtime.core.CreateEngagement(engagement.CreateRequest{
		Organization: "Lab", Operator: "analyst",
		Scope: engagement.Scope{
			Targets: []string{"lab-host"}, AllowedActions: []string{"emulate-t1053"},
			Authorization:  engagement.Authorization{Status: "granted", Basis: "lab_only"},
			NetworkProfile: engagement.NetworkProfile{Mode: "lab_only"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	c, err := runtime.core.CreateCase(casebook.CreateRequest{
		Title: "purple", Route: "purple-validation", EngagementID: eng.ID,
		Targets: []casebook.Target{{ID: "target_lab", Identity: "lab-host"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.core.AddCaseTTP(c.ID, casebook.TTPRequest{Technique: "T1053", Tactic: "Persistence"}); err != nil {
		t.Fatal(err)
	}

	var coverage struct {
		TotalTechniques int `json:"total_techniques"`
	}
	call("purple_coverage", map[string]any{"case_id": c.ID}, &coverage)
	if coverage.TotalTechniques != 1 {
		t.Fatalf("coverage=%+v", coverage)
	}

	var purplePlan struct {
		Job struct {
			State string `json:"state"`
		} `json:"job"`
		ExecutionPerformed bool `json:"execution_performed"`
	}
	call("purple_emulation_plan", map[string]any{
		"case_id": c.ID, "technique": "T1053", "target": "lab-host", "action": "emulate-t1053",
		"effect_class": "runtime mutation", "operation_id": "mcp-purple-plan",
	}, &purplePlan)
	if purplePlan.Job.State != "prepared" || purplePlan.ExecutionPerformed {
		t.Fatalf("purple plan=%+v", purplePlan)
	}
}
