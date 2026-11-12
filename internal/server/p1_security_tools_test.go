package server

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestP1SecurityToolsPersistEvidenceFirstCases(t *testing.T) {
	root, sourceRoot := isolatedServerRoot(t)
	runtime, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	go func() { _ = runtime.Run(ctx, serverTransport) }()

	client := mcp.NewClient(&mcp.Implementation{Name: "p1-security-test", Version: "1.0.0"}, nil)
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

	var malwareCase struct {
		ID string `json:"id"`
	}
	call("case_create", map[string]any{"title": "malware triage", "route": "malware-analysis"}, &malwareCase)
	var triage struct {
		Report struct {
			StaticOnly               bool `json:"static_only"`
			SampleExecutionPerformed bool `json:"sample_execution_performed"`
			NetworkInteraction       bool `json:"network_interaction"`
		} `json:"report"`
		Artifact *struct {
			ID string `json:"id"`
		} `json:"artifact"`
		Evidence *struct {
			ID string `json:"id"`
		} `json:"evidence"`
		Observation *struct {
			ID string `json:"id"`
		} `json:"observation"`
	}
	call("malware_triage", map[string]any{
		"path":    filepath.Join(sourceRoot, "testdata", "mcp-smoke.exe"),
		"case_id": malwareCase.ID, "use_die": false, "max_strings": 32,
	}, &triage)
	if !triage.Report.StaticOnly || triage.Report.SampleExecutionPerformed || triage.Report.NetworkInteraction ||
		triage.Artifact == nil || triage.Evidence == nil || triage.Observation == nil {
		t.Fatalf("triage=%+v", triage)
	}

	var blueCase struct {
		ID string `json:"id"`
	}
	call("case_create", map[string]any{"title": "sigma validation", "route": "blue-detection"}, &blueCase)
	var validation struct {
		Validation struct {
			Validated bool `json:"validated"`
		} `json:"validation"`
		Evidence []struct {
			ID string `json:"id"`
		} `json:"evidence"`
		Detection *struct {
			ID        string `json:"id"`
			Validated bool   `json:"validated"`
		} `json:"detection"`
	}
	call("detection_sigma_validate", map[string]any{
		"rule_path":         filepath.Join(sourceRoot, "testdata", "detection", "sigma_scheduled_task.yml"),
		"positive_fixtures": []string{filepath.Join(sourceRoot, "testdata", "detection", "sigma_scheduled_task_positive.json")},
		"negative_fixtures": []string{filepath.Join(sourceRoot, "testdata", "detection", "sigma_scheduled_task_negative.json")},
		"case_id":           blueCase.ID, "technique": "T1053",
		"telemetry": []string{"Windows Event Log"}, "telemetry_available": true,
		"false_positive_notes": "known administrative tasks", "coverage": "scheduled task creation",
	}, &validation)
	if !validation.Validation.Validated || validation.Detection == nil || !validation.Detection.Validated || len(validation.Evidence) != 3 {
		t.Fatalf("validation=%+v", validation)
	}
}
