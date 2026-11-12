package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestP2SecurityToolsRemainObservationOrPlanOnly(t *testing.T) {
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
	client := mcp.NewClient(&mcp.Implementation{Name: "p2-test", Version: "1.0.0"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	call := func(name string, args map[string]any, out any) {
		t.Helper()
		res, e := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if e != nil || res == nil || res.IsError {
			t.Fatalf("%s result=%#v err=%v", name, res, e)
		}
		if out != nil {
			decodeStructured(t, res.StructuredContent, out)
		}
	}

	graph := filepath.Join(root, "graph.json")
	if err := os.WriteFile(graph, []byte(`{"source_kind":"test","nodes":[{"id":"u","kind":"identity"},{"id":"h","kind":"host"}],"edges":[{"from":"u","to":"h","kind":"admin-of"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var gr struct {
		Graph struct {
			SHA256 string `json:"sha256"`
		} `json:"graph"`
		Path *struct {
			Found bool `json:"found"`
		} `json:"path"`
	}
	call("attack_graph_import", map[string]any{"path": graph, "from": "u", "to": "h"}, &gr)
	if gr.Graph.SHA256 == "" || gr.Path == nil || !gr.Path.Found {
		t.Fatalf("graph=%+v", gr)
	}

	cloud := filepath.Join(root, "cloud.json")
	if err := os.WriteFile(cloud, []byte(`{"provider":"gcp","scope_id":"project","resources":[{"id":"role/a","type":"role"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var cr struct {
		Report struct {
			ReadOnly bool `json:"read_only"`
		} `json:"report"`
	}
	call("cloud_inventory_import", map[string]any{"path": cloud}, &cr)
	if !cr.Report.ReadOnly {
		t.Fatalf("cloud=%+v", cr)
	}

	stix := filepath.Join(root, "stix.json")
	if err := os.WriteFile(stix, []byte(`{"type":"bundle","id":"bundle--1","objects":[{"type":"indicator","id":"indicator--1"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var sr struct {
		Report struct {
			Objects []any `json:"objects"`
		} `json:"report"`
	}
	call("cti_stix_import", map[string]any{"path": stix}, &sr)
	if len(sr.Report.Objects) != 1 {
		t.Fatalf("stix=%+v", sr)
	}

	var hp struct {
		Plan struct {
			ExecutionPerformed bool `json:"execution_performed"`
		} `json:"plan"`
	}
	call("hunt_plan", map[string]any{"hypothesis": "persistence", "telemetry": []string{"Sysmon"}}, &hp)
	if hp.Plan.ExecutionPerformed {
		t.Fatalf("hunt=%+v", hp)
	}

	fw := filepath.Join(root, "fw.bin")
	if err := os.WriteFile(fw, []byte("hsqsfixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	var fr struct {
		Report struct {
			ReadOnly bool   `json:"read_only"`
			Format   string `json:"format"`
		} `json:"report"`
	}
	call("firmware_inspect", map[string]any{"path": fw}, &fr)
	if !fr.Report.ReadOnly || fr.Report.Format != "squashfs" {
		t.Fatalf("fw=%+v", fr)
	}
}
