package main

import (
	"archive/zip"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	researchcore "reverseresearch/internal/core"
)

func TestP2SecurityCLIObservationOnly(t *testing.T) {
	root, _ := isolatedCLIRoot(t)

	graph := filepath.Join(root, "graph.json")
	if err := os.WriteFile(graph, []byte(`{"source_kind":"test","nodes":[{"id":"u","kind":"identity"},{"id":"h","kind":"host"}],"edges":[{"from":"u","to":"h","kind":"admin-of"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var gr researchcore.AttackGraphImportResult
	if err := json.Unmarshal(p0CLI(t, root, "attackgraph", "import", graph, "--from", "u", "--to", "h"), &gr); err != nil {
		t.Fatal(err)
	}
	if gr.Path == nil || !gr.Path.Found || gr.Graph.SHA256 == "" {
		t.Fatalf("graph=%+v", gr)
	}

	cloud := filepath.Join(root, "cloud.json")
	if err := os.WriteFile(cloud, []byte(`{"provider":"aws","scope_id":"acct","resources":[{"id":"r1","type":"role"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var cr researchcore.CloudInventoryResult
	if err := json.Unmarshal(p0CLI(t, root, "cloud", "inventory", cloud), &cr); err != nil {
		t.Fatal(err)
	}
	if !cr.Report.ReadOnly {
		t.Fatalf("cloud=%+v", cr)
	}

	stix := filepath.Join(root, "stix.json")
	if err := os.WriteFile(stix, []byte(`{"type":"bundle","id":"bundle--1","objects":[{"type":"indicator","id":"indicator--1"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var sr researchcore.STIXImportResult
	if err := json.Unmarshal(p0CLI(t, root, "cti", "import", stix), &sr); err != nil {
		t.Fatal(err)
	}
	if len(sr.Report.Objects) != 1 {
		t.Fatalf("stix=%+v", sr)
	}

	var hr researchcore.HuntPlanResult
	if err := json.Unmarshal(p0CLI(t, root, "hunt", "plan", "--hypothesis", "persistence", "--telemetry", "Sysmon", "--techniques", "T1053"), &hr); err != nil {
		t.Fatal(err)
	}
	if hr.Plan.ExecutionPerformed {
		t.Fatalf("hunt=%+v", hr)
	}

	ipa := filepath.Join(root, "demo.ipa")
	f, err := os.Create(ipa)
	if err != nil {
		t.Fatal(err)
	}
	z := zip.NewWriter(f)
	w, _ := z.Create("Payload/Demo.app/Info.plist")
	_, _ = w.Write([]byte("plist"))
	w, _ = z.Create("Payload/Demo.app/Demo")
	_, _ = w.Write([]byte{0xcf, 0xfa, 0xed, 0xfe, 1})
	_ = z.Close()
	_ = f.Close()
	var ir researchcore.IOSInspectResult
	if err := json.Unmarshal(p0CLI(t, root, "ios", "inspect", ipa), &ir); err != nil {
		t.Fatal(err)
	}
	if !ir.Report.ReadOnly {
		t.Fatalf("ios=%+v", ir)
	}

	fw := filepath.Join(root, "fw.bin")
	if err := os.WriteFile(fw, []byte("hsqsfixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	var fr researchcore.FirmwareInspectResult
	if err := json.Unmarshal(p0CLI(t, root, "firmware", "inspect", fw), &fr); err != nil {
		t.Fatal(err)
	}
	if fr.Report.Format != "squashfs" || !fr.Report.ReadOnly {
		t.Fatalf("fw=%+v", fr)
	}
}
