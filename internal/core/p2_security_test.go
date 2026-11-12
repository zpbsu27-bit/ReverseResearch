package core

import (
	"archive/zip"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"reverseresearch/internal/attackgraph"
	"reverseresearch/internal/casebook"
)

func TestP2AttackCloudCTIOwnersPersistObservationOnly(t *testing.T) {
	root, _ := isolatedCoreRoot(t)
	service, err := New(root)
	if err != nil {
		t.Fatal(err)
	}

	attackCase, err := service.CreateCase(casebook.CreateRequest{Title: "identity", Route: "identity-ad"})
	if err != nil {
		t.Fatal(err)
	}
	graphPath := filepath.Join(root, "graph.json")
	graphInput := attackgraph.Input{
		SourceKind: "bloodhound-export",
		Nodes:      []attackgraph.Node{{ID: "user/a", Kind: "identity"}, {ID: "host/a", Kind: "host"}},
		Edges:      []attackgraph.Edge{{From: "user/a", To: "host/a", Kind: "admin-of"}},
	}
	body, _ := json.Marshal(graphInput)
	if err := os.WriteFile(graphPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	graph, err := service.ImportAttackGraph(AttackGraphImportRequest{Path: graphPath, CaseID: attackCase.ID, From: "user/a", To: "host/a"})
	if err != nil {
		t.Fatal(err)
	}
	if graph.Artifact == nil || graph.Evidence == nil || graph.Observation == nil || graph.CasePath == nil || graph.Path == nil || !graph.Path.Found {
		t.Fatalf("graph=%+v", graph)
	}

	cloudCase, err := service.CreateCase(casebook.CreateRequest{Title: "cloud", Route: "container-k8s"})
	if err != nil {
		t.Fatal(err)
	}
	cloudPath := filepath.Join(root, "cloud.json")
	if err := os.WriteFile(cloudPath, []byte(`{"provider":"kubernetes","scope_id":"lab","resources":[{"id":"ns/a","type":"Namespace"},{"id":"pod/a","type":"Pod"}],"relationships":[{"from":"ns/a","to":"pod/a","kind":"contains"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cloud, err := service.ImportCloudInventory(CloudInventoryRequest{Path: cloudPath, CaseID: cloudCase.ID})
	if err != nil {
		t.Fatal(err)
	}
	if cloud.Artifact == nil || cloud.Evidence == nil || cloud.Observation == nil || !cloud.Report.ReadOnly {
		t.Fatalf("cloud=%+v", cloud)
	}

	ctiCase, err := service.CreateCase(casebook.CreateRequest{Title: "cti", Route: "cti-analysis"})
	if err != nil {
		t.Fatal(err)
	}
	stixPath := filepath.Join(root, "bundle.json")
	if err := os.WriteFile(stixPath, []byte(`{"type":"bundle","id":"bundle--1","objects":[{"type":"indicator","id":"indicator--1","name":"x"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	stix, err := service.ImportSTIX(STIXImportRequest{Path: stixPath, CaseID: ctiCase.ID})
	if err != nil {
		t.Fatal(err)
	}
	if stix.Artifact == nil || stix.Evidence == nil || stix.Observation == nil || len(stix.Report.Objects) != 1 {
		t.Fatalf("stix=%+v", stix)
	}

	huntCase, err := service.CreateCase(casebook.CreateRequest{Title: "hunt", Route: "threat-hunting"})
	if err != nil {
		t.Fatal(err)
	}
	hunt, err := service.BuildHuntPlan(HuntPlanRequest{CaseID: huntCase.ID, Hypothesis: "scheduled task persistence", Techniques: []string{"T1053"}, Telemetry: []string{"Sysmon"}, Adapters: []string{"sigma"}})
	if err != nil {
		t.Fatal(err)
	}
	if hunt.Plan.ExecutionPerformed || hunt.Observation == nil || hunt.Timeline == nil {
		t.Fatalf("hunt=%+v", hunt)
	}
}

func TestP2IOSAndFirmwareAreReadOnly(t *testing.T) {
	root, _ := isolatedCoreRoot(t)
	service, err := New(root)
	if err != nil {
		t.Fatal(err)
	}

	iosCase, err := service.CreateCase(casebook.CreateRequest{Title: "ios", Route: "ios"})
	if err != nil {
		t.Fatal(err)
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
	_, _ = w.Write([]byte{0xcf, 0xfa, 0xed, 0xfe, 1, 2, 3})
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	ios, err := service.InspectIOS(IOSInspectRequest{Path: ipa, CaseID: iosCase.ID})
	if err != nil {
		t.Fatal(err)
	}
	if !ios.Report.ReadOnly || ios.Artifact == nil || ios.Evidence == nil || ios.Observation == nil {
		t.Fatalf("ios=%+v", ios)
	}

	fwCase, err := service.CreateCase(casebook.CreateRequest{Title: "fw", Route: "firmware-iot"})
	if err != nil {
		t.Fatal(err)
	}
	fwPath := filepath.Join(root, "fw.bin")
	if err := os.WriteFile(fwPath, []byte("hsqsfixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	fw, err := service.InspectFirmware(FirmwareInspectRequest{Path: fwPath, CaseID: fwCase.ID})
	if err != nil {
		t.Fatal(err)
	}
	if !fw.Report.ReadOnly || fw.Report.Format != "squashfs" || fw.Artifact == nil || fw.Evidence == nil || fw.Observation == nil {
		t.Fatalf("fw=%+v", fw)
	}
}
