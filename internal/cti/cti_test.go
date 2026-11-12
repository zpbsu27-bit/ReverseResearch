package cti

import (
	"os"
	"path/filepath"
	"testing"
)

func TestImportSTIXAndHuntPlan(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bundle.json")
	body := `{"type":"bundle","id":"bundle--1","objects":[{"type":"indicator","id":"indicator--1","name":"x","pattern":"[ipv4-addr:value = '1.2.3.4']"},{"type":"relationship","id":"relationship--1","relationship_type":"indicates","source_ref":"indicator--1","target_ref":"malware--1"}]}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := ImportSTIX(p, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Objects) != 1 || len(r.Relationships) != 1 {
		t.Fatalf("report=%+v", r)
	}
	h, err := BuildHuntPlan("find persistence", []string{"T1053"}, []string{"Sysmon"}, []string{"sigma"})
	if err != nil {
		t.Fatal(err)
	}
	if h.ExecutionPerformed {
		t.Fatal("hunt plan executed unexpectedly")
	}
}
