package dashboard

import (
	"strings"
	"testing"

	"reverseresearch/internal/collaboration"
	"reverseresearch/internal/job"
	"reverseresearch/internal/packregistry"
	"reverseresearch/internal/remoteagent"
	"reverseresearch/internal/reporting"
	"reverseresearch/internal/toolindex"
)

func TestDashboardEscapesContentAndShowsOperations(t *testing.T) {
	doc := reporting.Document{Title: "<script>alert(1)</script>", CaseID: "c", CaseSHA256: strings.Repeat("a", 64), Profile: "general", Classification: "internal", Summary: reporting.Summary{Findings: 1}}
	w := &collaboration.Workspace{CaseID: "c", CaseOwner: "alice", Revision: "rev", Participants: []collaboration.Participant{{Subject: "alice", Role: "owner", Status: "active"}}}
	status := remoteagent.StatusRecord{
		Status:    remoteagent.StatusEnvelope{AgentVersion: "p4-test", Queue: remoteagent.QueueStatus{RunningJobs: 1, TerminalResults: 2}},
		Transport: remoteagent.TransportObservation{ServerCertificateNotAfterUTC: "2030-01-01T00:00:00Z"},
	}
	ops := Operations{
		Jobs:  []job.Job{{ID: "job_1", OperationID: "op_1", State: job.StatePlanned}},
		Tools: []toolindex.Tool{{Name: "ghidra", Available: true}},
		Agents: []remoteagent.FleetEntry{{
			Registration: remoteagent.Registration{
				Manifest: remoteagent.Manifest{AgentID: "agent-1", Capabilities: []string{"artifact.hash"}},
				Revision: "agent-rev",
			},
			Status: &status, State: "recent", LastSeenUTC: "2026-10-03T00:00:00Z", CertificateState: "valid",
		}},
		PackRegistry: &packregistry.RegistryState{
			Revision: "pack-rev",
			TrustedKeys: map[string]packregistry.TrustedKey{
				"lab": {KeyID: "lab", Publisher: "Lab"},
			},
			Receipts: []packregistry.Receipt{{ID: "receipt-1", PackID: "rules", PackVersion: "1", Kind: "rule", Publisher: "Lab", VerifiedUTC: "2026-10-03T00:00:00Z"}},
		},
	}
	body, err := Render(doc, w, ops)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if strings.Contains(text, "<script>alert(1)</script>") {
		t.Fatal("unescaped HTML")
	}
	for _, expected := range []string{"alice", "Collaboration", "job_1", "ghidra", "agent-1", "p4-test", "Signed Pack Registry", "receipt-1"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("dashboard missing %q", expected)
		}
	}
}
