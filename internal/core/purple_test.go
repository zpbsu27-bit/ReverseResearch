package core

import (
	"testing"
	"time"

	"reverseresearch/internal/casebook"
	"reverseresearch/internal/engagement"
	"reverseresearch/internal/job"
)

func TestPurpleCoverageAndPreparedEmulationStayEvidenceScoped(t *testing.T) {
	root, _ := isolatedCoreRoot(t)
	service, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	eng, err := service.CreateEngagement(engagement.CreateRequest{
		Organization: "Lab", Operator: "analyst",
		Scope: engagement.Scope{
			Targets: []string{"lab-host"}, AllowedActions: []string{"emulate-t1053"},
			Authorization:  engagement.Authorization{Status: "granted", Basis: "lab_only"},
			NetworkProfile: engagement.NetworkProfile{Mode: "lab_only"},
			StartsUTC:      time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
			EndsUTC:        time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	c, err := service.CreateCase(casebook.CreateRequest{
		Title: "purple", Route: "purple-validation", EngagementID: eng.ID,
		Targets: []casebook.Target{{ID: "target_lab", Kind: "host", Identity: "lab-host"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ttp, err := service.AddCaseTTP(c.ID, casebook.TTPRequest{Technique: "T1053", Tactic: "Persistence"})
	if err != nil {
		t.Fatal(err)
	}
	if ttp.ID == "" {
		t.Fatal("missing ttp")
	}

	coverage, err := service.PurpleCoverage(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if coverage.TotalTechniques != 1 || coverage.Techniques[0].Gap != "no_detection" || coverage.Complete {
		t.Fatalf("coverage=%+v", coverage)
	}

	plan, err := service.PreparePurpleEmulation(PurpleEmulationPlanRequest{
		CaseID: c.ID, Technique: "T1053", Target: "lab-host", Action: "emulate-t1053",
		EffectClass: "runtime mutation", OperationID: "purple-fixture-op",
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Job.State != job.StatePrepared || plan.ExecutionPerformed || plan.Timeline == nil || len(plan.CaseSHA256) != 64 {
		t.Fatalf("plan=%+v", plan)
	}
	stored, err := service.GetCase(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.Timeline) != 1 || stored.Timeline[0].JobID != plan.Job.ID {
		t.Fatalf("stored=%+v", stored)
	}
}

func TestPurpleEmulationRejectsUnknownTechniqueAndNonCaseTarget(t *testing.T) {
	root, _ := isolatedCoreRoot(t)
	service, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	eng, err := service.CreateEngagement(engagement.CreateRequest{
		Organization: "Lab", Operator: "analyst",
		Scope: engagement.Scope{
			Targets: []string{"lab-host", "other-host"}, AllowedActions: []string{"emulate"},
			Authorization:  engagement.Authorization{Status: "granted", Basis: "lab_only"},
			NetworkProfile: engagement.NetworkProfile{Mode: "lab_only"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	c, err := service.CreateCase(casebook.CreateRequest{
		Title: "purple", Route: "purple-validation", EngagementID: eng.ID,
		Targets: []casebook.Target{{ID: "target_lab", Identity: "lab-host"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.PreparePurpleEmulation(PurpleEmulationPlanRequest{
		CaseID: c.ID, Technique: "T1053", Target: "lab-host", Action: "emulate", EffectClass: "runtime mutation", OperationID: "unknown-ttp",
	}); err == nil {
		t.Fatal("unknown TTP was accepted")
	}
	if _, err := service.AddCaseTTP(c.ID, casebook.TTPRequest{Technique: "T1053"}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.PreparePurpleEmulation(PurpleEmulationPlanRequest{
		CaseID: c.ID, Technique: "T1053", Target: "other-host", Action: "emulate", EffectClass: "runtime mutation", OperationID: "wrong-case-target",
	}); err == nil {
		t.Fatal("engagement-scoped but non-Case target was accepted")
	}
}
