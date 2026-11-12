package core

import (
	"testing"
	"time"

	"reverseresearch/internal/engagement"
	"reverseresearch/internal/job"
)

func TestPrepareSelectsP0DomainPacksAndSpecialistSkills(t *testing.T) {
	root, _ := isolatedCoreRoot(t)
	service, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		task       string
		routeID    string
		playbookID string
		packID     string
		skillPath  string
	}{
		{"在隔离环境分析这个恶意样本并生成 IOC 和检测", "malware-analysis", "malware-analysis", "malware", "skills/seep-malware/SKILL.md"},
		{"把这批 Sysmon 遥测做成 Sigma 检测规则并验证正负样本", "blue-detection", "blue-detection", "blue-detection", "skills/seep-blueteam/SKILL.md"},
		{"做一次紫队验证，从 ATT&CK TTP 模拟到检测缺口再复测", "purple-validation", "purple-validation", "purple-validation", "skills/seep-purple-team/SKILL.md"},
	}
	for _, tc := range tests {
		prepared, err := service.Prepare(tc.task)
		if err != nil {
			t.Fatalf("prepare %q: %v", tc.task, err)
		}
		if prepared.Route.Route.ID != tc.routeID || prepared.Playbook == nil || prepared.Playbook.ID != tc.playbookID {
			t.Fatalf("prepare %q route/playbook=%+v", tc.task, prepared)
		}
		if prepared.DomainPack == nil || prepared.DomainPack.ID != tc.packID || prepared.DomainPack.Skill.Path != tc.skillPath || prepared.DomainPack.Skill.OwnsRouting {
			t.Fatalf("prepare %q domain pack=%+v", tc.task, prepared.DomainPack)
		}
		if prepared.Playbook.SkillPath != tc.skillPath {
			t.Fatalf("prepare %q playbook skill=%q want=%q", tc.task, prepared.Playbook.SkillPath, tc.skillPath)
		}
		if len(prepared.KnowledgePacks) == 0 {
			t.Fatalf("prepare %q has no validated knowledge packs", tc.task)
		}
		for _, pack := range prepared.KnowledgePacks {
			if pack.TrustStatus != "reviewed" || len(pack.NoteIDs) == 0 || len(pack.Standards) == 0 {
				t.Fatalf("prepare %q knowledge pack=%+v", tc.task, pack)
			}
		}
	}
}

func TestServiceEngagementAndGenericJobEnforceScope(t *testing.T) {
	root, _ := isolatedCoreRoot(t)
	service, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	eng, err := service.CreateEngagement(engagement.CreateRequest{
		Organization: "Lab",
		Operator:     "analyst",
		Scope: engagement.Scope{
			Targets:        []string{"host-a"},
			AllowedActions: []string{"observe"},
			Authorization:  engagement.Authorization{Status: "granted", Basis: "lab_only"},
			NetworkProfile: engagement.NetworkProfile{Mode: "authorized_target_only"},
			StartsUTC:      time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
			EndsUTC:        time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	planned, err := service.PlanJob(job.PlanRequest{
		OperationID: "core-p0-op", EngagementID: eng.ID, Target: "host-a",
		Action: "observe", EffectClass: "observation",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.TransitionJob(job.TransitionRequest{
		JobID: planned.ID, OperationID: planned.OperationID, To: job.StatePrepared,
	}); err == nil {
		t.Fatal("generic transition bypassed scope-aware Prepare")
	}
	prepared, err := service.PrepareJob(planned.ID, planned.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.State != job.StatePrepared {
		t.Fatalf("prepared=%+v", prepared)
	}
	running, err := service.TransitionJob(job.TransitionRequest{
		JobID: planned.ID, OperationID: planned.OperationID, To: job.StateRunning,
	})
	if err != nil {
		t.Fatal(err)
	}
	if running.State != job.StateRunning {
		t.Fatalf("running=%+v", running)
	}
}
