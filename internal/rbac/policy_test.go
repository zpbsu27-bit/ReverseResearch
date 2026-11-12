package rbac

import "testing"

func TestPolicySeparatesReviewExecutionAndAdministration(t *testing.T) {
	if !Evaluate(RoleAnalyst, ActionEvidenceAdd).Allowed {
		t.Fatal("analyst should add evidence")
	}
	if Evaluate(RoleAnalyst, ActionReportFinalize).Allowed {
		t.Fatal("analyst must not finalize")
	}
	if !Evaluate(RoleReviewer, ActionReportFinalize).Allowed {
		t.Fatal("reviewer should finalize")
	}
	if Evaluate(RoleReviewer, ActionJobExecute).Allowed {
		t.Fatal("reviewer must not execute")
	}
	if !Evaluate(RoleOwner, ActionRegistryManage).Allowed {
		t.Fatal("owner should manage registry")
	}
	if Evaluate(RoleAgent, ActionJobExecute).Allowed {
		t.Fatal("agent must not self-authorize execution")
	}
}
func TestUnknownRoleAndActionFailClosed(t *testing.T) {
	if Evaluate(Role("root"), ActionCaseRead).Allowed {
		t.Fatal("unknown role allowed")
	}
	if Evaluate(RoleOwner, Action("shell")).Allowed {
		t.Fatal("unknown action allowed")
	}
}
