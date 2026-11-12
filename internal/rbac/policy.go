package rbac

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

type Role string

const (
	RoleOwner    Role = "owner"
	RoleLead     Role = "lead"
	RoleAnalyst  Role = "analyst"
	RoleReviewer Role = "reviewer"
	RoleViewer   Role = "viewer"
	RoleAgent    Role = "agent"
)

type Action string

const (
	ActionCaseRead            Action = "case.read"
	ActionCaseWrite           Action = "case.write"
	ActionCollaborationManage Action = "collaboration.manage"
	ActionEvidenceAdd         Action = "evidence.add"
	ActionEvidenceLock        Action = "evidence.lock"
	ActionFindingWrite        Action = "finding.write"
	ActionTaskWrite           Action = "task.write"
	ActionCommentAdd          Action = "comment.add"
	ActionApprove             Action = "approval.write"
	ActionReportDraft         Action = "report.draft"
	ActionReportFinalize      Action = "report.finalize"
	ActionJobPrepare          Action = "job.prepare"
	ActionJobExecute          Action = "job.execute"
	ActionAgentManage         Action = "agent.manage"
	ActionRegistryRead        Action = "registry.read"
	ActionRegistryManage      Action = "registry.manage"
)

type Decision struct {
	Role    Role   `json:"role"`
	Action  Action `json:"action"`
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

var grants = map[Role]map[Action]bool{
	RoleOwner:    {ActionCaseRead: true, ActionCaseWrite: true, ActionCollaborationManage: true, ActionEvidenceAdd: true, ActionEvidenceLock: true, ActionFindingWrite: true, ActionTaskWrite: true, ActionCommentAdd: true, ActionApprove: true, ActionReportDraft: true, ActionReportFinalize: true, ActionJobPrepare: true, ActionJobExecute: true, ActionAgentManage: true, ActionRegistryRead: true, ActionRegistryManage: true},
	RoleLead:     {ActionCaseRead: true, ActionCaseWrite: true, ActionCollaborationManage: true, ActionEvidenceAdd: true, ActionEvidenceLock: true, ActionFindingWrite: true, ActionTaskWrite: true, ActionCommentAdd: true, ActionApprove: true, ActionReportDraft: true, ActionReportFinalize: true, ActionJobPrepare: true, ActionJobExecute: true, ActionRegistryRead: true},
	RoleAnalyst:  {ActionCaseRead: true, ActionCaseWrite: true, ActionEvidenceAdd: true, ActionFindingWrite: true, ActionTaskWrite: true, ActionCommentAdd: true, ActionReportDraft: true, ActionJobPrepare: true, ActionRegistryRead: true},
	RoleReviewer: {ActionCaseRead: true, ActionEvidenceLock: true, ActionCommentAdd: true, ActionApprove: true, ActionReportDraft: true, ActionReportFinalize: true, ActionRegistryRead: true},
	RoleViewer:   {ActionCaseRead: true, ActionRegistryRead: true},
	RoleAgent:    {ActionCaseRead: true, ActionEvidenceAdd: true, ActionJobPrepare: true},
}

func Evaluate(role Role, action Action) Decision {
	role = Role(strings.ToLower(strings.TrimSpace(string(role))))
	action = Action(strings.ToLower(strings.TrimSpace(string(action))))
	if !ValidRole(role) {
		return Decision{Role: role, Action: action, Reason: "unknown role"}
	}
	if !ValidAction(action) {
		return Decision{Role: role, Action: action, Reason: "unknown action"}
	}
	if grants[role][action] {
		return Decision{Role: role, Action: action, Allowed: true, Reason: "granted by built-in policy"}
	}
	return Decision{Role: role, Action: action, Reason: "action is not granted to role"}
}
func Require(role Role, action Action) error {
	d := Evaluate(role, action)
	if d.Allowed {
		return nil
	}
	return fmt.Errorf("rbac denied %s for %s: %s", action, role, d.Reason)
}
func ValidRole(role Role) bool { _, ok := grants[role]; return ok }
func ValidAction(action Action) bool {
	for _, a := range Actions() {
		if a == action {
			return true
		}
	}
	return false
}
func Actions() []Action {
	v := []Action{ActionCaseRead, ActionCaseWrite, ActionCollaborationManage, ActionEvidenceAdd, ActionEvidenceLock, ActionFindingWrite, ActionTaskWrite, ActionCommentAdd, ActionApprove, ActionReportDraft, ActionReportFinalize, ActionJobPrepare, ActionJobExecute, ActionAgentManage, ActionRegistryRead, ActionRegistryManage}
	sort.Slice(v, func(i, j int) bool { return v[i] < v[j] })
	return v
}
func NormalizeRole(value string) (Role, error) {
	r := Role(strings.ToLower(strings.TrimSpace(value)))
	if !ValidRole(r) {
		return "", errors.New("invalid role")
	}
	return r, nil
}
