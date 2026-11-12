package core

import (
	"errors"
	"fmt"
	"strings"

	"reverseresearch/internal/casebook"
	"reverseresearch/internal/job"
	"reverseresearch/internal/purple"
)

type PurpleEmulationPlanRequest struct {
	CaseID       string   `json:"case_id"`
	Technique    string   `json:"technique"`
	Target       string   `json:"target"`
	Action       string   `json:"action"`
	EffectClass  string   `json:"effect_class"`
	OperationID  string   `json:"operation_id"`
	ToolIdentity string   `json:"tool_identity,omitempty"`
	EvidenceIDs  []string `json:"evidence_ids,omitempty"`
}

type PurpleEmulationPlanResult struct {
	Job                job.Job                 `json:"job"`
	Timeline           *casebook.TimelineEntry `json:"timeline,omitempty"`
	CaseSHA256         string                  `json:"case_sha256"`
	ExecutionPerformed bool                    `json:"execution_performed"`
}

func (s *Service) PurpleCoverage(caseID string) (purple.Coverage, error) {
	caseID = strings.TrimSpace(caseID)
	if caseID == "" {
		return purple.Coverage{}, errors.New("case_id is required")
	}
	if err := s.requireCaseRoute(caseID, "purple-validation"); err != nil {
		return purple.Coverage{}, err
	}
	value, err := s.cases.Get(caseID)
	if err != nil {
		return purple.Coverage{}, err
	}
	return purple.BuildCoverage(value), nil
}

func (s *Service) PreparePurpleEmulation(request PurpleEmulationPlanRequest) (PurpleEmulationPlanResult, error) {
	request.CaseID = strings.TrimSpace(request.CaseID)
	request.Technique = strings.ToUpper(strings.TrimSpace(request.Technique))
	request.Target = strings.TrimSpace(request.Target)
	request.Action = strings.TrimSpace(request.Action)
	request.EffectClass = strings.ToLower(strings.TrimSpace(request.EffectClass))
	request.OperationID = strings.TrimSpace(request.OperationID)
	request.ToolIdentity = strings.TrimSpace(request.ToolIdentity)
	request.EvidenceIDs = cleanCoreStrings(request.EvidenceIDs)
	if request.CaseID == "" || request.Technique == "" || request.Target == "" || request.Action == "" || request.EffectClass == "" || request.OperationID == "" {
		return PurpleEmulationPlanResult{}, errors.New("case_id, technique, target, action, effect_class, and operation_id are required")
	}
	switch request.EffectClass {
	case "local mutation", "runtime mutation", "active network interaction":
	default:
		return PurpleEmulationPlanResult{}, fmt.Errorf("purple emulation plan does not permit effect_class %q; use local mutation, runtime mutation, or active network interaction", request.EffectClass)
	}
	if err := s.requireCaseRoute(request.CaseID, "purple-validation"); err != nil {
		return PurpleEmulationPlanResult{}, err
	}
	value, err := s.cases.Get(request.CaseID)
	if err != nil {
		return PurpleEmulationPlanResult{}, err
	}
	if value.EngagementID == "" {
		return PurpleEmulationPlanResult{}, errors.New("purple emulation plan requires Case engagement_id")
	}
	if !caseHasTechnique(value, request.Technique) {
		return PurpleEmulationPlanResult{}, fmt.Errorf("case %s does not contain TTP %s", value.ID, request.Technique)
	}
	if !caseHasTarget(value, request.Target) {
		return PurpleEmulationPlanResult{}, fmt.Errorf("target %q is not bound to case %s", request.Target, value.ID)
	}
	if err := caseHasEvidenceIDs(value, request.EvidenceIDs); err != nil {
		return PurpleEmulationPlanResult{}, err
	}
	verification, err := s.cases.Verify(request.CaseID)
	if err != nil {
		return PurpleEmulationPlanResult{}, err
	}
	if !verification.Valid {
		return PurpleEmulationPlanResult{}, fmt.Errorf("case %s failed structural/currentness verification with %d issue(s)", value.ID, len(verification.Issues))
	}
	if request.ToolIdentity == "" {
		request.ToolIdentity = "manual-emulation-plan"
	}
	planned, err := s.jobs.Plan(job.PlanRequest{
		OperationID: request.OperationID, EngagementID: value.EngagementID,
		Target: request.Target, Action: request.Action, EffectClass: request.EffectClass,
		ToolIdentity: request.ToolIdentity, InputRevision: verification.CaseSHA256,
		EvidenceIDs: request.EvidenceIDs,
	})
	if err != nil {
		return PurpleEmulationPlanResult{}, err
	}
	prepared, err := s.jobs.Prepare(planned.ID, planned.OperationID)
	if err != nil {
		return PurpleEmulationPlanResult{}, err
	}
	result := PurpleEmulationPlanResult{
		Job: prepared, CaseSHA256: verification.CaseSHA256, ExecutionPerformed: false,
	}
	timeline, err := s.cases.AddTimeline(request.CaseID, casebook.TimelineRequest{
		Kind:    "purple-emulation-prepared",
		Summary: fmt.Sprintf("Prepared scoped emulation job for %s; no emulation action was executed by this operation.", request.Technique),
		JobID:   prepared.ID, EvidenceIDs: request.EvidenceIDs,
	})
	if err != nil {
		return result, err
	}
	result.Timeline = &timeline
	return result, nil
}

func caseHasTechnique(value casebook.Case, technique string) bool {
	for _, ttp := range value.TTPs {
		if strings.EqualFold(strings.TrimSpace(ttp.Technique), technique) {
			return true
		}
	}
	return false
}

func caseHasTarget(value casebook.Case, target string) bool {
	for _, item := range value.Targets {
		if item.ID == target || item.Identity == target {
			return true
		}
	}
	return false
}

func caseHasEvidenceIDs(value casebook.Case, ids []string) error {
	known := make(map[string]bool, len(value.Evidence))
	for _, item := range value.Evidence {
		known[item.ID] = true
	}
	for _, id := range ids {
		if !known[id] {
			return fmt.Errorf("unknown case evidence id %q", id)
		}
	}
	return nil
}
