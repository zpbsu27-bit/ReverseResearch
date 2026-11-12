package casebook

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

type PathStep struct {
	Action      string   `json:"action"`
	EvidenceIDs []string `json:"evidence_ids,omitempty"`
	FindingIDs  []string `json:"finding_ids,omitempty"`
	JobID       string   `json:"job_id,omitempty"`
}

type RoleAssignmentRequest struct {
	Role            string `json:"role"`
	SpecialistSkill string `json:"specialist_skill,omitempty"`
	HandoffWhen     string `json:"handoff_when,omitempty"`
}

type RoleAssignment struct {
	ID              string `json:"id"`
	Role            string `json:"role"`
	SpecialistSkill string `json:"specialist_skill,omitempty"`
	HandoffWhen     string `json:"handoff_when,omitempty"`
	Status          string `json:"status"`
	CreatedUTC      string `json:"created_utc"`
}

type WorkItemRequest struct {
	Title       string   `json:"title"`
	OwnerRole   string   `json:"owner_role,omitempty"`
	Coverage    string   `json:"coverage,omitempty"`
	EvidenceIDs []string `json:"evidence_ids,omitempty"`
}

type WorkItemUpdateRequest struct {
	Status        string   `json:"status"`
	Coverage      string   `json:"coverage,omitempty"`
	EvidenceIDs   []string `json:"evidence_ids,omitempty"`
	BlockedReason string   `json:"blocked_reason,omitempty"`
}

type WorkItem struct {
	ID            string   `json:"id"`
	Title         string   `json:"title"`
	OwnerRole     string   `json:"owner_role,omitempty"`
	Status        string   `json:"status"`
	Coverage      string   `json:"coverage,omitempty"`
	EvidenceIDs   []string `json:"evidence_ids,omitempty"`
	BlockedReason string   `json:"blocked_reason,omitempty"`
	CreatedUTC    string   `json:"created_utc"`
	UpdatedUTC    string   `json:"updated_utc"`
}

type TimelineRequest struct {
	Kind        string   `json:"kind"`
	Summary     string   `json:"summary"`
	Role        string   `json:"role,omitempty"`
	WorkItemID  string   `json:"workitem_id,omitempty"`
	JobID       string   `json:"job_id,omitempty"`
	EvidenceIDs []string `json:"evidence_ids,omitempty"`
}

type TimelineEntry struct {
	ID          string   `json:"id"`
	Kind        string   `json:"kind"`
	Summary     string   `json:"summary"`
	Role        string   `json:"role,omitempty"`
	WorkItemID  string   `json:"workitem_id,omitempty"`
	JobID       string   `json:"job_id,omitempty"`
	EvidenceIDs []string `json:"evidence_ids,omitempty"`
	CreatedUTC  string   `json:"created_utc"`
}

func (s *Store) AssignRole(caseID string, request RoleAssignmentRequest) (result RoleAssignment, err error) {
	release, err := s.lockCase(caseID)
	if err != nil {
		return RoleAssignment{}, err
	}
	defer func() { err = errors.Join(err, release()) }()
	value, err := s.get(caseID)
	if err != nil {
		return RoleAssignment{}, err
	}
	request.Role = strings.TrimSpace(request.Role)
	request.SpecialistSkill = strings.TrimSpace(request.SpecialistSkill)
	request.HandoffWhen = strings.TrimSpace(request.HandoffWhen)
	if request.Role == "" {
		return RoleAssignment{}, errors.New("role is required")
	}
	for _, existing := range value.Roles {
		if existing.Role == request.Role && existing.SpecialistSkill == request.SpecialistSkill && existing.Status == "active" {
			return existing, nil
		}
	}
	id, err := newID("role")
	if err != nil {
		return RoleAssignment{}, err
	}
	item := RoleAssignment{
		ID: id, Role: request.Role, SpecialistSkill: request.SpecialistSkill,
		HandoffWhen: request.HandoffWhen, Status: "active", CreatedUTC: time.Now().UTC().Format(time.RFC3339Nano),
	}
	value.SchemaVersion = 2
	value.Roles = append(value.Roles, item)
	value.UpdatedUTC = item.CreatedUTC
	if err := s.save(value); err != nil {
		return RoleAssignment{}, err
	}
	return item, nil
}

func (s *Store) AddWorkItem(caseID string, request WorkItemRequest) (result WorkItem, err error) {
	release, err := s.lockCase(caseID)
	if err != nil {
		return WorkItem{}, err
	}
	defer func() { err = errors.Join(err, release()) }()
	value, err := s.get(caseID)
	if err != nil {
		return WorkItem{}, err
	}
	request.Title = strings.TrimSpace(request.Title)
	request.OwnerRole = strings.TrimSpace(request.OwnerRole)
	request.Coverage = strings.TrimSpace(request.Coverage)
	if request.Title == "" {
		return WorkItem{}, errors.New("workitem title is required")
	}
	if request.OwnerRole != "" && !roleExists(value, request.OwnerRole) {
		return WorkItem{}, fmt.Errorf("unknown owner role %q", request.OwnerRole)
	}
	if err := validateEvidenceIDs(value, request.EvidenceIDs); err != nil {
		return WorkItem{}, err
	}
	id, err := newID("wi")
	if err != nil {
		return WorkItem{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	item := WorkItem{
		ID: id, Title: request.Title, OwnerRole: request.OwnerRole, Status: "planned",
		Coverage: request.Coverage, EvidenceIDs: cleanStrings(request.EvidenceIDs), CreatedUTC: now, UpdatedUTC: now,
	}
	value.SchemaVersion = 2
	value.WorkItems = append(value.WorkItems, item)
	value.UpdatedUTC = now
	if err := s.save(value); err != nil {
		return WorkItem{}, err
	}
	return item, nil
}

func (s *Store) UpdateWorkItem(caseID, workItemID string, request WorkItemUpdateRequest) (result WorkItem, err error) {
	release, err := s.lockCase(caseID)
	if err != nil {
		return WorkItem{}, err
	}
	defer func() { err = errors.Join(err, release()) }()
	value, err := s.get(caseID)
	if err != nil {
		return WorkItem{}, err
	}
	request.Status = strings.TrimSpace(request.Status)
	switch request.Status {
	case "planned", "running", "blocked", "done", "cancelled":
	default:
		return WorkItem{}, fmt.Errorf("invalid workitem status %q", request.Status)
	}
	if request.Status == "blocked" && strings.TrimSpace(request.BlockedReason) == "" {
		return WorkItem{}, errors.New("blocked workitem requires blocked_reason")
	}
	if err := validateEvidenceIDs(value, request.EvidenceIDs); err != nil {
		return WorkItem{}, err
	}
	for index := range value.WorkItems {
		if value.WorkItems[index].ID != workItemID {
			continue
		}
		item := &value.WorkItems[index]
		item.Status = request.Status
		if strings.TrimSpace(request.Coverage) != "" {
			item.Coverage = strings.TrimSpace(request.Coverage)
		}
		if request.EvidenceIDs != nil {
			item.EvidenceIDs = cleanStrings(request.EvidenceIDs)
		}
		item.BlockedReason = strings.TrimSpace(request.BlockedReason)
		item.UpdatedUTC = time.Now().UTC().Format(time.RFC3339Nano)
		value.SchemaVersion = 2
		value.UpdatedUTC = item.UpdatedUTC
		if err := s.save(value); err != nil {
			return WorkItem{}, err
		}
		return *item, nil
	}
	return WorkItem{}, fmt.Errorf("unknown workitem id %q", workItemID)
}

func (s *Store) AddTimeline(caseID string, request TimelineRequest) (result TimelineEntry, err error) {
	release, err := s.lockCase(caseID)
	if err != nil {
		return TimelineEntry{}, err
	}
	defer func() { err = errors.Join(err, release()) }()
	value, err := s.get(caseID)
	if err != nil {
		return TimelineEntry{}, err
	}
	request.Kind = strings.TrimSpace(request.Kind)
	request.Summary = strings.TrimSpace(request.Summary)
	request.Role = strings.TrimSpace(request.Role)
	request.WorkItemID = strings.TrimSpace(request.WorkItemID)
	request.JobID = strings.TrimSpace(request.JobID)
	if request.Kind == "" || request.Summary == "" {
		return TimelineEntry{}, errors.New("timeline kind and summary are required")
	}
	if request.Role != "" && !roleExists(value, request.Role) {
		return TimelineEntry{}, fmt.Errorf("unknown timeline role %q", request.Role)
	}
	if request.WorkItemID != "" && !workItemExists(value, request.WorkItemID) {
		return TimelineEntry{}, fmt.Errorf("unknown timeline workitem id %q", request.WorkItemID)
	}
	if err := validateEvidenceIDs(value, request.EvidenceIDs); err != nil {
		return TimelineEntry{}, err
	}
	id, err := newID("tl")
	if err != nil {
		return TimelineEntry{}, err
	}
	item := TimelineEntry{
		ID: id, Kind: request.Kind, Summary: request.Summary, Role: request.Role,
		WorkItemID: request.WorkItemID, JobID: request.JobID, EvidenceIDs: cleanStrings(request.EvidenceIDs),
		CreatedUTC: time.Now().UTC().Format(time.RFC3339Nano),
	}
	value.SchemaVersion = 2
	value.Timeline = append(value.Timeline, item)
	value.UpdatedUTC = item.CreatedUTC
	if err := s.save(value); err != nil {
		return TimelineEntry{}, err
	}
	return item, nil
}

func roleExists(value Case, role string) bool {
	for _, item := range value.Roles {
		if item.Role == role && item.Status == "active" {
			return true
		}
	}
	return false
}

func workItemExists(value Case, id string) bool {
	for _, item := range value.WorkItems {
		if item.ID == id {
			return true
		}
	}
	return false
}

func evidenceExists(value Case, id string) bool {
	for _, item := range value.Evidence {
		if item.ID == id {
			return true
		}
	}
	return false
}

func findingExists(value Case, id string) bool {
	for _, item := range value.Findings {
		if item.ID == id {
			return true
		}
	}
	return false
}

func normalizePathSteps(values []PathStep) []PathStep {
	result := make([]PathStep, 0, len(values))
	for _, step := range values {
		step.Action = strings.TrimSpace(step.Action)
		step.JobID = strings.TrimSpace(step.JobID)
		step.EvidenceIDs = cleanStrings(step.EvidenceIDs)
		step.FindingIDs = cleanStrings(step.FindingIDs)
		if step.Action != "" {
			result = append(result, step)
		}
	}
	return result
}

func validatePathSteps(value Case, steps []PathStep) error {
	for index, step := range normalizePathSteps(steps) {
		if step.Action == "" {
			return fmt.Errorf("path step %d action is required", index+1)
		}
		for _, evidenceID := range step.EvidenceIDs {
			if !evidenceExists(value, evidenceID) {
				return fmt.Errorf("path step %d references unknown evidence id %q", index+1, evidenceID)
			}
		}
		for _, findingID := range step.FindingIDs {
			if !findingExists(value, findingID) {
				return fmt.Errorf("path step %d references unknown finding id %q", index+1, findingID)
			}
		}
	}
	return nil
}

func caseObjectExists(value Case, id string) bool {
	if id == "" {
		return false
	}
	if evidenceExists(value, id) || findingExists(value, id) || artifactExists(value, id) || workItemExists(value, id) {
		return true
	}
	for _, item := range value.Hypotheses {
		if item.ID == id {
			return true
		}
	}
	for _, item := range value.Detections {
		if item.ID == id {
			return true
		}
	}
	for _, item := range value.Vulnerabilities {
		if item.ID == id {
			return true
		}
	}
	for _, item := range value.Mitigations {
		if item.ID == id {
			return true
		}
	}
	for _, item := range value.TTPs {
		if item.ID == id {
			return true
		}
	}
	return false
}
