package casebook

import (
	"fmt"
	"strings"
	"time"
)

type ReviewIssue struct {
	Code     string `json:"code"`
	ObjectID string `json:"object_id,omitempty"`
	Message  string `json:"message"`
}

type Review struct {
	CaseID       string        `json:"case_id"`
	CaseSHA256   string        `json:"case_sha256"`
	CheckedUTC   string        `json:"checked_utc"`
	Ready        bool          `json:"ready"`
	Verification Verification  `json:"verification"`
	Issues       []ReviewIssue `json:"issues"`
	Warnings     []ReviewIssue `json:"warnings,omitempty"`
}

func (s *Store) Review(id string) (Review, error) {
	verification, err := s.Verify(id)
	if err != nil {
		return Review{}, err
	}
	value, revision, err := s.snapshot(id)
	if err != nil {
		return Review{}, err
	}
	result := Review{
		CaseID: id, CaseSHA256: revision, CheckedUTC: time.Now().UTC().Format(time.RFC3339Nano),
		Ready: true, Verification: verification, Issues: []ReviewIssue{}, Warnings: []ReviewIssue{},
	}
	issue := func(code, objectID, message string) {
		result.Ready = false
		result.Issues = append(result.Issues, ReviewIssue{Code: code, ObjectID: objectID, Message: message})
	}
	warn := func(code, objectID, message string) {
		result.Warnings = append(result.Warnings, ReviewIssue{Code: code, ObjectID: objectID, Message: message})
	}
	if !verification.Valid {
		for _, item := range verification.Issues {
			issue("verify_"+item.Code, item.ObjectID, item.Message)
		}
	}
	if verification.CaseSHA256 != revision {
		issue("case_changed_after_verify", id, "case changed after structural verification; rerun review")
	}
	if value.SchemaVersion != 2 {
		issue("case_v2_required", id, "strict case review requires schema_version=2")
	}
	if strings.TrimSpace(value.EngagementID) == "" {
		issue("engagement_required", id, "professional case review requires an engagement binding")
	}
	if len(value.Targets) == 0 && len(value.Artifacts) == 0 {
		issue("target_or_artifact_required", id, "case requires at least one target or artifact")
	}
	hasLead := false
	for _, role := range value.Roles {
		if role.Status == "active" && role.Role == "lead" {
			hasLead = true
			break
		}
	}
	if !hasLead {
		issue("lead_role_required", id, "case requires one active lead role")
	}
	if len(value.Timeline) == 0 {
		issue("timeline_required", id, "case requires at least one timeline entry")
	}
	for _, workItem := range value.WorkItems {
		switch workItem.Status {
		case "done", "cancelled":
		default:
			issue("open_workitem", workItem.ID, fmt.Sprintf("workitem remains %q", workItem.Status))
		}
		if workItem.Status == "blocked" && strings.TrimSpace(workItem.BlockedReason) == "" {
			issue("blocked_reason_required", workItem.ID, "blocked workitem requires a reason")
		}
	}
	for _, evidence := range value.Evidence {
		if evidence.LinkedWorkItemID != "" && !workItemExists(value, evidence.LinkedWorkItemID) {
			issue("unknown_evidence_workitem", evidence.ID, fmt.Sprintf("unknown linked workitem %q", evidence.LinkedWorkItemID))
		}
		if evidence.SupersedesEvidenceID != "" && !evidenceExists(value, evidence.SupersedesEvidenceID) {
			issue("unknown_superseded_evidence", evidence.ID, fmt.Sprintf("unknown superseded evidence %q", evidence.SupersedesEvidenceID))
		}
		if evidence.SourcePath == "" && evidence.ReproCommand == "" {
			warn("evidence_reproduction_weak", evidence.ID, "evidence has neither bound source bytes nor a reproduction command")
		}
	}
	for _, finding := range value.Findings {
		if len(finding.EvidenceIDs) == 0 {
			issue("finding_evidence_required", finding.ID, "finding must reference evidence")
		}
		if strings.TrimSpace(finding.Strength) == "" {
			issue("finding_strength_required", finding.ID, "finding must declare observed, inferred, or unverified strength")
		}
		if finding.Status == "validated" {
			if strings.EqualFold(finding.Confidence, "low") {
				issue("validated_finding_low_confidence", finding.ID, "validated finding cannot have low confidence")
			}
			if strings.TrimSpace(finding.Location) == "" {
				warn("validated_finding_location_missing", finding.ID, "validated finding has no file/address/url/class location")
			}
		}
	}
	for _, path := range value.Paths {
		if path.PathType == "" {
			warn("path_type_missing", path.ID, "path does not declare attack/callflow/solve type")
		}
		for index, step := range path.Steps {
			if len(step.EvidenceIDs) == 0 {
				warn("path_step_evidence_missing", path.ID, fmt.Sprintf("path step %d has no evidence link", index+1))
			}
		}
	}
	for _, detection := range value.Detections {
		if !detection.Validated {
			continue
		}
		if !detection.SyntaxValid || !detection.SchemaValid || !detection.PositivePassed || !detection.NegativePassed || !detection.TelemetryAvailable {
			issue("detection_validation_incomplete", detection.ID, "validated detection is missing explicit validation gates")
		}
		if !hasRetest(value, detection.ID) {
			issue("detection_retest_required", detection.ID, "validated detection requires an evidence-backed retest")
		}
	}
	for _, retest := range value.Retests {
		if len(retest.EvidenceIDs) == 0 {
			issue("retest_evidence_required", retest.ID, "retest requires evidence")
		}
	}
	return result, nil
}

func hasRetest(value Case, subjectID string) bool {
	for _, item := range value.Retests {
		if item.SubjectID == subjectID && len(item.EvidenceIDs) > 0 {
			return true
		}
	}
	return false
}
