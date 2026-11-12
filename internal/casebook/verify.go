package casebook

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Verification checks recorded structure and current source bytes, not whether a
// research conclusion is true or a debugger has validated it at runtime.
type Verification struct {
	CaseID           string  `json:"case_id"`
	CaseSHA256       string  `json:"case_sha256"`
	CheckedUTC       string  `json:"checked_utc"`
	Valid            bool    `json:"valid"`
	EvidenceChecked  int     `json:"evidence_checked"`
	UnboundEvidence  int     `json:"unbound_evidence"`
	UnboundFindings  int     `json:"unbound_findings"`
	UngradedFindings int     `json:"ungraded_findings"`
	UnboundPaths     int     `json:"unbound_paths"`
	Issues           []Issue `json:"issues"`
}

type Issue struct {
	Code     string `json:"code"`
	ObjectID string `json:"object_id"`
	Message  string `json:"message"`
}

// Verify snapshots one case under its lock, hashes sources without holding the
// record lock, then checks that the case revision did not change during the audit.
// It never rewrites the record or upgrades a finding's confidence.
func (s *Store) Verify(id string) (Verification, error) {
	return s.verify(id, fingerprintSource)
}

func (s *Store) verify(id string, fingerprint func(string) (string, int64, error)) (Verification, error) {
	value, revision, err := s.snapshot(id)
	if err != nil {
		return Verification{}, err
	}
	result := Verification{CaseID: id, CaseSHA256: revision, Valid: true, Issues: []Issue{}}
	issue := func(code, objectID, message string) {
		result.Valid = false
		result.Issues = append(result.Issues, Issue{Code: code, ObjectID: objectID, Message: message})
	}
	seen := make(map[string]bool)
	checkID := func(objectID string) {
		if err := validateID(objectID); err != nil {
			issue("invalid_object_id", objectID, err.Error())
		}
		if seen[objectID] {
			issue("duplicate_object_id", objectID, "object IDs must be unique within a case")
		}
		seen[objectID] = true
	}
	if strings.TrimSpace(value.Title) == "" || (value.Status != StatusOpen && value.Status != StatusClosed) {
		issue("invalid_case", id, "case title or status is invalid")
	}
	for _, target := range value.Targets {
		if target.ID != "" {
			checkID(target.ID)
		}
		if strings.TrimSpace(target.Identity) == "" {
			issue("invalid_target", target.ID, "target identity is empty")
		}
	}
	artifactIDs := make(map[string]bool, len(value.Artifacts))
	for _, artifact := range value.Artifacts {
		checkID(artifact.ID)
		artifactIDs[artifact.ID] = true
		if strings.TrimSpace(artifact.Kind) == "" || strings.TrimSpace(artifact.Identity) == "" || artifact.Size < 0 {
			issue("invalid_artifact", artifact.ID, "artifact kind/identity are required and size must be non-negative")
		}
		if artifact.SHA256 != "" {
			digest, err := hex.DecodeString(artifact.SHA256)
			if err != nil || len(digest) != sha256.Size {
				issue("invalid_artifact_sha256", artifact.ID, "artifact SHA-256 must be 64 hexadecimal characters")
			}
		}
	}
	evidenceIDs := make(map[string]bool, len(value.Evidence))
	for _, evidence := range value.Evidence {
		checkID(evidence.ID)
		evidenceIDs[evidence.ID] = true
		if strings.TrimSpace(evidence.Summary) == "" {
			issue("invalid_evidence", evidence.ID, "evidence summary is empty")
		}
		if evidence.SourcePath == "" {
			if evidence.SourceSHA256 != "" || evidence.SourceSize != 0 {
				issue("invalid_source_binding", evidence.ID, "source metadata has no source path")
			} else {
				result.UnboundEvidence++
			}
			continue
		}
		result.EvidenceChecked++
		digest, decodeErr := hex.DecodeString(evidence.SourceSHA256)
		if decodeErr != nil || len(digest) != sha256.Size || evidence.SourceSize < 0 || !filepath.IsAbs(evidence.SourcePath) {
			issue("invalid_source_binding", evidence.ID, "source binding requires an absolute path, SHA-256 and non-negative size")
			continue
		}
		hash, size, err := fingerprint(evidence.SourcePath)
		if err != nil {
			code := "source_unavailable"
			if errors.Is(err, errSourceChanged) {
				code = "source_changed"
			}
			issue(code, evidence.ID, err.Error())
		} else if !strings.EqualFold(hash, evidence.SourceSHA256) || size != evidence.SourceSize {
			issue("source_changed", evidence.ID, "source size or SHA-256 no longer matches the recorded evidence")
		}
	}
	for _, observation := range value.Observations {
		checkID(observation.ID)
		if strings.TrimSpace(observation.Summary) == "" {
			issue("invalid_observation", observation.ID, "observation summary is empty")
		}
		for _, evidenceID := range observation.EvidenceIDs {
			if !evidenceIDs[evidenceID] {
				issue("unknown_evidence", observation.ID, fmt.Sprintf("unknown evidence ID %q", evidenceID))
			}
		}
	}
	findingIDs := make(map[string]bool, len(value.Findings))
	for _, finding := range value.Findings {
		checkID(finding.ID)
		findingIDs[finding.ID] = true
		if strings.TrimSpace(finding.Title) == "" || strings.TrimSpace(finding.Conclusion) == "" {
			issue("invalid_finding", finding.ID, "finding title or conclusion is empty")
		}
		if len(finding.EvidenceIDs) == 0 {
			result.UnboundFindings++
		}
		if strings.TrimSpace(finding.Strength) == "" {
			// Legacy records predate explicit strength grading. Keep them readable
			// and visible rather than silently rewriting historical conclusions.
			result.UngradedFindings++
		} else if _, err := normalizeFindingStrength(finding.Strength); err != nil {
			issue("invalid_finding_strength", finding.ID, err.Error())
		}
		for _, evidenceID := range finding.EvidenceIDs {
			if !evidenceIDs[evidenceID] {
				issue("unknown_evidence", finding.ID, fmt.Sprintf("unknown evidence ID %q", evidenceID))
			}
		}
	}
	for _, path := range value.Paths {
		checkID(path.ID)
		if strings.TrimSpace(path.Title) == "" || strings.TrimSpace(path.Details) == "" {
			issue("invalid_path", path.ID, "research path title or details is empty")
		}
		if len(path.FindingIDs) == 0 {
			result.UnboundPaths++
		}
		for _, findingID := range path.FindingIDs {
			if !findingIDs[findingID] {
				issue("unknown_finding", path.ID, fmt.Sprintf("unknown finding ID %q", findingID))
			}
		}
	}

	if value.SchemaVersion != 0 && value.SchemaVersion != 2 {
		issue("invalid_schema_version", id, fmt.Sprintf("unsupported case schema_version %d", value.SchemaVersion))
	}

	hypothesisIDs := make(map[string]bool, len(value.Hypotheses))
	for _, hypothesis := range value.Hypotheses {
		checkID(hypothesis.ID)
		hypothesisIDs[hypothesis.ID] = true
		if strings.TrimSpace(hypothesis.Hypothesis) == "" {
			issue("invalid_hypothesis", hypothesis.ID, "hypothesis text is empty")
		}
		switch hypothesis.Status {
		case HypothesisOpen, HypothesisSupported, HypothesisRejected, HypothesisRetracted:
		default:
			issue("invalid_hypothesis_status", hypothesis.ID, fmt.Sprintf("invalid hypothesis status %q", hypothesis.Status))
		}
		if (hypothesis.Status == HypothesisRejected || hypothesis.Status == HypothesisRetracted) && strings.TrimSpace(hypothesis.RejectedReason) == "" {
			issue("missing_retraction_reason", hypothesis.ID, "rejected/retracted hypothesis requires a reason")
		}
		for _, evidenceID := range append(append([]string(nil), hypothesis.SupportingEvidenceIDs...), hypothesis.ConflictingEvidenceIDs...) {
			if !evidenceIDs[evidenceID] {
				issue("unknown_evidence", hypothesis.ID, fmt.Sprintf("unknown evidence ID %q", evidenceID))
			}
		}
	}
	for _, hypothesis := range value.Hypotheses {
		if replacement := strings.TrimSpace(hypothesis.ReplacementHypothesisID); replacement != "" {
			if replacement == hypothesis.ID || !hypothesisIDs[replacement] {
				issue("invalid_replacement_hypothesis", hypothesis.ID, fmt.Sprintf("replacement hypothesis %q is not another known hypothesis", replacement))
			}
		}
	}

	detectionIDs := make(map[string]bool, len(value.Detections))
	for _, detection := range value.Detections {
		checkID(detection.ID)
		detectionIDs[detection.ID] = true
		if strings.TrimSpace(detection.Name) == "" || strings.TrimSpace(detection.Kind) == "" || strings.TrimSpace(detection.Rule) == "" || strings.TrimSpace(detection.Revision) == "" {
			issue("invalid_detection", detection.ID, "detection name, kind, rule, and revision are required")
		}
		for _, evidenceID := range detection.EvidenceIDs {
			if !evidenceIDs[evidenceID] {
				issue("unknown_evidence", detection.ID, fmt.Sprintf("unknown evidence ID %q", evidenceID))
			}
		}
		if detection.Validated {
			if len(detection.EvidenceIDs) == 0 || len(detection.TelemetryRequirement) == 0 || strings.TrimSpace(detection.PositiveFixture) == "" || strings.TrimSpace(detection.NegativeFixture) == "" || strings.TrimSpace(detection.ExpectedHit) == "" {
				issue("invalid_validated_detection", detection.ID, "validated detection requires evidence, telemetry, positive/negative fixtures, and expected hit")
			}
			if !detection.SyntaxValid || !detection.SchemaValid || !detection.PositivePassed || !detection.NegativePassed || !detection.TelemetryAvailable {
				issue("invalid_validated_detection", detection.ID, "validated detection is missing explicit validation gates")
			}
			if strings.TrimSpace(detection.FalsePositiveNotes) == "" {
				issue("invalid_validated_detection", detection.ID, "validated detection requires false-positive notes")
			}
		}
	}

	knownRetestSubjects := make(map[string]bool, len(findingIDs)+len(hypothesisIDs)+len(detectionIDs))
	for objectID := range findingIDs {
		knownRetestSubjects[objectID] = true
	}
	for objectID := range hypothesisIDs {
		knownRetestSubjects[objectID] = true
	}
	for objectID := range detectionIDs {
		knownRetestSubjects[objectID] = true
	}
	for _, vulnerability := range value.Vulnerabilities {
		checkID(vulnerability.ID)
		knownRetestSubjects[vulnerability.ID] = true
		for _, evidenceID := range vulnerability.EvidenceIDs {
			if !evidenceIDs[evidenceID] {
				issue("unknown_evidence", vulnerability.ID, fmt.Sprintf("unknown evidence ID %q", evidenceID))
			}
		}
		for _, findingID := range vulnerability.FindingIDs {
			if !findingIDs[findingID] {
				issue("unknown_finding", vulnerability.ID, fmt.Sprintf("unknown finding ID %q", findingID))
			}
		}
	}
	for _, mitigation := range value.Mitigations {
		checkID(mitigation.ID)
		knownRetestSubjects[mitigation.ID] = true
		if strings.TrimSpace(mitigation.Summary) == "" {
			issue("invalid_mitigation", mitigation.ID, "mitigation summary is empty")
		}
		for _, evidenceID := range mitigation.EvidenceIDs {
			if !evidenceIDs[evidenceID] {
				issue("unknown_evidence", mitigation.ID, fmt.Sprintf("unknown evidence ID %q", evidenceID))
			}
		}
		for _, findingID := range mitigation.FindingIDs {
			if !findingIDs[findingID] {
				issue("unknown_finding", mitigation.ID, fmt.Sprintf("unknown finding ID %q", findingID))
			}
		}
	}
	for _, retest := range value.Retests {
		checkID(retest.ID)
		if strings.TrimSpace(retest.SubjectType) == "" || strings.TrimSpace(retest.SubjectID) == "" || strings.TrimSpace(retest.Status) == "" || strings.TrimSpace(retest.Summary) == "" {
			issue("invalid_retest", retest.ID, "retest subject, status, and summary are required")
		}
		if !knownRetestSubjects[retest.SubjectID] {
			issue("unknown_retest_subject", retest.ID, fmt.Sprintf("unknown retest subject ID %q", retest.SubjectID))
		}
		for _, evidenceID := range retest.EvidenceIDs {
			if !evidenceIDs[evidenceID] {
				issue("unknown_evidence", retest.ID, fmt.Sprintf("unknown evidence ID %q", evidenceID))
			}
		}
	}
	for _, role := range value.Roles {
		checkID(role.ID)
		if strings.TrimSpace(role.Role) == "" || strings.TrimSpace(role.Status) == "" {
			issue("invalid_role", role.ID, "role and status are required")
		}
	}
	workItemIDs := make(map[string]bool, len(value.WorkItems))
	for _, workItem := range value.WorkItems {
		checkID(workItem.ID)
		workItemIDs[workItem.ID] = true
		if strings.TrimSpace(workItem.Title) == "" {
			issue("invalid_workitem", workItem.ID, "workitem title is empty")
		}
		switch workItem.Status {
		case "planned", "running", "blocked", "done", "cancelled":
		default:
			issue("invalid_workitem_status", workItem.ID, fmt.Sprintf("invalid workitem status %q", workItem.Status))
		}
		if workItem.Status == "blocked" && strings.TrimSpace(workItem.BlockedReason) == "" {
			issue("missing_blocked_reason", workItem.ID, "blocked workitem requires a reason")
		}
		for _, evidenceID := range workItem.EvidenceIDs {
			if !evidenceIDs[evidenceID] {
				issue("unknown_evidence", workItem.ID, fmt.Sprintf("unknown evidence ID %q", evidenceID))
			}
		}
	}
	for _, evidence := range value.Evidence {
		if evidence.LinkedWorkItemID != "" && !workItemIDs[evidence.LinkedWorkItemID] {
			issue("unknown_workitem", evidence.ID, fmt.Sprintf("unknown linked workitem ID %q", evidence.LinkedWorkItemID))
		}
		if evidence.SupersedesEvidenceID != "" && !evidenceIDs[evidence.SupersedesEvidenceID] {
			issue("unknown_superseded_evidence", evidence.ID, fmt.Sprintf("unknown superseded evidence ID %q", evidence.SupersedesEvidenceID))
		}
	}
	for _, entry := range value.Timeline {
		checkID(entry.ID)
		if strings.TrimSpace(entry.Kind) == "" || strings.TrimSpace(entry.Summary) == "" {
			issue("invalid_timeline", entry.ID, "timeline kind and summary are required")
		}
		if entry.WorkItemID != "" && !workItemIDs[entry.WorkItemID] {
			issue("unknown_workitem", entry.ID, fmt.Sprintf("unknown workitem ID %q", entry.WorkItemID))
		}
		for _, evidenceID := range entry.EvidenceIDs {
			if !evidenceIDs[evidenceID] {
				issue("unknown_evidence", entry.ID, fmt.Sprintf("unknown evidence ID %q", evidenceID))
			}
		}
	}
	for _, ioc := range value.IOCs {
		checkID(ioc.ID)
		if strings.TrimSpace(ioc.Type) == "" || strings.TrimSpace(ioc.Value) == "" {
			issue("invalid_ioc", ioc.ID, "IOC type and value are required")
		}
		if ioc.SourceID != "" && !caseHasSourceObject(value, ioc.SourceID) {
			issue("unknown_ioc_source", ioc.ID, fmt.Sprintf("unknown source ID %q", ioc.SourceID))
		}
	}
	for _, ttp := range value.TTPs {
		checkID(ttp.ID)
		knownRetestSubjects[ttp.ID] = true
		if strings.TrimSpace(ttp.Technique) == "" {
			issue("invalid_ttp", ttp.ID, "TTP technique is required")
		}
		for _, findingID := range ttp.FindingIDs {
			if !findingIDs[findingID] {
				issue("unknown_finding", ttp.ID, fmt.Sprintf("unknown finding ID %q", findingID))
			}
		}
	}
	reportIDs := make(map[string]bool, len(value.Reports))
	for _, report := range value.Reports {
		checkID(report.ID)
		reportIDs[report.ID] = true
	}
	for _, report := range value.Reports {
		if report.SchemaVersion != 1 || strings.TrimSpace(report.Kind) == "" || strings.TrimSpace(report.Format) == "" || strings.TrimSpace(report.Revision) == "" {
			issue("invalid_report", report.ID, "report schema_version=1, kind, format, and revision are required")
		}
		switch report.Status {
		case "draft", "final":
		default:
			issue("invalid_report_status", report.ID, fmt.Sprintf("invalid report status %q", report.Status))
		}
		if len(report.CaseSHA256) != 64 {
			issue("invalid_report_case_revision", report.ID, "report must pin a 64-character Case SHA-256 revision")
		}
		if report.ArtifactID != "" && !artifactIDs[report.ArtifactID] {
			issue("unknown_artifact", report.ID, fmt.Sprintf("unknown artifact ID %q", report.ArtifactID))
		}
		for _, findingID := range report.FindingIDs {
			if !findingIDs[findingID] {
				issue("unknown_finding", report.ID, fmt.Sprintf("unknown finding ID %q", findingID))
			}
		}
		for _, evidenceID := range report.EvidenceIDs {
			if !evidenceIDs[evidenceID] {
				issue("unknown_evidence", report.ID, fmt.Sprintf("unknown evidence ID %q", evidenceID))
			}
		}
		if report.SupersedesReportID != "" && !reportIDs[report.SupersedesReportID] {
			issue("unknown_superseded_report", report.ID, fmt.Sprintf("unknown superseded report ID %q", report.SupersedesReportID))
		}
		if report.Status == "final" {
			if strings.TrimSpace(report.Profile) == "" || strings.TrimSpace(report.Classification) == "" || len(report.Sections) == 0 {
				issue("incomplete_final_report", report.ID, "final report requires profile, classification, and sections")
			}
			if len(report.FindingIDs) == 0 && len(report.EvidenceIDs) == 0 {
				issue("unbound_final_report", report.ID, "final report requires finding or evidence links")
			}
		}
	}
	_, currentRevision, err := s.snapshot(id)
	if err != nil {
		return Verification{}, fmt.Errorf("recheck case revision: %w", err)
	}
	if currentRevision != revision {
		issue("case_changed", id, "case changed during verification; rerun against the current revision")
	}
	result.CheckedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	return result, nil
}

func (s *Store) snapshot(id string) (value Case, revision string, err error) {
	release, err := s.lockCase(id)
	if err != nil {
		return Case{}, "", err
	}
	defer func() { err = errors.Join(err, release()) }()
	value, body, err := s.read(id)
	if err != nil {
		return Case{}, "", err
	}
	digest := sha256.Sum256(body)
	return value, hex.EncodeToString(digest[:]), nil
}

// List returns newest cases first. A durable index avoids parsing every case
// record on every bounded list call. The index is automatically rebuilt after
// external changes, missing cache state, or corruption.
func (s *Store) List(limit int) ([]Case, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	index, err := s.currentCaseIndex()
	if err != nil {
		return nil, err
	}
	if len(index.Entries) > limit {
		index.Entries = index.Entries[:limit]
	}
	values := make([]Case, 0, len(index.Entries))
	for _, entry := range index.Entries {
		value, err := s.Get(entry.ID)
		if err != nil {
			// One removed or damaged case must not break every bounded list:
			// refence the cache so the next call rebuilds without the dangling
			// entry, and return the cases that are still readable.
			if errors.Is(err, os.ErrNotExist) {
				_ = s.invalidateCaseIndex()
			}
			continue
		}
		values = append(values, value)
	}
	return values, nil
}
