package casebook

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

type Target struct {
	ID       string `json:"id"`
	Kind     string `json:"kind,omitempty"`
	Identity string `json:"identity"`
	Label    string `json:"label,omitempty"`
}

type Artifact struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	Identity   string `json:"identity"`
	Source     string `json:"source,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
	Size       int64  `json:"size,omitempty"`
	CreatedUTC string `json:"created_utc"`
}

type Observation struct {
	ID          string   `json:"id"`
	Summary     string   `json:"summary"`
	EvidenceIDs []string `json:"evidence_ids,omitempty"`
	CreatedUTC  string   `json:"created_utc"`
}

type HypothesisStatus string

const (
	HypothesisOpen      HypothesisStatus = "open"
	HypothesisSupported HypothesisStatus = "supported"
	HypothesisRejected  HypothesisStatus = "rejected"
	HypothesisRetracted HypothesisStatus = "retracted"
)

type HypothesisRequest struct {
	Hypothesis             string   `json:"hypothesis"`
	SupportingEvidenceIDs  []string `json:"supporting_evidence_ids,omitempty"`
	ConflictingEvidenceIDs []string `json:"conflicting_evidence_ids,omitempty"`
	RequiredExperiment     string   `json:"required_experiment,omitempty"`
}

type HypothesisUpdateRequest struct {
	Status                  HypothesisStatus `json:"status"`
	SupportingEvidenceIDs   []string         `json:"supporting_evidence_ids,omitempty"`
	ConflictingEvidenceIDs  []string         `json:"conflicting_evidence_ids,omitempty"`
	RequiredExperiment      string           `json:"required_experiment,omitempty"`
	RejectedReason          string           `json:"rejected_reason,omitempty"`
	ReplacementHypothesisID string           `json:"replacement_hypothesis_id,omitempty"`
}

type Hypothesis struct {
	ID                      string           `json:"id"`
	Hypothesis              string           `json:"hypothesis"`
	SupportingEvidenceIDs   []string         `json:"supporting_evidence_ids,omitempty"`
	ConflictingEvidenceIDs  []string         `json:"conflicting_evidence_ids,omitempty"`
	RequiredExperiment      string           `json:"required_experiment,omitempty"`
	Status                  HypothesisStatus `json:"status"`
	RejectedReason          string           `json:"rejected_reason,omitempty"`
	ReplacementHypothesisID string           `json:"replacement_hypothesis_id,omitempty"`
	CreatedUTC              string           `json:"created_utc"`
	UpdatedUTC              string           `json:"updated_utc"`
}

type Vulnerability struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	CWE         []string `json:"cwe,omitempty"`
	CAPEC       []string `json:"capec,omitempty"`
	CVE         []string `json:"cve,omitempty"`
	FindingIDs  []string `json:"finding_ids,omitempty"`
	EvidenceIDs []string `json:"evidence_ids,omitempty"`
}

type IOC struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Value    string `json:"value"`
	SourceID string `json:"source_id,omitempty"`
}

type TTP struct {
	ID         string   `json:"id"`
	Technique  string   `json:"technique"`
	Tactic     string   `json:"tactic,omitempty"`
	FindingIDs []string `json:"finding_ids,omitempty"`
}

type DetectionRequest struct {
	Name                 string   `json:"name"`
	Kind                 string   `json:"kind"`
	Technique            string   `json:"technique,omitempty"`
	TelemetryRequirement []string `json:"telemetry_requirement,omitempty"`
	Rule                 string   `json:"rule"`
	Revision             string   `json:"revision"`
	PositiveFixture      string   `json:"positive_fixture,omitempty"`
	NegativeFixture      string   `json:"negative_fixture,omitempty"`
	ExpectedHit          string   `json:"expected_hit,omitempty"`
	FalsePositiveNotes   string   `json:"false_positive_notes,omitempty"`
	Coverage             string   `json:"coverage,omitempty"`
	EvidenceIDs          []string `json:"evidence_ids,omitempty"`
	SyntaxValid          bool     `json:"syntax_valid"`
	SchemaValid          bool     `json:"schema_valid"`
	PositivePassed       bool     `json:"positive_passed"`
	NegativePassed       bool     `json:"negative_passed"`
	TelemetryAvailable   bool     `json:"telemetry_available"`
	Validated            bool     `json:"validated"`
}

type Detection struct {
	ID                   string   `json:"id"`
	Name                 string   `json:"name"`
	Kind                 string   `json:"kind"`
	Technique            string   `json:"technique,omitempty"`
	TelemetryRequirement []string `json:"telemetry_requirement,omitempty"`
	Rule                 string   `json:"rule"`
	Revision             string   `json:"revision"`
	PositiveFixture      string   `json:"positive_fixture,omitempty"`
	NegativeFixture      string   `json:"negative_fixture,omitempty"`
	ExpectedHit          string   `json:"expected_hit,omitempty"`
	FalsePositiveNotes   string   `json:"false_positive_notes,omitempty"`
	Coverage             string   `json:"coverage,omitempty"`
	EvidenceIDs          []string `json:"evidence_ids,omitempty"`
	SyntaxValid          bool     `json:"syntax_valid"`
	SchemaValid          bool     `json:"schema_valid"`
	PositivePassed       bool     `json:"positive_passed"`
	NegativePassed       bool     `json:"negative_passed"`
	TelemetryAvailable   bool     `json:"telemetry_available"`
	Validated            bool     `json:"validated"`
	CreatedUTC           string   `json:"created_utc"`
}

type Mitigation struct {
	ID          string   `json:"id"`
	Summary     string   `json:"summary"`
	Technique   string   `json:"technique,omitempty"`
	FindingIDs  []string `json:"finding_ids,omitempty"`
	EvidenceIDs []string `json:"evidence_ids,omitempty"`
}

type RetestRequest struct {
	SubjectType string   `json:"subject_type"`
	SubjectID   string   `json:"subject_id"`
	Status      string   `json:"status"`
	Summary     string   `json:"summary"`
	EvidenceIDs []string `json:"evidence_ids,omitempty"`
}

type Retest struct {
	ID          string   `json:"id"`
	SubjectType string   `json:"subject_type"`
	SubjectID   string   `json:"subject_id"`
	Status      string   `json:"status"`
	Summary     string   `json:"summary"`
	EvidenceIDs []string `json:"evidence_ids,omitempty"`
	CreatedUTC  string   `json:"created_utc"`
}

type Report struct {
	ID                 string   `json:"id"`
	SchemaVersion      int      `json:"schema_version"`
	Kind               string   `json:"kind"`
	Format             string   `json:"format"`
	Revision           string   `json:"revision"`
	Profile            string   `json:"profile,omitempty"`
	Classification     string   `json:"classification,omitempty"`
	Status             string   `json:"status"`
	Summary            string   `json:"summary,omitempty"`
	ArtifactID         string   `json:"artifact_id,omitempty"`
	FindingIDs         []string `json:"finding_ids,omitempty"`
	EvidenceIDs        []string `json:"evidence_ids,omitempty"`
	Sections           []string `json:"sections,omitempty"`
	SupersedesReportID string   `json:"supersedes_report_id,omitempty"`
	CaseSHA256         string   `json:"case_sha256"`
	CreatedUTC         string   `json:"created_utc"`
}

func (s *Store) AddHypothesis(caseID string, request HypothesisRequest) (result Hypothesis, err error) {
	release, err := s.lockCase(caseID)
	if err != nil {
		return Hypothesis{}, err
	}
	defer func() { err = errors.Join(err, release()) }()
	value, err := s.get(caseID)
	if err != nil {
		return Hypothesis{}, err
	}
	text := strings.TrimSpace(request.Hypothesis)
	if text == "" {
		return Hypothesis{}, errors.New("hypothesis is required")
	}
	if err := validateEvidenceIDs(value, append(append([]string(nil), request.SupportingEvidenceIDs...), request.ConflictingEvidenceIDs...)); err != nil {
		return Hypothesis{}, err
	}
	id, err := newID("h")
	if err != nil {
		return Hypothesis{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	hypothesis := Hypothesis{
		ID: id, Hypothesis: text,
		SupportingEvidenceIDs:  cleanStrings(request.SupportingEvidenceIDs),
		ConflictingEvidenceIDs: cleanStrings(request.ConflictingEvidenceIDs),
		RequiredExperiment:     strings.TrimSpace(request.RequiredExperiment),
		Status:                 HypothesisOpen, CreatedUTC: now, UpdatedUTC: now,
	}
	value.SchemaVersion = 2
	value.Hypotheses = append(value.Hypotheses, hypothesis)
	value.UpdatedUTC = now
	if err := s.save(value); err != nil {
		return Hypothesis{}, err
	}
	return hypothesis, nil
}

func (s *Store) UpdateHypothesis(caseID, hypothesisID string, request HypothesisUpdateRequest) (result Hypothesis, err error) {
	release, err := s.lockCase(caseID)
	if err != nil {
		return Hypothesis{}, err
	}
	defer func() { err = errors.Join(err, release()) }()
	value, err := s.get(caseID)
	if err != nil {
		return Hypothesis{}, err
	}
	if err := validateEvidenceIDs(value, append(append([]string(nil), request.SupportingEvidenceIDs...), request.ConflictingEvidenceIDs...)); err != nil {
		return Hypothesis{}, err
	}
	if request.Status != HypothesisOpen && request.Status != HypothesisSupported && request.Status != HypothesisRejected && request.Status != HypothesisRetracted {
		return Hypothesis{}, fmt.Errorf("invalid hypothesis status %q", request.Status)
	}
	index := -1
	for i := range value.Hypotheses {
		if value.Hypotheses[i].ID == hypothesisID {
			index = i
			break
		}
	}
	if index < 0 {
		return Hypothesis{}, fmt.Errorf("unknown hypothesis id %q", hypothesisID)
	}
	replacement := strings.TrimSpace(request.ReplacementHypothesisID)
	if replacement != "" {
		found := false
		for i := range value.Hypotheses {
			if value.Hypotheses[i].ID == replacement && replacement != hypothesisID {
				found = true
				break
			}
		}
		if !found {
			return Hypothesis{}, fmt.Errorf("unknown replacement hypothesis id %q", replacement)
		}
	}
	reason := strings.TrimSpace(request.RejectedReason)
	if (request.Status == HypothesisRejected || request.Status == HypothesisRetracted) && reason == "" {
		return Hypothesis{}, errors.New("rejected/retracted hypothesis requires rejected_reason")
	}
	item := &value.Hypotheses[index]
	item.Status = request.Status
	if request.SupportingEvidenceIDs != nil {
		item.SupportingEvidenceIDs = cleanStrings(request.SupportingEvidenceIDs)
	}
	if request.ConflictingEvidenceIDs != nil {
		item.ConflictingEvidenceIDs = cleanStrings(request.ConflictingEvidenceIDs)
	}
	if strings.TrimSpace(request.RequiredExperiment) != "" {
		item.RequiredExperiment = strings.TrimSpace(request.RequiredExperiment)
	}
	item.RejectedReason = reason
	item.ReplacementHypothesisID = replacement
	item.UpdatedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	value.SchemaVersion = 2
	value.UpdatedUTC = item.UpdatedUTC
	if err := s.save(value); err != nil {
		return Hypothesis{}, err
	}
	return *item, nil
}

func (s *Store) AddDetection(caseID string, request DetectionRequest) (result Detection, err error) {
	release, err := s.lockCase(caseID)
	if err != nil {
		return Detection{}, err
	}
	defer func() { err = errors.Join(err, release()) }()
	value, err := s.get(caseID)
	if err != nil {
		return Detection{}, err
	}
	request.Name = strings.TrimSpace(request.Name)
	request.Kind = strings.TrimSpace(request.Kind)
	request.Rule = strings.TrimSpace(request.Rule)
	request.Revision = strings.TrimSpace(request.Revision)
	if request.Name == "" || request.Kind == "" || request.Rule == "" || request.Revision == "" {
		return Detection{}, errors.New("detection name, kind, rule, and revision are required")
	}
	if err := validateEvidenceIDs(value, request.EvidenceIDs); err != nil {
		return Detection{}, err
	}
	if request.Validated {
		if strings.TrimSpace(request.PositiveFixture) == "" || strings.TrimSpace(request.NegativeFixture) == "" || strings.TrimSpace(request.ExpectedHit) == "" {
			return Detection{}, errors.New("validated detection requires positive_fixture, negative_fixture, and expected_hit")
		}
		if len(request.EvidenceIDs) == 0 || len(request.TelemetryRequirement) == 0 {
			return Detection{}, errors.New("validated detection requires evidence_ids and telemetry_requirement")
		}
		if !request.SyntaxValid || !request.SchemaValid || !request.PositivePassed || !request.NegativePassed || !request.TelemetryAvailable {
			return Detection{}, errors.New("validated detection requires syntax/schema validation, positive/negative fixture pass, and telemetry availability")
		}
		if strings.TrimSpace(request.FalsePositiveNotes) == "" {
			return Detection{}, errors.New("validated detection requires false_positive_notes")
		}
	}
	id, err := newID("d")
	if err != nil {
		return Detection{}, err
	}
	detection := Detection{
		ID: id, Name: request.Name, Kind: request.Kind, Technique: strings.TrimSpace(request.Technique),
		TelemetryRequirement: cleanStrings(request.TelemetryRequirement), Rule: request.Rule, Revision: request.Revision,
		PositiveFixture: strings.TrimSpace(request.PositiveFixture), NegativeFixture: strings.TrimSpace(request.NegativeFixture),
		ExpectedHit: strings.TrimSpace(request.ExpectedHit), FalsePositiveNotes: strings.TrimSpace(request.FalsePositiveNotes),
		Coverage: strings.TrimSpace(request.Coverage), EvidenceIDs: cleanStrings(request.EvidenceIDs),
		SyntaxValid: request.SyntaxValid, SchemaValid: request.SchemaValid,
		PositivePassed: request.PositivePassed, NegativePassed: request.NegativePassed,
		TelemetryAvailable: request.TelemetryAvailable, Validated: request.Validated,
		CreatedUTC: time.Now().UTC().Format(time.RFC3339Nano),
	}
	value.SchemaVersion = 2
	value.Detections = append(value.Detections, detection)
	value.UpdatedUTC = detection.CreatedUTC
	if err := s.save(value); err != nil {
		return Detection{}, err
	}
	return detection, nil
}

func (s *Store) AddRetest(caseID string, request RetestRequest) (result Retest, err error) {
	release, err := s.lockCase(caseID)
	if err != nil {
		return Retest{}, err
	}
	defer func() { err = errors.Join(err, release()) }()
	value, err := s.get(caseID)
	if err != nil {
		return Retest{}, err
	}
	request.SubjectType = strings.TrimSpace(request.SubjectType)
	request.SubjectID = strings.TrimSpace(request.SubjectID)
	request.Status = strings.TrimSpace(request.Status)
	request.Summary = strings.TrimSpace(request.Summary)
	if request.SubjectType == "" || request.SubjectID == "" || request.Status == "" || request.Summary == "" {
		return Retest{}, errors.New("retest subject_type, subject_id, status, and summary are required")
	}
	if len(request.EvidenceIDs) == 0 {
		return Retest{}, errors.New("retest requires evidence_ids")
	}
	if err := validateEvidenceIDs(value, request.EvidenceIDs); err != nil {
		return Retest{}, err
	}
	if !caseObjectExists(value, request.SubjectID) {
		return Retest{}, fmt.Errorf("unknown retest subject id %q", request.SubjectID)
	}
	id, err := newID("r")
	if err != nil {
		return Retest{}, err
	}
	retest := Retest{
		ID: id, SubjectType: request.SubjectType, SubjectID: request.SubjectID, Status: request.Status,
		Summary: request.Summary, EvidenceIDs: cleanStrings(request.EvidenceIDs), CreatedUTC: time.Now().UTC().Format(time.RFC3339Nano),
	}
	value.SchemaVersion = 2
	value.Retests = append(value.Retests, retest)
	value.UpdatedUTC = retest.CreatedUTC
	if err := s.save(value); err != nil {
		return Retest{}, err
	}
	return retest, nil
}

func validateEvidenceIDs(value Case, ids []string) error {
	known := make(map[string]bool, len(value.Evidence))
	for _, evidence := range value.Evidence {
		known[evidence.ID] = true
	}
	for _, id := range cleanStrings(ids) {
		if !known[id] {
			return fmt.Errorf("unknown evidence id %q", id)
		}
	}
	return nil
}

func normalizeTargets(values []Target) []Target {
	seen := map[string]bool{}
	result := make([]Target, 0, len(values))
	for _, value := range values {
		value.ID = strings.TrimSpace(value.ID)
		value.Kind = strings.TrimSpace(value.Kind)
		value.Identity = strings.TrimSpace(value.Identity)
		value.Label = strings.TrimSpace(value.Label)
		if value.Identity == "" {
			continue
		}
		key := value.ID + "\x00" + value.Identity
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, value)
	}
	return result
}

func cleanStrings(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}
