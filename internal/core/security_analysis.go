package core

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"reverseresearch/internal/casebook"
	"reverseresearch/internal/detection"
	"reverseresearch/internal/malware"
)

type MalwareTriageRequest struct {
	Path    string          `json:"path"`
	CaseID  string          `json:"case_id,omitempty"`
	Options malware.Options `json:"options"`
}

type MalwareTriageResult struct {
	Report      malware.Report        `json:"report"`
	Artifact    *casebook.Artifact    `json:"artifact,omitempty"`
	Evidence    *casebook.Evidence    `json:"evidence,omitempty"`
	Observation *casebook.Observation `json:"observation,omitempty"`
}

type SigmaValidationRequest struct {
	RulePath           string   `json:"rule_path"`
	PositiveFixtures   []string `json:"positive_fixtures"`
	NegativeFixtures   []string `json:"negative_fixtures"`
	CaseID             string   `json:"case_id,omitempty"`
	Name               string   `json:"name,omitempty"`
	Technique          string   `json:"technique,omitempty"`
	Telemetry          []string `json:"telemetry,omitempty"`
	TelemetryAvailable bool     `json:"telemetry_available"`
	FalsePositiveNotes string   `json:"false_positive_notes,omitempty"`
	Coverage           string   `json:"coverage,omitempty"`
}

type SigmaValidationResult struct {
	Validation detection.SigmaValidation `json:"validation"`
	Evidence   []casebook.Evidence       `json:"evidence,omitempty"`
	Detection  *casebook.Detection       `json:"detection,omitempty"`
}

func (s *Service) TriageMalware(ctx context.Context, request MalwareTriageRequest) (MalwareTriageResult, error) {
	request.Path = strings.TrimSpace(request.Path)
	request.CaseID = strings.TrimSpace(request.CaseID)
	if request.Path == "" {
		return MalwareTriageResult{}, errors.New("malware path is required")
	}
	report, err := malware.New(s.root).Triage(ctx, request.Path, request.Options)
	if err != nil {
		return MalwareTriageResult{}, err
	}
	result := MalwareTriageResult{Report: report}
	if request.CaseID == "" {
		return result, nil
	}
	if err := s.requireCaseRoute(request.CaseID, "malware-analysis"); err != nil {
		return MalwareTriageResult{}, err
	}
	artifact, err := s.cases.AddArtifact(request.CaseID, casebook.ArtifactRequest{
		Kind: "malware-sample", Identity: report.Target.ID, Source: report.Target.Path,
		SHA256: report.Target.SHA256, Size: report.Target.Size,
	})
	if err != nil {
		return MalwareTriageResult{}, err
	}
	result.Artifact = &artifact

	notes := fmt.Sprintf(
		"bounded static triage; sample_execution_performed=%t; network_interaction=%t; sections=%d; strings=%d; signals=%d",
		report.SampleExecutionPerformed, report.NetworkInteraction, len(report.Sections), len(report.Strings), len(report.Signals),
	)
	evidence, err := s.cases.AddEvidence(request.CaseID, casebook.EvidenceRequest{
		Summary: "Bounded static malware triage for " + report.Target.ID,
		Kind:    "static-analysis", SourcePath: report.Target.Path, Notes: notes,
		ReproCommand: "ReverseResearch malware triage <sample> --die=" + fmt.Sprint(request.Options.UseDIE),
	})
	if err != nil {
		return result, err
	}
	result.Evidence = &evidence

	observation, err := s.cases.AddObservation(request.CaseID, casebook.ObservationRequest{
		Summary: fmt.Sprintf(
			"Static triage completed for %s without executing the sample or performing network interaction; %d PE section profile(s), %d bounded string sample(s), %d heuristic signal(s) recorded.",
			report.Target.ID, len(report.Sections), len(report.Strings), len(report.Signals),
		),
		EvidenceIDs: []string{evidence.ID},
	})
	if err != nil {
		return result, err
	}
	result.Observation = &observation
	return result, nil
}

func (s *Service) ValidateSigma(request SigmaValidationRequest) (SigmaValidationResult, error) {
	request.RulePath = strings.TrimSpace(request.RulePath)
	request.CaseID = strings.TrimSpace(request.CaseID)
	request.Name = strings.TrimSpace(request.Name)
	request.Technique = strings.TrimSpace(request.Technique)
	request.FalsePositiveNotes = strings.TrimSpace(request.FalsePositiveNotes)
	request.Coverage = strings.TrimSpace(request.Coverage)
	request.Telemetry = cleanCoreStrings(request.Telemetry)
	if request.RulePath == "" {
		return SigmaValidationResult{}, errors.New("sigma rule_path is required")
	}
	validation, err := detection.ValidateSigmaFiles(detection.SigmaRequest{
		RulePath: request.RulePath, PositiveFixtures: request.PositiveFixtures, NegativeFixtures: request.NegativeFixtures,
	})
	if err != nil {
		return SigmaValidationResult{}, err
	}
	result := SigmaValidationResult{Validation: validation}
	if request.CaseID == "" {
		return result, nil
	}
	if err := s.requireCaseRouteAny(request.CaseID, "blue-detection", "purple-validation", "malware-analysis"); err != nil {
		return SigmaValidationResult{}, err
	}
	if len(request.Telemetry) == 0 || request.FalsePositiveNotes == "" || request.Coverage == "" {
		return SigmaValidationResult{}, errors.New("case-bound Sigma validation requires telemetry, false_positive_notes, and coverage")
	}
	if request.Name == "" {
		request.Name = validation.Title
	}

	evidence := make([]casebook.Evidence, 0, 1+len(validation.PositiveFixtures)+len(validation.NegativeFixtures))
	addEvidence := func(summary, kind, source string) error {
		item, addErr := s.cases.AddEvidence(request.CaseID, casebook.EvidenceRequest{
			Summary: summary, Kind: kind, SourcePath: source,
			ReproCommand: "ReverseResearch detection sigma --rule <rule> --positive <fixtures> --negative <fixtures>",
		})
		if addErr != nil {
			return addErr
		}
		evidence = append(evidence, item)
		return nil
	}
	if err := addEvidence("Sigma rule "+validation.Title+" revision "+validation.RuleRevision, "detection-rule", validation.RulePath); err != nil {
		return result, err
	}
	for _, fixture := range validation.PositiveFixtures {
		if err := addEvidence(
			fmt.Sprintf("Positive detection fixture %s: events=%d matches=%d passed=%t", filepath.Base(fixture.Path), fixture.Events, fixture.Matches, fixture.Passed),
			"detection-positive-fixture", fixture.Path,
		); err != nil {
			result.Evidence = evidence
			return result, err
		}
	}
	for _, fixture := range validation.NegativeFixtures {
		if err := addEvidence(
			fmt.Sprintf("Negative detection fixture %s: events=%d matches=%d passed=%t", filepath.Base(fixture.Path), fixture.Events, fixture.Matches, fixture.Passed),
			"detection-negative-fixture", fixture.Path,
		); err != nil {
			result.Evidence = evidence
			return result, err
		}
	}
	result.Evidence = evidence
	evidenceIDs := make([]string, 0, len(evidence))
	for _, item := range evidence {
		evidenceIDs = append(evidenceIDs, item.ID)
	}
	caseValidated := validation.Validated && request.TelemetryAvailable
	detectionRecord, err := s.cases.AddDetection(request.CaseID, casebook.DetectionRequest{
		Name: request.Name, Kind: "sigma", Technique: request.Technique,
		TelemetryRequirement: request.Telemetry, Rule: validation.RuleText, Revision: validation.RuleRevision,
		PositiveFixture: fixtureIdentitySummary(validation.PositiveFixtures),
		NegativeFixture: fixtureIdentitySummary(validation.NegativeFixtures),
		ExpectedHit:     validation.ExpectedHit, FalsePositiveNotes: request.FalsePositiveNotes, Coverage: request.Coverage,
		EvidenceIDs: evidenceIDs, SyntaxValid: validation.SyntaxValid, SchemaValid: validation.SchemaValid,
		PositivePassed: validation.PositivePassed, NegativePassed: validation.NegativePassed,
		TelemetryAvailable: request.TelemetryAvailable, Validated: caseValidated,
	})
	if err != nil {
		return result, err
	}
	result.Detection = &detectionRecord
	return result, nil
}

func (s *Service) requireCaseRoute(caseID, route string) error {
	return s.requireCaseRouteAny(caseID, route)
}

func (s *Service) requireCaseRouteAny(caseID string, allowed ...string) error {
	value, err := s.cases.Get(caseID)
	if err != nil {
		return err
	}
	if strings.TrimSpace(value.Route) == "" {
		return nil
	}
	for _, route := range allowed {
		if value.Route == route {
			return nil
		}
	}
	return fmt.Errorf("case %s route %q is incompatible with this operation; expected one of %v", caseID, value.Route, allowed)
}

func fixtureIdentitySummary(fixtures []detection.FixtureResult) string {
	parts := make([]string, 0, len(fixtures))
	for _, fixture := range fixtures {
		parts = append(parts, filepath.Base(fixture.Path)+"@sha256:"+fixture.SHA256)
	}
	return strings.Join(parts, ";")
}

func cleanCoreStrings(values []string) []string {
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
