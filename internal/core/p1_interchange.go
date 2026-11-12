package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"reverseresearch/internal/casebook"
	"reverseresearch/internal/protocolinfer"
	"reverseresearch/internal/sourceaudit"
	"reverseresearch/internal/targetidentity"
)

type SARIFImportRequest struct {
	Path       string `json:"path"`
	CaseID     string `json:"case_id,omitempty"`
	MaxBytes   int64  `json:"max_bytes,omitempty"`
	MaxResults int    `json:"max_results,omitempty"`
}

type SARIFImportResult struct {
	Report   sourceaudit.SARIFReport `json:"report"`
	Artifact *casebook.Artifact      `json:"artifact,omitempty"`
	Evidence *casebook.Evidence      `json:"evidence,omitempty"`
	Findings []casebook.Finding      `json:"findings,omitempty"`
}

type SBOMImportRequest struct {
	Path          string `json:"path"`
	CaseID        string `json:"case_id,omitempty"`
	MaxBytes      int64  `json:"max_bytes,omitempty"`
	MaxComponents int    `json:"max_components,omitempty"`
}

type SBOMImportResult struct {
	Report      sourceaudit.SBOMReport `json:"report"`
	Artifact    *casebook.Artifact     `json:"artifact,omitempty"`
	Evidence    *casebook.Evidence     `json:"evidence,omitempty"`
	Observation *casebook.Observation  `json:"observation,omitempty"`
}

type ProtocolValidationRequest struct {
	ModelSamplesPath string `json:"model_samples_path"`
	FixturesPath     string `json:"fixtures_path"`
	CaseID           string `json:"case_id,omitempty"`
	Name             string `json:"name,omitempty"`
	MaxBytes         int64  `json:"max_bytes,omitempty"`
}

type ProtocolValidationResult struct {
	ModelSource   targetidentity.Identity  `json:"model_source"`
	FixtureSource targetidentity.Identity  `json:"fixture_source"`
	Analysis      protocolinfer.Result     `json:"analysis"`
	Validation    protocolinfer.Validation `json:"validation"`
	Kaitai        string                   `json:"kaitai_candidate,omitempty"`
	Artifacts     []casebook.Artifact      `json:"artifacts,omitempty"`
	Evidence      []casebook.Evidence      `json:"evidence,omitempty"`
	Observation   *casebook.Observation    `json:"observation,omitempty"`
}

func (s *Service) ImportSARIF(request SARIFImportRequest) (SARIFImportResult, error) {
	request.Path = strings.TrimSpace(request.Path)
	request.CaseID = strings.TrimSpace(request.CaseID)
	if request.Path == "" {
		return SARIFImportResult{}, errors.New("SARIF path is required")
	}
	report, err := sourceaudit.ImportSARIF(request.Path, request.MaxBytes, request.MaxResults)
	if err != nil {
		return SARIFImportResult{}, err
	}
	result := SARIFImportResult{Report: report}
	if request.CaseID == "" {
		return result, nil
	}
	if err := s.requireCaseRouteAny(request.CaseID, "source-code-audit", "supply-chain"); err != nil {
		return result, err
	}
	artifact, err := s.cases.AddArtifact(request.CaseID, casebook.ArtifactRequest{
		Kind: "sarif", Identity: report.Source.ID, Source: report.Source.Path,
		SHA256: report.Source.SHA256, Size: report.Source.Size,
	})
	if err != nil {
		return result, err
	}
	result.Artifact = &artifact
	evidence, err := s.cases.AddEvidence(request.CaseID, casebook.EvidenceRequest{
		Summary: fmt.Sprintf("SARIF %s import: candidates=%d rejected=%d", report.Version, len(report.Candidates), report.Rejected),
		Kind:    "sarif", SourcePath: report.Source.Path,
		Notes:        "SARIF results are imported as unverified canonical Findings; tool output does not prove vulnerability applicability.",
		ReproCommand: "ReverseResearch source sarif <file>",
	})
	if err != nil {
		return result, err
	}
	result.Evidence = &evidence
	for _, candidate := range report.Candidates {
		title := strings.TrimSpace(candidate.RuleID)
		if title == "" {
			title = "SARIF candidate"
		}
		location := ""
		affected := ""
		if len(candidate.Locations) > 0 {
			loc := candidate.Locations[0]
			affected = loc.URI
			location = loc.URI
			if loc.StartLine > 0 {
				location = fmt.Sprintf("%s:%d", loc.URI, loc.StartLine)
			}
		}
		var cwe []string
		if strings.HasPrefix(strings.ToUpper(candidate.RuleID), "CWE-") {
			cwe = []string{strings.ToUpper(candidate.RuleID)}
		}
		finding, addErr := s.cases.AddFinding(request.CaseID, casebook.FindingRequest{
			Title: title, Conclusion: candidate.Message,
			Strength: "unverified", Confidence: "tool-candidate",
			CWE: cwe, AffectedAsset: affected, Category: "source-analysis",
			Status: "candidate", Location: location, EvidenceIDs: []string{evidence.ID},
		})
		if addErr != nil {
			return result, addErr
		}
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func (s *Service) ImportSBOM(request SBOMImportRequest) (SBOMImportResult, error) {
	request.Path = strings.TrimSpace(request.Path)
	request.CaseID = strings.TrimSpace(request.CaseID)
	if request.Path == "" {
		return SBOMImportResult{}, errors.New("SBOM path is required")
	}
	report, err := sourceaudit.ImportSBOM(request.Path, request.MaxBytes, request.MaxComponents)
	if err != nil {
		return SBOMImportResult{}, err
	}
	result := SBOMImportResult{Report: report}
	if request.CaseID == "" {
		return result, nil
	}
	if err := s.requireCaseRouteAny(request.CaseID, "source-code-audit", "supply-chain"); err != nil {
		return result, err
	}
	artifact, err := s.cases.AddArtifact(request.CaseID, casebook.ArtifactRequest{
		Kind: "sbom-" + report.Format, Identity: report.Source.ID, Source: report.Source.Path,
		SHA256: report.Source.SHA256, Size: report.Source.Size,
	})
	if err != nil {
		return result, err
	}
	result.Artifact = &artifact
	evidence, err := s.cases.AddEvidence(request.CaseID, casebook.EvidenceRequest{
		Summary: fmt.Sprintf("%s SBOM import: components=%d spec=%s", report.Format, len(report.Components), report.SpecVersion),
		Kind:    "sbom", SourcePath: report.Source.Path,
		Notes:        "SBOM component presence is an inventory observation, not vulnerability applicability.",
		ReproCommand: "ReverseResearch source sbom <file>",
	})
	if err != nil {
		return result, err
	}
	result.Evidence = &evidence
	observation, err := s.cases.AddObservation(request.CaseID, casebook.ObservationRequest{
		Summary:     fmt.Sprintf("Imported %d component(s) from %s SBOM %s; no vulnerability claim was generated.", len(report.Components), report.Format, report.Source.ID),
		EvidenceIDs: []string{evidence.ID},
	})
	if err != nil {
		return result, err
	}
	result.Observation = &observation
	return result, nil
}

func (s *Service) ValidateProtocol(request ProtocolValidationRequest) (ProtocolValidationResult, error) {
	request.ModelSamplesPath = strings.TrimSpace(request.ModelSamplesPath)
	request.FixturesPath = strings.TrimSpace(request.FixturesPath)
	request.CaseID = strings.TrimSpace(request.CaseID)
	request.Name = strings.TrimSpace(request.Name)
	if request.ModelSamplesPath == "" || request.FixturesPath == "" {
		return ProtocolValidationResult{}, errors.New("model_samples_path and fixtures_path are required")
	}
	if request.Name == "" {
		request.Name = "candidate_protocol"
	}
	modelSource, modelSamples, err := readProtocolSampleSet(request.ModelSamplesPath, request.MaxBytes)
	if err != nil {
		return ProtocolValidationResult{}, err
	}
	fixtureSource, fixtures, err := readProtocolSampleSet(request.FixturesPath, request.MaxBytes)
	if err != nil {
		return ProtocolValidationResult{}, err
	}
	analysis, err := protocolinfer.Analyze(modelSamples)
	if err != nil {
		return ProtocolValidationResult{}, err
	}
	validation, err := protocolinfer.ValidateModel(analysis, fixtures)
	if err != nil {
		return ProtocolValidationResult{}, err
	}
	result := ProtocolValidationResult{
		ModelSource: modelSource, FixtureSource: fixtureSource, Analysis: analysis,
		Validation: validation, Kaitai: protocolinfer.KaitaiSkeleton(request.Name, analysis),
	}
	if request.CaseID == "" {
		return result, nil
	}
	if err := s.requireCaseRoute(request.CaseID, "traffic-protocol"); err != nil {
		return result, err
	}
	for _, item := range []struct {
		kind   string
		source targetidentity.Identity
	}{
		{"protocol-model-corpus", modelSource},
		{"protocol-validation-fixtures", fixtureSource},
	} {
		artifact, addErr := s.cases.AddArtifact(request.CaseID, casebook.ArtifactRequest{
			Kind: item.kind, Identity: item.source.ID, Source: item.source.Path,
			SHA256: item.source.SHA256, Size: item.source.Size,
		})
		if addErr != nil {
			return result, addErr
		}
		result.Artifacts = append(result.Artifacts, artifact)
		evidence, addErr := s.cases.AddEvidence(request.CaseID, casebook.EvidenceRequest{
			Summary: item.kind + " " + item.source.ID, Kind: item.kind, SourcePath: item.source.Path,
			ReproCommand: "ReverseResearch protocol validate --model <json> --fixtures <json>",
		})
		if addErr != nil {
			return result, addErr
		}
		result.Evidence = append(result.Evidence, evidence)
	}
	evidenceIDs := make([]string, 0, len(result.Evidence))
	for _, item := range result.Evidence {
		evidenceIDs = append(evidenceIDs, item.ID)
	}
	observation, err := s.cases.AddObservation(request.CaseID, casebook.ObservationRequest{
		Summary: fmt.Sprintf("Protocol candidate independent validation: model=%s fixtures=%s checks=%d validated=%t.",
			analysis.CorpusSHA256, validation.FixtureCorpusSHA256, len(validation.Checks), validation.Validated),
		EvidenceIDs: evidenceIDs,
	})
	if err != nil {
		return result, err
	}
	result.Observation = &observation
	return result, nil
}

func readProtocolSampleSet(path string, maxBytes int64) (targetidentity.Identity, []protocolinfer.Sample, error) {
	if maxBytes <= 0 {
		maxBytes = 32 << 20
	}
	if maxBytes > 128<<20 {
		maxBytes = 128 << 20
	}
	source, err := targetidentity.InspectBounded(path, maxBytes)
	if err != nil {
		return targetidentity.Identity{}, nil, err
	}
	if source.Size > maxBytes {
		return targetidentity.Identity{}, nil, fmt.Errorf("protocol sample file exceeds max_bytes: size=%d max=%d", source.Size, maxBytes)
	}
	body, err := os.ReadFile(source.Path)
	if err != nil {
		return targetidentity.Identity{}, nil, err
	}
	var samples []protocolinfer.Sample
	if err := json.Unmarshal(body, &samples); err != nil {
		return targetidentity.Identity{}, nil, fmt.Errorf("decode protocol sample file %s: %w", filepath.Base(source.Path), err)
	}
	after, err := targetidentity.InspectBounded(source.Path, maxBytes)
	if err != nil {
		return targetidentity.Identity{}, nil, err
	}
	if after.ID != source.ID || after.Size != source.Size || after.ModifiedUTC != source.ModifiedUTC {
		return targetidentity.Identity{}, nil, errors.New("protocol sample file changed during read")
	}
	return source, samples, nil
}
