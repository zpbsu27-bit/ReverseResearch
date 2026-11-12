package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"reverseresearch/internal/casebook"
	"reverseresearch/internal/dfir"
	"reverseresearch/internal/fuzz"
	"reverseresearch/internal/protocolinfer"
	"reverseresearch/internal/sourceaudit"
	"reverseresearch/internal/targetidentity"
)

type DFIRInspectRequest struct {
	Path   string `json:"path"`
	CaseID string `json:"case_id,omitempty"`
}

type DFIRInspectResult struct {
	Artifact     dfir.Artifact         `json:"artifact"`
	CaseArtifact *casebook.Artifact    `json:"case_artifact,omitempty"`
	Evidence     *casebook.Evidence    `json:"evidence,omitempty"`
	Observation  *casebook.Observation `json:"observation,omitempty"`
}

type DFIRTimelineRequest struct {
	Path       string `json:"path"`
	CaseID     string `json:"case_id,omitempty"`
	Format     string `json:"format,omitempty"`
	MaxBytes   int64  `json:"max_bytes,omitempty"`
	MaxEntries int    `json:"max_entries,omitempty"`
}

type DFIRTimelineResult struct {
	Timeline     dfir.Timeline         `json:"timeline"`
	CaseArtifact *casebook.Artifact    `json:"case_artifact,omitempty"`
	Evidence     *casebook.Evidence    `json:"evidence,omitempty"`
	Observation  *casebook.Observation `json:"observation,omitempty"`
}

type FuzzPlanRequest struct {
	CaseID string `json:"case_id,omitempty"`
	fuzz.PlanRequest
}

type FuzzPlanResult struct {
	Plan        fuzz.Plan             `json:"plan"`
	Artifacts   []casebook.Artifact   `json:"artifacts,omitempty"`
	Evidence    []casebook.Evidence   `json:"evidence,omitempty"`
	Observation *casebook.Observation `json:"observation,omitempty"`
}

type CrashRecordRequest struct {
	CaseID    string     `json:"case_id"`
	InputPath string     `json:"input_path"`
	Crash     fuzz.Crash `json:"crash"`
}

type CrashRecordResult struct {
	Crash       fuzz.Crash           `json:"crash"`
	Fingerprint fuzz.Fingerprint     `json:"fingerprint"`
	Artifact    casebook.Artifact    `json:"artifact"`
	Evidence    casebook.Evidence    `json:"evidence"`
	Observation casebook.Observation `json:"observation"`
}

type ProtocolFileRequest struct {
	SamplesPath string `json:"samples_path"`
	CaseID      string `json:"case_id,omitempty"`
	Name        string `json:"name,omitempty"`
	MaxBytes    int64  `json:"max_bytes,omitempty"`
}

type ProtocolFileResult struct {
	Source      targetidentity.Identity `json:"source"`
	Analysis    protocolinfer.Result    `json:"analysis"`
	Kaitai      string                  `json:"kaitai_candidate"`
	Artifact    *casebook.Artifact      `json:"artifact,omitempty"`
	Evidence    *casebook.Evidence      `json:"evidence,omitempty"`
	Observation *casebook.Observation   `json:"observation,omitempty"`
}

type SourceAuditRequest struct {
	Root    string              `json:"root"`
	CaseID  string              `json:"case_id,omitempty"`
	Options sourceaudit.Options `json:"options"`
}

type SourceAuditResult struct {
	Report      sourceaudit.Report    `json:"report"`
	Artifact    *casebook.Artifact    `json:"artifact,omitempty"`
	Evidence    *casebook.Evidence    `json:"evidence,omitempty"`
	Observation *casebook.Observation `json:"observation,omitempty"`
}

func (s *Service) InspectDFIRArtifact(request DFIRInspectRequest) (DFIRInspectResult, error) {
	return s.InspectDFIRArtifactContext(context.Background(), request)
}

func (s *Service) InspectDFIRArtifactContext(ctx context.Context, request DFIRInspectRequest) (DFIRInspectResult, error) {
	request.Path = strings.TrimSpace(request.Path)
	request.CaseID = strings.TrimSpace(request.CaseID)
	if request.Path == "" {
		return DFIRInspectResult{}, errors.New("dfir path is required")
	}
	artifact, err := dfir.InspectContext(ctx, request.Path)
	if err != nil {
		return DFIRInspectResult{}, err
	}
	result := DFIRInspectResult{Artifact: artifact}
	if request.CaseID == "" {
		return result, nil
	}
	if err := s.requireCaseRoute(request.CaseID, "dfir-forensics"); err != nil {
		return result, err
	}
	record, err := s.cases.AddArtifact(request.CaseID, casebook.ArtifactRequest{
		Kind: "dfir-" + string(artifact.Kind), Identity: "sha256:" + artifact.Identity.SHA256,
		Source: artifact.Identity.Path, SHA256: artifact.Identity.SHA256, Size: artifact.Identity.Size,
	})
	if err != nil {
		return result, err
	}
	result.CaseArtifact = &record
	evidence, err := s.cases.AddEvidence(request.CaseID, casebook.EvidenceRequest{
		Summary: "DFIR source artifact identified as " + string(artifact.Kind),
		Kind:    "dfir-source", SourcePath: artifact.Identity.Path,
		Notes:        fmt.Sprintf("parser_status=%s; recommended_tools=%s; read_only=%t", artifact.ParserStatus, strings.Join(artifact.RecommendedTools, ","), artifact.ReadOnly),
		ReproCommand: "ReverseResearch dfir inspect <artifact>",
	})
	if err != nil {
		return result, err
	}
	result.Evidence = &evidence
	observation, err := s.cases.AddObservation(request.CaseID, casebook.ObservationRequest{
		Summary:     fmt.Sprintf("DFIR artifact %s classified as %s; source preserved read-only.", artifact.Identity.SHA256, artifact.Kind),
		EvidenceIDs: []string{evidence.ID},
	})
	if err != nil {
		return result, err
	}
	result.Observation = &observation
	return result, nil
}

func (s *Service) ImportDFIRTimeline(request DFIRTimelineRequest) (DFIRTimelineResult, error) {
	return s.ImportDFIRTimelineContext(context.Background(), request)
}

func (s *Service) ImportDFIRTimelineContext(ctx context.Context, request DFIRTimelineRequest) (DFIRTimelineResult, error) {
	request.Path = strings.TrimSpace(request.Path)
	request.CaseID = strings.TrimSpace(request.CaseID)
	if request.Path == "" {
		return DFIRTimelineResult{}, errors.New("timeline path is required")
	}
	timeline, err := dfir.ImportTimelineJSONLContext(ctx, request.Path, dfir.ImportOptions{
		Format: request.Format, MaxBytes: request.MaxBytes, MaxEntries: request.MaxEntries,
	})
	if err != nil {
		return DFIRTimelineResult{}, err
	}
	result := DFIRTimelineResult{Timeline: timeline}
	if request.CaseID == "" {
		return result, nil
	}
	if err := s.requireCaseRoute(request.CaseID, "dfir-forensics"); err != nil {
		return result, err
	}
	record, err := s.cases.AddArtifact(request.CaseID, casebook.ArtifactRequest{
		Kind: "dfir-timeline-source", Identity: "sha256:" + timeline.Source.Identity.SHA256,
		Source: timeline.Source.Identity.Path, SHA256: timeline.Source.Identity.SHA256, Size: timeline.Source.Identity.Size,
	})
	if err != nil {
		return result, err
	}
	result.CaseArtifact = &record
	evidence, err := s.cases.AddEvidence(request.CaseID, casebook.EvidenceRequest{
		Summary: fmt.Sprintf("Normalized DFIR timeline: entries=%d duplicates=%d rejected=%d", len(timeline.Entries), timeline.Duplicates, timeline.Rejected),
		Kind:    "dfir-timeline", SourcePath: timeline.Source.Identity.Path,
		Notes:        "normalized events retain source artifact SHA and source line; raw source remains authoritative",
		ReproCommand: "ReverseResearch dfir timeline <jsonl> --format " + timeline.Format,
	})
	if err != nil {
		return result, err
	}
	result.Evidence = &evidence
	observation, err := s.cases.AddObservation(request.CaseID, casebook.ObservationRequest{
		Summary:     fmt.Sprintf("DFIR timeline normalized %d entries from immutable source %s; %d duplicate and %d rejected record(s) retained as counts.", len(timeline.Entries), timeline.Source.Identity.SHA256, timeline.Duplicates, timeline.Rejected),
		EvidenceIDs: []string{evidence.ID},
	})
	if err != nil {
		return result, err
	}
	result.Observation = &observation
	return result, nil
}

func (s *Service) BuildFuzzPlan(request FuzzPlanRequest) (FuzzPlanResult, error) {
	return s.BuildFuzzPlanContext(context.Background(), request)
}

func (s *Service) BuildFuzzPlanContext(ctx context.Context, request FuzzPlanRequest) (FuzzPlanResult, error) {
	request.CaseID = strings.TrimSpace(request.CaseID)
	plan, err := fuzz.BuildPlanContext(ctx, request.PlanRequest)
	if err != nil {
		return FuzzPlanResult{}, err
	}
	result := FuzzPlanResult{Plan: plan}
	if request.CaseID == "" {
		return result, nil
	}
	if err := s.requireCaseRouteAny(request.CaseID, "vuln-research", "nday-research"); err != nil {
		return result, err
	}
	for _, spec := range []casebook.ArtifactRequest{
		{Kind: "fuzz-target", Identity: "sha256:" + plan.Target.SHA256, Source: plan.Target.Path, SHA256: plan.Target.SHA256, Size: plan.Target.Size},
		{Kind: "fuzz-harness", Identity: "sha256:" + plan.Harness.SHA256, Source: plan.Harness.Path, SHA256: plan.Harness.SHA256, Size: plan.Harness.Size},
		{Kind: "fuzz-corpus", Identity: "sha256:" + plan.Corpus.SHA256, Source: plan.Corpus.Path, SHA256: plan.Corpus.SHA256, Size: plan.Corpus.TotalBytes},
	} {
		item, addErr := s.cases.AddArtifact(request.CaseID, spec)
		if addErr != nil {
			return result, addErr
		}
		result.Artifacts = append(result.Artifacts, item)
	}
	for _, spec := range []casebook.EvidenceRequest{
		{Summary: "Fuzz target identity", Kind: "fuzz-target", SourcePath: plan.Target.Path, ReproCommand: "ReverseResearch fuzz plan ..."},
		{Summary: "Fuzz harness identity", Kind: "fuzz-harness", SourcePath: plan.Harness.Path, ReproCommand: "ReverseResearch fuzz plan ..."},
	} {
		item, addErr := s.cases.AddEvidence(request.CaseID, spec)
		if addErr != nil {
			return result, addErr
		}
		result.Evidence = append(result.Evidence, item)
	}
	evidenceIDs := make([]string, 0, len(result.Evidence))
	for _, item := range result.Evidence {
		evidenceIDs = append(evidenceIDs, item.ID)
	}
	observation, err := s.cases.AddObservation(request.CaseID, casebook.ObservationRequest{
		Summary:     fmt.Sprintf("Fuzz plan prepared for %s with engine=%s sanitizers=%v corpus_sha256=%s; execution was not started.", plan.Target.SHA256, plan.Engine, plan.Sanitizers, plan.Corpus.SHA256),
		EvidenceIDs: evidenceIDs,
	})
	if err != nil {
		return result, err
	}
	result.Observation = &observation
	return result, nil
}

func (s *Service) RecordCrash(request CrashRecordRequest) (CrashRecordResult, error) {
	return s.RecordCrashContext(context.Background(), request)
}

func (s *Service) RecordCrashContext(ctx context.Context, request CrashRecordRequest) (CrashRecordResult, error) {
	request.CaseID = strings.TrimSpace(request.CaseID)
	request.InputPath = strings.TrimSpace(request.InputPath)
	if request.CaseID == "" || request.InputPath == "" {
		return CrashRecordResult{}, errors.New("case_id and input_path are required")
	}
	if err := s.requireCaseRouteAny(request.CaseID, "vuln-research", "nday-research"); err != nil {
		return CrashRecordResult{}, err
	}
	identity, err := targetidentity.InspectContext(ctx, request.InputPath)
	if err != nil {
		return CrashRecordResult{}, err
	}
	if request.Crash.InputSHA256 != "" && !strings.EqualFold(request.Crash.InputSHA256, identity.SHA256) {
		return CrashRecordResult{}, errors.New("crash input_sha256 does not match current input_path")
	}
	request.Crash.InputSHA256 = identity.SHA256
	fingerprint, err := fuzz.FingerprintCrash(request.Crash)
	if err != nil {
		return CrashRecordResult{}, err
	}
	artifact, err := s.cases.AddArtifact(request.CaseID, casebook.ArtifactRequest{
		Kind: "fuzz-crash-input", Identity: "sha256:" + identity.SHA256,
		Source: identity.Path, SHA256: identity.SHA256, Size: identity.Size,
	})
	if err != nil {
		return CrashRecordResult{}, err
	}
	evidence, err := s.cases.AddEvidence(request.CaseID, casebook.EvidenceRequest{
		Summary: "Crash reproducer " + fingerprint.ID, Kind: "crash-reproducer", SourcePath: identity.Path,
		Notes:        fmt.Sprintf("exception=%s module=%s fault_instruction=%s stack_fingerprint=%s", fingerprint.Exception, fingerprint.Module, fingerprint.FaultInstruction, fingerprint.StackFingerprint),
		ReproCommand: "ReverseResearch crash record --input <path> --crash <json>",
	})
	if err != nil {
		return CrashRecordResult{}, err
	}
	observation, err := s.cases.AddObservation(request.CaseID, casebook.ObservationRequest{
		Summary:     fmt.Sprintf("Crash %s observed for input %s; crash alone does not establish exploitability.", fingerprint.ID, identity.SHA256),
		EvidenceIDs: []string{evidence.ID},
	})
	if err != nil {
		return CrashRecordResult{}, err
	}
	return CrashRecordResult{Crash: request.Crash, Fingerprint: fingerprint, Artifact: artifact, Evidence: evidence, Observation: observation}, nil
}

func (s *Service) FingerprintCrash(crash fuzz.Crash) (fuzz.Fingerprint, error) {
	return fuzz.FingerprintCrash(crash)
}

func (s *Service) DedupeCrashes(crashes []fuzz.Crash) ([]fuzz.Group, error) {
	return fuzz.Dedupe(crashes)
}

func (s *Service) InferProtocolFile(request ProtocolFileRequest) (ProtocolFileResult, error) {
	request.SamplesPath = strings.TrimSpace(request.SamplesPath)
	request.CaseID = strings.TrimSpace(request.CaseID)
	request.Name = strings.TrimSpace(request.Name)
	if request.SamplesPath == "" {
		return ProtocolFileResult{}, errors.New("samples_path is required")
	}
	limit := request.MaxBytes
	if limit <= 0 {
		limit = 32 << 20
	}
	if limit > 128<<20 {
		limit = 128 << 20
	}
	before, err := targetidentity.InspectBounded(request.SamplesPath, limit)
	if err != nil {
		return ProtocolFileResult{}, err
	}
	if before.Size > limit {
		return ProtocolFileResult{}, fmt.Errorf("protocol sample file exceeds max_bytes: size=%d max=%d", before.Size, limit)
	}
	body, err := os.ReadFile(before.Path)
	if err != nil {
		return ProtocolFileResult{}, err
	}
	var samples []protocolinfer.Sample
	if err := json.Unmarshal(body, &samples); err != nil {
		return ProtocolFileResult{}, fmt.Errorf("decode protocol sample file: %w", err)
	}
	analysis, err := protocolinfer.Analyze(samples)
	if err != nil {
		return ProtocolFileResult{}, err
	}
	after, err := targetidentity.InspectBounded(before.Path, limit)
	if err != nil {
		return ProtocolFileResult{}, err
	}
	if before.ID != after.ID || before.Size != after.Size || before.ModifiedUTC != after.ModifiedUTC {
		return ProtocolFileResult{}, errors.New("protocol sample file changed during analysis")
	}
	result := ProtocolFileResult{Source: before, Analysis: analysis, Kaitai: protocolinfer.KaitaiSkeleton(request.Name, analysis)}
	if request.CaseID == "" {
		return result, nil
	}
	if err := s.requireCaseRoute(request.CaseID, "traffic-protocol"); err != nil {
		return result, err
	}
	artifact, err := s.cases.AddArtifact(request.CaseID, casebook.ArtifactRequest{
		Kind: "protocol-corpus", Identity: "sha256:" + before.SHA256, Source: before.Path, SHA256: before.SHA256, Size: before.Size,
	})
	if err != nil {
		return result, err
	}
	result.Artifact = &artifact
	evidence, err := s.cases.AddEvidence(request.CaseID, casebook.EvidenceRequest{
		Summary: fmt.Sprintf("Protocol inference corpus %s: samples=%d inferred_length_candidates=%d checksum_candidates=%d", analysis.CorpusSHA256, analysis.SampleCount, len(analysis.LengthCandidates), len(analysis.ChecksumCandidates)),
		Kind:    "protocol-corpus", SourcePath: before.Path,
		Notes:        "all inferred fields remain candidate until independent fixture/round-trip validation",
		ReproCommand: "ReverseResearch protocol infer --samples <json>",
	})
	if err != nil {
		return result, err
	}
	result.Evidence = &evidence
	observation, err := s.cases.AddObservation(request.CaseID, casebook.ObservationRequest{
		Summary:     fmt.Sprintf("Protocol candidate model generated from corpus %s; result strength=%s and generated schema remains candidate-only.", analysis.CorpusSHA256, analysis.Strength),
		EvidenceIDs: []string{evidence.ID},
	})
	if err != nil {
		return result, err
	}
	result.Observation = &observation
	return result, nil
}

func (s *Service) AuditSource(request SourceAuditRequest) (SourceAuditResult, error) {
	request.Root = strings.TrimSpace(request.Root)
	request.CaseID = strings.TrimSpace(request.CaseID)
	if request.Root == "" {
		return SourceAuditResult{}, errors.New("source audit root is required")
	}
	report, err := sourceaudit.Scan(request.Root, request.Options)
	if err != nil {
		return SourceAuditResult{}, err
	}
	result := SourceAuditResult{Report: report}
	if request.CaseID == "" {
		return result, nil
	}
	if err := s.requireCaseRouteAny(request.CaseID, "source-code-audit", "supply-chain"); err != nil {
		return result, err
	}
	artifact, err := s.cases.AddArtifact(request.CaseID, casebook.ArtifactRequest{
		Kind: "source-repository", Identity: "sha256:" + report.SnapshotSHA256,
		Source: report.Root, SHA256: report.SnapshotSHA256, Size: report.BytesScanned,
	})
	if err != nil {
		return result, err
	}
	result.Artifact = &artifact
	evidence, err := s.cases.AddEvidence(request.CaseID, casebook.EvidenceRequest{
		Summary:      fmt.Sprintf("Bounded source inventory snapshot %s: files=%d manifests=%d dependencies=%d secret_candidates=%d", report.SnapshotSHA256, report.FilesScanned, len(report.Manifests), len(report.Dependencies), len(report.SecretCandidates)),
		Kind:         "source-inventory",
		Notes:        "secret candidates are fingerprinted/redacted; package presence does not establish vulnerability applicability",
		ReproCommand: "ReverseResearch source audit <repository>",
	})
	if err != nil {
		return result, err
	}
	result.Evidence = &evidence
	observation, err := s.cases.AddObservation(request.CaseID, casebook.ObservationRequest{
		Summary:     fmt.Sprintf("Source audit inventory completed for snapshot %s with %d dependency record(s) and %d redacted secret candidate(s).", report.SnapshotSHA256, len(report.Dependencies), len(report.SecretCandidates)),
		EvidenceIDs: []string{evidence.ID},
	})
	if err != nil {
		return result, err
	}
	result.Observation = &observation
	return result, nil
}
