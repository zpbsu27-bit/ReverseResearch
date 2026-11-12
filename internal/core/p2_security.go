package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"reverseresearch/internal/attackgraph"
	"reverseresearch/internal/casebook"
	"reverseresearch/internal/cloudinventory"
	"reverseresearch/internal/cti"
	"reverseresearch/internal/firmwareinspect"
	"reverseresearch/internal/iosinspect"
	"reverseresearch/internal/targetidentity"
)

const defaultAttackGraphMaxBytes int64 = 64 << 20

type AttackGraphImportRequest struct {
	Path     string `json:"path"`
	CaseID   string `json:"case_id,omitempty"`
	From     string `json:"from,omitempty"`
	To       string `json:"to,omitempty"`
	MaxBytes int64  `json:"max_bytes,omitempty"`
	MaxDepth int    `json:"max_depth,omitempty"`
}

type AttackGraphImportResult struct {
	Source      targetidentity.Identity `json:"source"`
	Graph       attackgraph.Graph       `json:"graph"`
	Path        *attackgraph.PathResult `json:"path,omitempty"`
	Artifact    *casebook.Artifact      `json:"artifact,omitempty"`
	Evidence    *casebook.Evidence      `json:"evidence,omitempty"`
	Observation *casebook.Observation   `json:"observation,omitempty"`
	CasePath    *casebook.ResearchPath  `json:"case_path,omitempty"`
}

type CloudInventoryRequest struct {
	Path     string `json:"path"`
	CaseID   string `json:"case_id,omitempty"`
	MaxBytes int64  `json:"max_bytes,omitempty"`
}

type CloudInventoryResult struct {
	Report      cloudinventory.Report `json:"report"`
	Artifact    *casebook.Artifact    `json:"artifact,omitempty"`
	Evidence    *casebook.Evidence    `json:"evidence,omitempty"`
	Observation *casebook.Observation `json:"observation,omitempty"`
}

type STIXImportRequest struct {
	Path       string `json:"path"`
	CaseID     string `json:"case_id,omitempty"`
	MaxBytes   int64  `json:"max_bytes,omitempty"`
	MaxObjects int    `json:"max_objects,omitempty"`
}

type STIXImportResult struct {
	Report      cti.Report            `json:"report"`
	Artifact    *casebook.Artifact    `json:"artifact,omitempty"`
	Evidence    *casebook.Evidence    `json:"evidence,omitempty"`
	Observation *casebook.Observation `json:"observation,omitempty"`
}

type HuntPlanRequest struct {
	CaseID     string   `json:"case_id,omitempty"`
	Hypothesis string   `json:"hypothesis"`
	Techniques []string `json:"techniques,omitempty"`
	Telemetry  []string `json:"telemetry"`
	Adapters   []string `json:"adapters,omitempty"`
}

type HuntPlanResult struct {
	Plan        cti.HuntPlan            `json:"plan"`
	Observation *casebook.Observation   `json:"observation,omitempty"`
	Timeline    *casebook.TimelineEntry `json:"timeline,omitempty"`
}

type IOSInspectRequest struct {
	Path   string `json:"path"`
	CaseID string `json:"case_id,omitempty"`
}

type IOSInspectResult struct {
	Report      iosinspect.Report     `json:"report"`
	Artifact    *casebook.Artifact    `json:"artifact,omitempty"`
	Evidence    *casebook.Evidence    `json:"evidence,omitempty"`
	Observation *casebook.Observation `json:"observation,omitempty"`
}

type FirmwareInspectRequest struct {
	Path   string `json:"path"`
	CaseID string `json:"case_id,omitempty"`
}

type FirmwareInspectResult struct {
	Report      firmwareinspect.Report `json:"report"`
	Artifact    *casebook.Artifact     `json:"artifact,omitempty"`
	Evidence    *casebook.Evidence     `json:"evidence,omitempty"`
	Observation *casebook.Observation  `json:"observation,omitempty"`
}

func (s *Service) ImportAttackGraph(request AttackGraphImportRequest) (AttackGraphImportResult, error) {
	request.Path = strings.TrimSpace(request.Path)
	request.CaseID = strings.TrimSpace(request.CaseID)
	if request.Path == "" {
		return AttackGraphImportResult{}, errors.New("attack graph path is required")
	}
	source, input, err := readAttackGraphInput(request.Path, request.MaxBytes)
	if err != nil {
		return AttackGraphImportResult{}, err
	}
	graph, err := attackgraph.Build(input)
	if err != nil {
		return AttackGraphImportResult{}, err
	}
	result := AttackGraphImportResult{Source: source, Graph: graph}
	from, to := strings.TrimSpace(request.From), strings.TrimSpace(request.To)
	if (from == "") != (to == "") {
		return AttackGraphImportResult{}, errors.New("both from and to are required for path analysis")
	}
	if from != "" {
		path, pathErr := attackgraph.ShortestPath(graph, from, to, request.MaxDepth)
		if pathErr != nil {
			return AttackGraphImportResult{}, pathErr
		}
		result.Path = &path
	}
	if request.CaseID == "" {
		return result, nil
	}
	if err := s.requireCaseRouteAny(request.CaseID,
		"identity-ad", "cloud-security", "container-k8s", "adversary-emulation",
		"network-assessment", "pentest-network"); err != nil {
		return result, err
	}
	artifact, evidence, err := s.persistP2Source(request.CaseID, "attack-graph", source,
		fmt.Sprintf("Attack graph import nodes=%d edges=%d graph_sha256=%s source_kind=%s",
			len(graph.Nodes), len(graph.Edges), graph.SHA256, graph.SourceKind),
		"ReverseResearch attackgraph import <graph.json>")
	if err != nil {
		return result, err
	}
	result.Artifact, result.Evidence = &artifact, &evidence
	observation, err := s.cases.AddObservation(request.CaseID, casebook.ObservationRequest{
		Summary: fmt.Sprintf("Imported attack-path graph %s with %d node(s) and %d edge(s); graph edges remain evidence-backed observations, not execution authorization.",
			graph.SHA256, len(graph.Nodes), len(graph.Edges)),
		EvidenceIDs: []string{evidence.ID},
	})
	if err != nil {
		return result, err
	}
	result.Observation = &observation
	if result.Path != nil && result.Path.Found {
		steps := make([]casebook.PathStep, 0, len(result.Path.Edges))
		for _, edge := range result.Path.Edges {
			steps = append(steps, casebook.PathStep{
				Action:      fmt.Sprintf("%s --%s--> %s", edge.From, edge.Kind, edge.To),
				EvidenceIDs: []string{evidence.ID},
			})
		}
		casePath, pathErr := s.cases.AddPath(request.CaseID, casebook.PathRequest{
			Title:    "Observed attack-path candidate " + from + " -> " + to,
			Details:  "Shortest directed path in the imported graph; this is an analysis path and does not authorize or prove exploitation.",
			PathType: "attack-path-candidate", Start: from, Goal: to, Steps: steps,
		})
		if pathErr != nil {
			return result, pathErr
		}
		result.CasePath = &casePath
	}
	return result, nil
}

func (s *Service) ImportCloudInventory(request CloudInventoryRequest) (CloudInventoryResult, error) {
	request.Path = strings.TrimSpace(request.Path)
	request.CaseID = strings.TrimSpace(request.CaseID)
	if request.Path == "" {
		return CloudInventoryResult{}, errors.New("cloud inventory path is required")
	}
	report, err := cloudinventory.Import(request.Path, request.MaxBytes)
	if err != nil {
		return CloudInventoryResult{}, err
	}
	result := CloudInventoryResult{Report: report}
	if request.CaseID == "" {
		return result, nil
	}
	if err := s.requireCaseRouteAny(request.CaseID, "cloud-security", "container-k8s", "identity-ad"); err != nil {
		return result, err
	}
	artifact, evidence, err := s.persistP2Source(request.CaseID, "cloud-inventory", report.Source,
		fmt.Sprintf("provider=%s scope_id=%s resources=%d graph_sha256=%s read_only=%t",
			report.Provider, report.ScopeID, len(report.Resources), report.Graph.SHA256, report.ReadOnly),
		"ReverseResearch cloud inventory <snapshot.json>")
	if err != nil {
		return result, err
	}
	result.Artifact, result.Evidence = &artifact, &evidence
	observation, err := s.cases.AddObservation(request.CaseID, casebook.ObservationRequest{
		Summary: fmt.Sprintf("Imported read-only %s inventory for scope %s with %d resource(s); no live credentials or cloud actions were used.",
			report.Provider, report.ScopeID, len(report.Resources)),
		EvidenceIDs: []string{evidence.ID},
	})
	if err != nil {
		return result, err
	}
	result.Observation = &observation
	return result, nil
}

func (s *Service) ImportSTIX(request STIXImportRequest) (STIXImportResult, error) {
	request.Path = strings.TrimSpace(request.Path)
	request.CaseID = strings.TrimSpace(request.CaseID)
	if request.Path == "" {
		return STIXImportResult{}, errors.New("STIX path is required")
	}
	report, err := cti.ImportSTIX(request.Path, request.MaxBytes, request.MaxObjects)
	if err != nil {
		return STIXImportResult{}, err
	}
	result := STIXImportResult{Report: report}
	if request.CaseID == "" {
		return result, nil
	}
	if err := s.requireCaseRouteAny(request.CaseID, "cti-analysis", "threat-hunting", "malware-analysis"); err != nil {
		return result, err
	}
	artifact, evidence, err := s.persistP2Source(request.CaseID, "stix-bundle", report.Source,
		fmt.Sprintf("stix_version=%s objects=%d relationships=%d rejected=%d",
			report.STIXVersion, len(report.Objects), len(report.Relationships), report.Rejected),
		"ReverseResearch cti import <bundle.json>")
	if err != nil {
		return result, err
	}
	result.Artifact, result.Evidence = &artifact, &evidence
	observation, err := s.cases.AddObservation(request.CaseID, casebook.ObservationRequest{
		Summary: fmt.Sprintf("Imported STIX %s bundle with %d supported object(s), %d relationship(s), %d rejected object(s).",
			report.STIXVersion, len(report.Objects), len(report.Relationships), report.Rejected),
		EvidenceIDs: []string{evidence.ID},
	})
	if err != nil {
		return result, err
	}
	result.Observation = &observation
	return result, nil
}

func (s *Service) BuildHuntPlan(request HuntPlanRequest) (HuntPlanResult, error) {
	request.CaseID = strings.TrimSpace(request.CaseID)
	plan, err := cti.BuildHuntPlan(request.Hypothesis, request.Techniques, request.Telemetry, request.Adapters)
	if err != nil {
		return HuntPlanResult{}, err
	}
	result := HuntPlanResult{Plan: plan}
	if request.CaseID == "" {
		return result, nil
	}
	if err := s.requireCaseRouteAny(request.CaseID, "threat-hunting", "cti-analysis", "blue-detection"); err != nil {
		return result, err
	}
	observation, err := s.cases.AddObservation(request.CaseID, casebook.ObservationRequest{
		Summary: fmt.Sprintf("Prepared threat-hunt hypothesis %q with telemetry=%s; execution_performed=false.",
			plan.Hypothesis, strings.Join(plan.Telemetry, ",")),
	})
	if err != nil {
		return result, err
	}
	result.Observation = &observation
	timeline, err := s.cases.AddTimeline(request.CaseID, casebook.TimelineRequest{
		Kind: "hunt-plan-prepared",
		Summary: fmt.Sprintf("Threat-hunt plan prepared; techniques=%s adapters=%s execution_performed=false.",
			strings.Join(plan.Techniques, ","), strings.Join(plan.Adapters, ",")),
	})
	if err != nil {
		return result, err
	}
	result.Timeline = &timeline
	return result, nil
}

func (s *Service) InspectIOS(request IOSInspectRequest) (IOSInspectResult, error) {
	return s.InspectIOSContext(context.Background(), request)
}

func (s *Service) InspectIOSContext(ctx context.Context, request IOSInspectRequest) (IOSInspectResult, error) {
	request.Path = strings.TrimSpace(request.Path)
	request.CaseID = strings.TrimSpace(request.CaseID)
	if request.Path == "" {
		return IOSInspectResult{}, errors.New("IPA path is required")
	}
	report, err := iosinspect.InspectIPAContext(ctx, request.Path)
	if err != nil {
		return IOSInspectResult{}, err
	}
	result := IOSInspectResult{Report: report}
	if request.CaseID == "" {
		return result, nil
	}
	if err := s.requireCaseRoute(request.CaseID, "ios"); err != nil {
		return result, err
	}
	artifact, evidence, err := s.persistP2Source(request.CaseID, "ipa", report.Source,
		fmt.Sprintf("app_roots=%d info_plists=%d macho_candidates=%d frameworks=%d read_only=%t",
			len(report.AppRoots), len(report.InfoPlists), len(report.MachO), len(report.Frameworks), report.ReadOnly),
		"ReverseResearch ios inspect <app.ipa>")
	if err != nil {
		return result, err
	}
	result.Artifact, result.Evidence = &artifact, &evidence
	observation, err := s.cases.AddObservation(request.CaseID, casebook.ObservationRequest{
		Summary: fmt.Sprintf("IPA inventory found %d app root(s), %d Mach-O candidate(s) and %d framework entry(s); no extraction, signing, device trust or runtime instrumentation was performed.",
			len(report.AppRoots), len(report.MachO), len(report.Frameworks)),
		EvidenceIDs: []string{evidence.ID},
	})
	if err != nil {
		return result, err
	}
	result.Observation = &observation
	return result, nil
}

func (s *Service) InspectFirmware(request FirmwareInspectRequest) (FirmwareInspectResult, error) {
	return s.InspectFirmwareContext(context.Background(), request)
}

func (s *Service) InspectFirmwareContext(ctx context.Context, request FirmwareInspectRequest) (FirmwareInspectResult, error) {
	request.Path = strings.TrimSpace(request.Path)
	request.CaseID = strings.TrimSpace(request.CaseID)
	if request.Path == "" {
		return FirmwareInspectResult{}, errors.New("firmware path is required")
	}
	report, err := firmwareinspect.InspectContext(ctx, request.Path)
	if err != nil {
		return FirmwareInspectResult{}, err
	}
	result := FirmwareInspectResult{Report: report}
	if request.CaseID == "" {
		return result, nil
	}
	if err := s.requireCaseRoute(request.CaseID, "firmware-iot"); err != nil {
		return result, err
	}
	artifact, evidence, err := s.persistP2Source(request.CaseID, "firmware", report.Source,
		fmt.Sprintf("format=%s recommended_tools=%s read_only=%t",
			report.Format, strings.Join(report.RecommendedTools, ","), report.ReadOnly),
		"ReverseResearch firmware inspect <image>")
	if err != nil {
		return result, err
	}
	result.Artifact, result.Evidence = &artifact, &evidence
	observation, err := s.cases.AddObservation(request.CaseID, casebook.ObservationRequest{
		Summary:     fmt.Sprintf("Firmware image classified as %s; no extraction, emulation, flashing or target mutation was performed.", report.Format),
		EvidenceIDs: []string{evidence.ID},
	})
	if err != nil {
		return result, err
	}
	result.Observation = &observation
	return result, nil
}

func (s *Service) persistP2Source(caseID, kind string, source targetidentity.Identity, notes, repro string) (casebook.Artifact, casebook.Evidence, error) {
	artifact, err := s.cases.AddArtifact(caseID, casebook.ArtifactRequest{
		Kind: kind, Identity: source.ID, Source: source.Path, SHA256: source.SHA256, Size: source.Size,
	})
	if err != nil {
		return casebook.Artifact{}, casebook.Evidence{}, err
	}
	evidence, err := s.cases.AddEvidence(caseID, casebook.EvidenceRequest{
		Summary: kind + " source " + source.ID, Kind: kind, SourcePath: source.Path,
		Notes: notes, ReproCommand: repro,
	})
	return artifact, evidence, err
}

func readAttackGraphInput(path string, maxBytes int64) (targetidentity.Identity, attackgraph.Input, error) {
	if maxBytes <= 0 {
		maxBytes = defaultAttackGraphMaxBytes
	}
	if maxBytes > 256<<20 {
		maxBytes = 256 << 20
	}
	source, err := targetidentity.InspectBounded(path, maxBytes)
	if err != nil {
		return targetidentity.Identity{}, attackgraph.Input{}, err
	}
	if source.Size > maxBytes {
		return targetidentity.Identity{}, attackgraph.Input{}, fmt.Errorf("attack graph exceeds max_bytes: size=%d max=%d", source.Size, maxBytes)
	}
	body, err := os.ReadFile(source.Path)
	if err != nil {
		return targetidentity.Identity{}, attackgraph.Input{}, err
	}
	var input attackgraph.Input
	if err := json.Unmarshal(body, &input); err != nil {
		return targetidentity.Identity{}, attackgraph.Input{}, fmt.Errorf("decode attack graph: %w", err)
	}
	after, err := targetidentity.InspectBounded(source.Path, maxBytes)
	if err != nil {
		return targetidentity.Identity{}, attackgraph.Input{}, err
	}
	if after.ID != source.ID || after.Size != source.Size || after.ModifiedUTC != source.ModifiedUTC {
		return targetidentity.Identity{}, attackgraph.Input{}, errors.New("attack graph changed during import")
	}
	return source, input, nil
}
