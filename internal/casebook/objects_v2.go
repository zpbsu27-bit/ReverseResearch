package casebook

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

type ArtifactRequest struct {
	Kind     string `json:"kind"`
	Identity string `json:"identity"`
	Source   string `json:"source,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
	Size     int64  `json:"size,omitempty"`
}

type ObservationRequest struct {
	Summary     string   `json:"summary"`
	EvidenceIDs []string `json:"evidence_ids,omitempty"`
}

type VulnerabilityRequest struct {
	Title       string   `json:"title"`
	CWE         []string `json:"cwe,omitempty"`
	CAPEC       []string `json:"capec,omitempty"`
	CVE         []string `json:"cve,omitempty"`
	FindingIDs  []string `json:"finding_ids,omitempty"`
	EvidenceIDs []string `json:"evidence_ids,omitempty"`
}

type IOCRequest struct {
	Type     string `json:"type"`
	Value    string `json:"value"`
	SourceID string `json:"source_id,omitempty"`
}

type TTPRequest struct {
	Technique  string   `json:"technique"`
	Tactic     string   `json:"tactic,omitempty"`
	FindingIDs []string `json:"finding_ids,omitempty"`
}

type MitigationRequest struct {
	Summary     string   `json:"summary"`
	Technique   string   `json:"technique,omitempty"`
	FindingIDs  []string `json:"finding_ids,omitempty"`
	EvidenceIDs []string `json:"evidence_ids,omitempty"`
}

type ReportRequest struct {
	Kind               string   `json:"kind"`
	Format             string   `json:"format"`
	Revision           string   `json:"revision"`
	Profile            string   `json:"profile,omitempty"`
	Classification     string   `json:"classification,omitempty"`
	Status             string   `json:"status,omitempty"`
	Summary            string   `json:"summary,omitempty"`
	ArtifactID         string   `json:"artifact_id,omitempty"`
	FindingIDs         []string `json:"finding_ids,omitempty"`
	EvidenceIDs        []string `json:"evidence_ids,omitempty"`
	Sections           []string `json:"sections,omitempty"`
	SupersedesReportID string   `json:"supersedes_report_id,omitempty"`
}

func (s *Store) AddArtifact(caseID string, request ArtifactRequest) (result Artifact, err error) {
	release, err := s.lockCase(caseID)
	if err != nil {
		return Artifact{}, err
	}
	defer func() { err = errors.Join(err, release()) }()
	value, err := s.get(caseID)
	if err != nil {
		return Artifact{}, err
	}
	request.Kind = strings.TrimSpace(request.Kind)
	request.Identity = strings.TrimSpace(request.Identity)
	request.Source = strings.TrimSpace(request.Source)
	request.SHA256 = strings.ToLower(strings.TrimSpace(request.SHA256))
	if request.Kind == "" || request.Identity == "" {
		return Artifact{}, errors.New("artifact kind and identity are required")
	}
	if request.Size < 0 {
		return Artifact{}, errors.New("artifact size must not be negative")
	}
	if request.SHA256 != "" {
		digest, decodeErr := hex.DecodeString(request.SHA256)
		if decodeErr != nil || len(digest) != 32 {
			return Artifact{}, errors.New("artifact sha256 must be exactly 64 hexadecimal characters")
		}
	}
	id, err := newID("a")
	if err != nil {
		return Artifact{}, err
	}
	item := Artifact{
		ID: id, Kind: request.Kind, Identity: request.Identity, Source: request.Source,
		SHA256: request.SHA256, Size: request.Size, CreatedUTC: time.Now().UTC().Format(time.RFC3339Nano),
	}
	value.SchemaVersion = 2
	value.Artifacts = append(value.Artifacts, item)
	value.UpdatedUTC = item.CreatedUTC
	if err := s.save(value); err != nil {
		return Artifact{}, err
	}
	return item, nil
}

func (s *Store) AddObservation(caseID string, request ObservationRequest) (result Observation, err error) {
	release, err := s.lockCase(caseID)
	if err != nil {
		return Observation{}, err
	}
	defer func() { err = errors.Join(err, release()) }()
	value, err := s.get(caseID)
	if err != nil {
		return Observation{}, err
	}
	request.Summary = strings.TrimSpace(request.Summary)
	if request.Summary == "" {
		return Observation{}, errors.New("observation summary is required")
	}
	if err := validateEvidenceIDs(value, request.EvidenceIDs); err != nil {
		return Observation{}, err
	}
	id, err := newID("o")
	if err != nil {
		return Observation{}, err
	}
	item := Observation{
		ID: id, Summary: request.Summary, EvidenceIDs: cleanStrings(request.EvidenceIDs),
		CreatedUTC: time.Now().UTC().Format(time.RFC3339Nano),
	}
	value.SchemaVersion = 2
	value.Observations = append(value.Observations, item)
	value.UpdatedUTC = item.CreatedUTC
	if err := s.save(value); err != nil {
		return Observation{}, err
	}
	return item, nil
}

func (s *Store) AddVulnerability(caseID string, request VulnerabilityRequest) (result Vulnerability, err error) {
	release, err := s.lockCase(caseID)
	if err != nil {
		return Vulnerability{}, err
	}
	defer func() { err = errors.Join(err, release()) }()
	value, err := s.get(caseID)
	if err != nil {
		return Vulnerability{}, err
	}
	request.Title = strings.TrimSpace(request.Title)
	if request.Title == "" {
		return Vulnerability{}, errors.New("vulnerability title is required")
	}
	if err := validateFindingIDs(value, request.FindingIDs); err != nil {
		return Vulnerability{}, err
	}
	if err := validateEvidenceIDs(value, request.EvidenceIDs); err != nil {
		return Vulnerability{}, err
	}
	id, err := newID("v")
	if err != nil {
		return Vulnerability{}, err
	}
	item := Vulnerability{
		ID: id, Title: request.Title, CWE: cleanStrings(request.CWE), CAPEC: cleanStrings(request.CAPEC),
		CVE: cleanStrings(request.CVE), FindingIDs: cleanStrings(request.FindingIDs), EvidenceIDs: cleanStrings(request.EvidenceIDs),
	}
	value.SchemaVersion = 2
	value.Vulnerabilities = append(value.Vulnerabilities, item)
	value.UpdatedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	if err := s.save(value); err != nil {
		return Vulnerability{}, err
	}
	return item, nil
}

func (s *Store) AddIOC(caseID string, request IOCRequest) (result IOC, err error) {
	release, err := s.lockCase(caseID)
	if err != nil {
		return IOC{}, err
	}
	defer func() { err = errors.Join(err, release()) }()
	value, err := s.get(caseID)
	if err != nil {
		return IOC{}, err
	}
	request.Type = strings.TrimSpace(request.Type)
	request.Value = strings.TrimSpace(request.Value)
	request.SourceID = strings.TrimSpace(request.SourceID)
	if request.Type == "" || request.Value == "" {
		return IOC{}, errors.New("ioc type and value are required")
	}
	if request.SourceID != "" && !caseHasSourceObject(value, request.SourceID) {
		return IOC{}, fmt.Errorf("unknown IOC source id %q", request.SourceID)
	}
	id, err := newID("ioc")
	if err != nil {
		return IOC{}, err
	}
	item := IOC{ID: id, Type: request.Type, Value: request.Value, SourceID: request.SourceID}
	value.SchemaVersion = 2
	value.IOCs = append(value.IOCs, item)
	value.UpdatedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	if err := s.save(value); err != nil {
		return IOC{}, err
	}
	return item, nil
}

func (s *Store) AddTTP(caseID string, request TTPRequest) (result TTP, err error) {
	release, err := s.lockCase(caseID)
	if err != nil {
		return TTP{}, err
	}
	defer func() { err = errors.Join(err, release()) }()
	value, err := s.get(caseID)
	if err != nil {
		return TTP{}, err
	}
	request.Technique = strings.TrimSpace(request.Technique)
	request.Tactic = strings.TrimSpace(request.Tactic)
	if request.Technique == "" {
		return TTP{}, errors.New("ttp technique is required")
	}
	if err := validateFindingIDs(value, request.FindingIDs); err != nil {
		return TTP{}, err
	}
	id, err := newID("ttp")
	if err != nil {
		return TTP{}, err
	}
	item := TTP{ID: id, Technique: request.Technique, Tactic: request.Tactic, FindingIDs: cleanStrings(request.FindingIDs)}
	value.SchemaVersion = 2
	value.TTPs = append(value.TTPs, item)
	value.UpdatedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	if err := s.save(value); err != nil {
		return TTP{}, err
	}
	return item, nil
}

func (s *Store) AddMitigation(caseID string, request MitigationRequest) (result Mitigation, err error) {
	release, err := s.lockCase(caseID)
	if err != nil {
		return Mitigation{}, err
	}
	defer func() { err = errors.Join(err, release()) }()
	value, err := s.get(caseID)
	if err != nil {
		return Mitigation{}, err
	}
	request.Summary = strings.TrimSpace(request.Summary)
	request.Technique = strings.TrimSpace(request.Technique)
	if request.Summary == "" {
		return Mitigation{}, errors.New("mitigation summary is required")
	}
	if err := validateFindingIDs(value, request.FindingIDs); err != nil {
		return Mitigation{}, err
	}
	if err := validateEvidenceIDs(value, request.EvidenceIDs); err != nil {
		return Mitigation{}, err
	}
	id, err := newID("m")
	if err != nil {
		return Mitigation{}, err
	}
	item := Mitigation{
		ID: id, Summary: request.Summary, Technique: request.Technique,
		FindingIDs: cleanStrings(request.FindingIDs), EvidenceIDs: cleanStrings(request.EvidenceIDs),
	}
	value.SchemaVersion = 2
	value.Mitigations = append(value.Mitigations, item)
	value.UpdatedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	if err := s.save(value); err != nil {
		return Mitigation{}, err
	}
	return item, nil
}

func (s *Store) AddReport(caseID string, request ReportRequest) (result Report, err error) {
	request.Kind = strings.TrimSpace(request.Kind)
	request.Format = strings.ToLower(strings.TrimSpace(request.Format))
	request.Revision = strings.TrimSpace(request.Revision)
	request.Profile = strings.TrimSpace(request.Profile)
	request.Classification = strings.TrimSpace(request.Classification)
	request.Status = strings.ToLower(strings.TrimSpace(request.Status))
	request.Summary = strings.TrimSpace(request.Summary)
	request.ArtifactID = strings.TrimSpace(request.ArtifactID)
	request.FindingIDs = cleanStrings(request.FindingIDs)
	request.EvidenceIDs = cleanStrings(request.EvidenceIDs)
	request.Sections = cleanStrings(request.Sections)
	request.SupersedesReportID = strings.TrimSpace(request.SupersedesReportID)
	if request.Status == "" {
		request.Status = "draft"
	}
	if request.Kind == "" || request.Format == "" || request.Revision == "" {
		return Report{}, errors.New("report kind, format, and revision are required")
	}
	switch request.Status {
	case "draft", "final":
	default:
		return Report{}, fmt.Errorf("invalid report status %q", request.Status)
	}
	var reviewedRevision string
	if request.Status == "final" {
		review, reviewErr := s.Review(caseID)
		if reviewErr != nil {
			return Report{}, reviewErr
		}
		if !review.Ready {
			return Report{}, fmt.Errorf("final report requires a ready Case review with %d issue(s)", len(review.Issues))
		}
		reviewedRevision = review.CaseSHA256
		if request.Profile == "" || request.Classification == "" || len(request.Sections) == 0 {
			return Report{}, errors.New("final report requires profile, classification, and sections")
		}
		if len(request.FindingIDs) == 0 && len(request.EvidenceIDs) == 0 {
			return Report{}, errors.New("final report requires finding_ids or evidence_ids")
		}
	}

	release, err := s.lockCase(caseID)
	if err != nil {
		return Report{}, err
	}
	defer func() { err = errors.Join(err, release()) }()
	value, body, err := s.read(caseID)
	if err != nil {
		return Report{}, err
	}
	digest := sha256.Sum256(body)
	caseRevision := hex.EncodeToString(digest[:])
	if reviewedRevision != "" && reviewedRevision != caseRevision {
		return Report{}, errors.New("case changed after strict review; rerun review before final report")
	}
	if request.ArtifactID != "" && !artifactExists(value, request.ArtifactID) {
		return Report{}, fmt.Errorf("unknown report artifact id %q", request.ArtifactID)
	}
	if err := validateFindingIDs(value, request.FindingIDs); err != nil {
		return Report{}, err
	}
	if err := validateEvidenceIDs(value, request.EvidenceIDs); err != nil {
		return Report{}, err
	}
	if request.SupersedesReportID != "" && !reportExists(value, request.SupersedesReportID) {
		return Report{}, fmt.Errorf("unknown superseded report id %q", request.SupersedesReportID)
	}
	id, err := newID("report")
	if err != nil {
		return Report{}, err
	}
	item := Report{
		ID: id, SchemaVersion: 1, Kind: request.Kind, Format: request.Format, Revision: request.Revision,
		Profile: request.Profile, Classification: request.Classification, Status: request.Status, Summary: request.Summary,
		ArtifactID: request.ArtifactID, FindingIDs: request.FindingIDs, EvidenceIDs: request.EvidenceIDs,
		Sections: request.Sections, SupersedesReportID: request.SupersedesReportID, CaseSHA256: caseRevision,
		CreatedUTC: time.Now().UTC().Format(time.RFC3339Nano),
	}
	value.SchemaVersion = 2
	value.Reports = append(value.Reports, item)
	value.UpdatedUTC = item.CreatedUTC
	if err := s.save(value); err != nil {
		return Report{}, err
	}
	return item, nil
}

func validateFindingIDs(value Case, ids []string) error {
	for _, id := range cleanStrings(ids) {
		if !findingExists(value, id) {
			return fmt.Errorf("unknown finding id %q", id)
		}
	}
	return nil
}

func artifactExists(value Case, id string) bool {
	for _, item := range value.Artifacts {
		if item.ID == id {
			return true
		}
	}
	return false
}

func caseHasSourceObject(value Case, id string) bool {
	if evidenceExists(value, id) || findingExists(value, id) || artifactExists(value, id) {
		return true
	}
	for _, item := range value.Observations {
		if item.ID == id {
			return true
		}
	}
	return false
}

func reportExists(value Case, id string) bool {
	for _, item := range value.Reports {
		if item.ID == id {
			return true
		}
	}
	return false
}
