package casebook

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"reverseresearch/internal/recordio"
)

type Status string

const (
	StatusOpen   Status = "open"
	StatusClosed Status = "closed"
)

var safeID = regexp.MustCompile(`^[a-z0-9_-]+$`)

type CreateRequest struct {
	Title        string   `json:"title"`
	Route        string   `json:"route,omitempty"`
	EngagementID string   `json:"engagement_id,omitempty"`
	Targets      []Target `json:"targets,omitempty"`
}

type EvidenceRequest struct {
	Summary              string `json:"summary"`
	Kind                 string `json:"kind,omitempty"`
	SourcePath           string `json:"source_path,omitempty"`
	Notes                string `json:"notes,omitempty"`
	ObservedAt           string `json:"observed_at,omitempty"`
	ReproCommand         string `json:"repro_command,omitempty"`
	RawExcerpt           string `json:"raw_excerpt,omitempty"`
	LinkedWorkItemID     string `json:"linked_workitem_id,omitempty"`
	SupersedesEvidenceID string `json:"supersedes_evidence_id,omitempty"`
}

type FindingRequest struct {
	Title             string   `json:"title"`
	Conclusion        string   `json:"conclusion"`
	Strength          string   `json:"strength,omitempty"`
	Confidence        string   `json:"confidence,omitempty"`
	Severity          string   `json:"severity,omitempty"`
	CWE               []string `json:"cwe,omitempty"`
	CAPEC             []string `json:"capec,omitempty"`
	CVE               []string `json:"cve,omitempty"`
	ATTACK            []string `json:"attack,omitempty"`
	AffectedAsset     string   `json:"affected_asset,omitempty"`
	Reproducibility   string   `json:"reproducibility,omitempty"`
	DetectionStatus   string   `json:"detection_status,omitempty"`
	RemediationStatus string   `json:"remediation_status,omitempty"`
	RetestStatus      string   `json:"retest_status,omitempty"`
	Category          string   `json:"category,omitempty"`
	Status            string   `json:"status,omitempty"`
	Location          string   `json:"location,omitempty"`
	Impact            string   `json:"impact,omitempty"`
	ReproSteps        []string `json:"repro_steps,omitempty"`
	Remediation       string   `json:"remediation,omitempty"`
	EvidenceIDs       []string `json:"evidence_ids,omitempty"`
}

type PathRequest struct {
	Title         string     `json:"title"`
	Details       string     `json:"details"`
	PathType      string     `json:"path_type,omitempty"`
	Start         string     `json:"start,omitempty"`
	Goal          string     `json:"goal,omitempty"`
	Steps         []PathStep `json:"steps,omitempty"`
	ResidualRisks []string   `json:"residual_risks,omitempty"`
	FindingIDs    []string   `json:"finding_ids,omitempty"`
}

type Evidence struct {
	ID                   string `json:"id"`
	Summary              string `json:"summary"`
	Kind                 string `json:"kind,omitempty"`
	SourcePath           string `json:"source_path,omitempty"`
	SourceSHA256         string `json:"source_sha256,omitempty"`
	SourceSize           int64  `json:"source_size,omitempty"`
	Notes                string `json:"notes,omitempty"`
	ObservedAt           string `json:"observed_at,omitempty"`
	ReproCommand         string `json:"repro_command,omitempty"`
	RawExcerpt           string `json:"raw_excerpt,omitempty"`
	LinkedWorkItemID     string `json:"linked_workitem_id,omitempty"`
	SupersedesEvidenceID string `json:"supersedes_evidence_id,omitempty"`
	CreatedUTC           string `json:"created_utc"`
}

type Finding struct {
	ID                string   `json:"id"`
	Title             string   `json:"title"`
	Conclusion        string   `json:"conclusion"`
	Strength          string   `json:"strength,omitempty"`
	Confidence        string   `json:"confidence,omitempty"`
	Severity          string   `json:"severity,omitempty"`
	CWE               []string `json:"cwe,omitempty"`
	CAPEC             []string `json:"capec,omitempty"`
	CVE               []string `json:"cve,omitempty"`
	ATTACK            []string `json:"attack,omitempty"`
	AffectedAsset     string   `json:"affected_asset,omitempty"`
	Reproducibility   string   `json:"reproducibility,omitempty"`
	DetectionStatus   string   `json:"detection_status,omitempty"`
	RemediationStatus string   `json:"remediation_status,omitempty"`
	RetestStatus      string   `json:"retest_status,omitempty"`
	Category          string   `json:"category,omitempty"`
	Status            string   `json:"status,omitempty"`
	Location          string   `json:"location,omitempty"`
	Impact            string   `json:"impact,omitempty"`
	ReproSteps        []string `json:"repro_steps,omitempty"`
	Remediation       string   `json:"remediation,omitempty"`
	EvidenceIDs       []string `json:"evidence_ids,omitempty"`
	CreatedUTC        string   `json:"created_utc"`
}

type ResearchPath struct {
	ID            string     `json:"id"`
	Title         string     `json:"title"`
	Details       string     `json:"details"`
	PathType      string     `json:"path_type,omitempty"`
	Start         string     `json:"start,omitempty"`
	Goal          string     `json:"goal,omitempty"`
	Steps         []PathStep `json:"steps,omitempty"`
	ResidualRisks []string   `json:"residual_risks,omitempty"`
	FindingIDs    []string   `json:"finding_ids,omitempty"`
	CreatedUTC    string     `json:"created_utc"`
}

type Case struct {
	SchemaVersion   int              `json:"schema_version,omitempty"`
	ID              string           `json:"id"`
	Title           string           `json:"title"`
	Route           string           `json:"route,omitempty"`
	EngagementID    string           `json:"engagement_id,omitempty"`
	Status          Status           `json:"status"`
	CreatedUTC      string           `json:"created_utc"`
	UpdatedUTC      string           `json:"updated_utc"`
	Targets         []Target         `json:"targets,omitempty"`
	Artifacts       []Artifact       `json:"artifacts,omitempty"`
	Observations    []Observation    `json:"observations,omitempty"`
	Evidence        []Evidence       `json:"evidence,omitempty"`
	Hypotheses      []Hypothesis     `json:"hypotheses,omitempty"`
	Findings        []Finding        `json:"findings,omitempty"`
	Paths           []ResearchPath   `json:"paths,omitempty"`
	Vulnerabilities []Vulnerability  `json:"vulnerabilities,omitempty"`
	IOCs            []IOC            `json:"iocs,omitempty"`
	TTPs            []TTP            `json:"ttps,omitempty"`
	Detections      []Detection      `json:"detections,omitempty"`
	Mitigations     []Mitigation     `json:"mitigations,omitempty"`
	Retests         []Retest         `json:"retests,omitempty"`
	Reports         []Report         `json:"reports,omitempty"`
	Roles           []RoleAssignment `json:"roles,omitempty"`
	WorkItems       []WorkItem       `json:"workitems,omitempty"`
	Timeline        []TimelineEntry  `json:"timeline,omitempty"`
}

type Store struct {
	root string
}

func New(root string) (*Store, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("case store root is required")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve case store root: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(absolute, "cases"), 0o700); err != nil {
		return nil, fmt.Errorf("create case store: %w", err)
	}
	return &Store{root: absolute}, nil
}

func (s *Store) Create(request CreateRequest) (result Case, err error) {
	title := strings.TrimSpace(request.Title)
	if title == "" {
		return Case{}, errors.New("case title is required")
	}
	id, err := newID("case")
	if err != nil {
		return Case{}, err
	}
	release, err := s.lockCase(id)
	if err != nil {
		return Case{}, err
	}
	defer func() { err = errors.Join(err, release()) }()
	if _, err := os.Lstat(s.casePath(id)); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return Case{}, errors.New("case ID collision; existing record was not changed")
		}
		return Case{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	value := Case{
		SchemaVersion: 2,
		ID:            id,
		Title:         title,
		Route:         strings.TrimSpace(request.Route),
		EngagementID:  strings.TrimSpace(request.EngagementID),
		Targets:       normalizeTargets(request.Targets),
		Status:        StatusOpen,
		CreatedUTC:    now,
		UpdatedUTC:    now,
	}
	if err := s.save(value); err != nil {
		return Case{}, err
	}
	return value, nil
}

func (s *Store) Get(id string) (result Case, err error) {
	release, err := s.lockCase(id)
	if err != nil {
		return Case{}, err
	}
	defer func() { err = errors.Join(err, release()) }()
	return s.get(id)
}

// get requires the caller to hold the stable per-case lock.
func (s *Store) get(id string) (Case, error) {
	value, _, err := s.read(id)
	return value, err
}

// read binds decoding and revision calculation to the same bytes. The caller
// holds the stable case lock; symbolic-link records are not accepted.
func (s *Store) read(id string) (Case, []byte, error) {
	if err := validateID(id); err != nil {
		return Case{}, nil, err
	}
	info, err := os.Lstat(s.casePath(id))
	if err != nil {
		return Case{}, nil, fmt.Errorf("stat case %s: %w", id, err)
	}
	if !info.Mode().IsRegular() {
		return Case{}, nil, errors.New("case record must be a regular file")
	}
	body, err := recordio.ReadFileLimit(s.casePath(id), MaxCaseRecordBytes)
	if err != nil {
		return Case{}, nil, fmt.Errorf("read case %s: %w", id, err)
	}
	var value Case
	if err := json.Unmarshal(body, &value); err != nil {
		return Case{}, nil, fmt.Errorf("decode case %s: %w", id, err)
	}
	if value.ID != id {
		return Case{}, nil, errors.New("case identity mismatch")
	}
	return value, body, nil
}

func (s *Store) AddEvidence(caseID string, request EvidenceRequest) (result Evidence, err error) {
	if err := validateID(caseID); err != nil {
		return Evidence{}, err
	}
	summary := strings.TrimSpace(request.Summary)
	if summary == "" {
		return Evidence{}, errors.New("evidence summary is required")
	}
	id, err := newID("e")
	if err != nil {
		return Evidence{}, err
	}
	evidence := Evidence{
		ID: id, Summary: summary, Kind: strings.TrimSpace(request.Kind), Notes: strings.TrimSpace(request.Notes),
		ObservedAt: strings.TrimSpace(request.ObservedAt), ReproCommand: strings.TrimSpace(request.ReproCommand),
		RawExcerpt: strings.TrimSpace(request.RawExcerpt), LinkedWorkItemID: strings.TrimSpace(request.LinkedWorkItemID),
		SupersedesEvidenceID: strings.TrimSpace(request.SupersedesEvidenceID),
		CreatedUTC:           time.Now().UTC().Format(time.RFC3339Nano),
	}
	if strings.TrimSpace(request.SourcePath) != "" {
		absolute, err := filepath.Abs(request.SourcePath)
		if err != nil {
			return Evidence{}, fmt.Errorf("resolve evidence source: %w", err)
		}
		hash, size, err := fingerprintSource(absolute)
		if err != nil {
			return Evidence{}, err
		}
		evidence.SourcePath = filepath.Clean(absolute)
		evidence.SourceSHA256 = hash
		evidence.SourceSize = size
	}
	// Hashing a large source must not block unrelated updates to this case.
	// Only the read-modify-publish transaction holds the stable case lock.
	release, err := s.lockCase(caseID)
	if err != nil {
		return Evidence{}, err
	}
	defer func() { err = errors.Join(err, release()) }()
	value, err := s.get(caseID)
	if err != nil {
		return Evidence{}, err
	}
	if evidence.LinkedWorkItemID != "" && !workItemExists(value, evidence.LinkedWorkItemID) {
		return Evidence{}, fmt.Errorf("unknown workitem id %q", evidence.LinkedWorkItemID)
	}
	if evidence.SupersedesEvidenceID != "" && !evidenceExists(value, evidence.SupersedesEvidenceID) {
		return Evidence{}, fmt.Errorf("unknown superseded evidence id %q", evidence.SupersedesEvidenceID)
	}
	value.SchemaVersion = 2
	value.Evidence = append(value.Evidence, evidence)
	value.UpdatedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	if err := s.save(value); err != nil {
		return Evidence{}, err
	}
	return evidence, nil
}

func (s *Store) AddFinding(caseID string, request FindingRequest) (result Finding, err error) {
	release, err := s.lockCase(caseID)
	if err != nil {
		return Finding{}, err
	}
	defer func() { err = errors.Join(err, release()) }()
	value, err := s.get(caseID)
	if err != nil {
		return Finding{}, err
	}
	title := strings.TrimSpace(request.Title)
	conclusion := strings.TrimSpace(request.Conclusion)
	if title == "" || conclusion == "" {
		return Finding{}, errors.New("finding title and conclusion are required")
	}
	strength, err := normalizeFindingStrength(request.Strength)
	if err != nil {
		return Finding{}, err
	}
	known := make(map[string]struct{}, len(value.Evidence))
	for _, evidence := range value.Evidence {
		known[evidence.ID] = struct{}{}
	}
	for _, id := range request.EvidenceIDs {
		if _, ok := known[id]; !ok {
			return Finding{}, fmt.Errorf("unknown evidence id %q", id)
		}
	}
	id, err := newID("f")
	if err != nil {
		return Finding{}, err
	}
	finding := Finding{
		ID: id, Title: title, Conclusion: conclusion, Strength: strength,
		Confidence: strings.TrimSpace(request.Confidence), Severity: strings.TrimSpace(request.Severity),
		CWE: cleanStrings(request.CWE), CAPEC: cleanStrings(request.CAPEC), CVE: cleanStrings(request.CVE), ATTACK: cleanStrings(request.ATTACK),
		AffectedAsset: strings.TrimSpace(request.AffectedAsset), Reproducibility: strings.TrimSpace(request.Reproducibility),
		DetectionStatus: strings.TrimSpace(request.DetectionStatus), RemediationStatus: strings.TrimSpace(request.RemediationStatus),
		RetestStatus: strings.TrimSpace(request.RetestStatus), Category: strings.TrimSpace(request.Category),
		Status: strings.TrimSpace(request.Status), Location: strings.TrimSpace(request.Location), Impact: strings.TrimSpace(request.Impact),
		ReproSteps: cleanStrings(request.ReproSteps), Remediation: strings.TrimSpace(request.Remediation),
		EvidenceIDs: cleanStrings(request.EvidenceIDs),
		CreatedUTC:  time.Now().UTC().Format(time.RFC3339Nano),
	}
	if finding.Status == "validated" {
		if len(finding.EvidenceIDs) == 0 {
			return Finding{}, errors.New("validated finding requires evidence_ids")
		}
		if strings.EqualFold(finding.Confidence, "low") {
			return Finding{}, errors.New("validated finding cannot use low confidence")
		}
	}
	value.SchemaVersion = 2
	value.Findings = append(value.Findings, finding)
	value.UpdatedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	if err := s.save(value); err != nil {
		return Finding{}, err
	}
	return finding, nil
}

func (s *Store) AddPath(caseID string, request PathRequest) (result ResearchPath, err error) {
	release, err := s.lockCase(caseID)
	if err != nil {
		return ResearchPath{}, err
	}
	defer func() { err = errors.Join(err, release()) }()
	value, err := s.get(caseID)
	if err != nil {
		return ResearchPath{}, err
	}
	title := strings.TrimSpace(request.Title)
	details := strings.TrimSpace(request.Details)
	if title == "" || details == "" {
		return ResearchPath{}, errors.New("path title and details are required")
	}
	known := make(map[string]struct{}, len(value.Findings))
	for _, finding := range value.Findings {
		known[finding.ID] = struct{}{}
	}
	for _, id := range request.FindingIDs {
		if _, ok := known[id]; !ok {
			return ResearchPath{}, fmt.Errorf("unknown finding id %q", id)
		}
	}
	id, err := newID("p")
	if err != nil {
		return ResearchPath{}, err
	}
	if err := validatePathSteps(value, request.Steps); err != nil {
		return ResearchPath{}, err
	}
	path := ResearchPath{
		ID: id, Title: title, Details: details, PathType: strings.TrimSpace(request.PathType),
		Start: strings.TrimSpace(request.Start), Goal: strings.TrimSpace(request.Goal), Steps: normalizePathSteps(request.Steps),
		ResidualRisks: cleanStrings(request.ResidualRisks), FindingIDs: cleanStrings(request.FindingIDs),
		CreatedUTC: time.Now().UTC().Format(time.RFC3339Nano),
	}
	value.SchemaVersion = 2
	value.Paths = append(value.Paths, path)
	value.UpdatedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	if err := s.save(value); err != nil {
		return ResearchPath{}, err
	}
	return path, nil
}

func (s *Store) lockCase(id string) (func() error, error) {
	if err := validateID(id); err != nil {
		return nil, err
	}
	return recordio.Acquire(filepath.Join(s.root, "cases", "."+id+".lock"), 10*time.Second)
}

func (s *Store) casePath(id string) string {
	return filepath.Join(s.root, "cases", id+".json")
}

func (s *Store) save(value Case) error {
	if err := validateID(value.ID); err != nil {
		return err
	}
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode case: %w", err)
	}
	body = append(body, '\n')
	if len(body) > MaxCaseRecordBytes {
		return fmt.Errorf("case record exceeds durable size limit: %d > %d", len(body), MaxCaseRecordBytes)
	}
	if err := s.markCaseIndexDirty(value); err != nil {
		return err
	}
	if err := recordio.WriteFile(s.casePath(value.ID), body, 0o600); err != nil {
		return errors.Join(err, s.clearCaseIndexDirty(value.ID, value.UpdatedUTC))
	}
	if err := s.updateCaseIndex(value); err != nil {
		// The recent index is only an acceleration cache. Never turn a committed
		// Case mutation into an ambiguous failure because cache maintenance failed.
		// Keep the revision-owned dirty marker. The next bounded List rebuilds
		// from canonical Case records while the index lock protects replacement;
		// deleting the shared cache here (outside that lock) could erase another
		// process's freshly published index.
		return nil
	}
	return nil
}

func normalizeFindingStrength(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "unverified", nil
	}
	switch value {
	case "observed", "inferred", "unverified":
		return value, nil
	default:
		return "", fmt.Errorf("finding strength %q is invalid; expected observed, inferred, or unverified", value)
	}
}

func validateID(id string) error {
	if len(id) > 128 || !safeID.MatchString(id) || strings.Contains(id, "..") {
		return fmt.Errorf("invalid case object id %q", id)
	}
	return nil
}

func newID(prefix string) (string, error) {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate id: %w", err)
	}
	return prefix + "_" + hex.EncodeToString(raw[:]), nil
}
