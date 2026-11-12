package core

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"reverseresearch/internal/casebook"
	"reverseresearch/internal/collaboration"
	"reverseresearch/internal/dashboard"
	"reverseresearch/internal/packregistry"
	"reverseresearch/internal/rbac"
	"reverseresearch/internal/recordio"
	"reverseresearch/internal/remoteagent"
	"reverseresearch/internal/reporting"
	"reverseresearch/internal/targetidentity"
	"reverseresearch/internal/toolindex"
)

type ReportRenderRequest struct {
	CaseID               string   `json:"case_id"`
	Profile              string   `json:"profile"`
	Classification       string   `json:"classification,omitempty"`
	Format               string   `json:"format"`
	Status               string   `json:"status,omitempty"`
	Sections             []string `json:"sections,omitempty"`
	OutputPath           string   `json:"output_path,omitempty"`
	ExpectedOutputSHA256 string   `json:"expected_output_sha256,omitempty"`
}
type ReportRenderResult struct {
	Document      reporting.Document       `json:"document"`
	Format        string                   `json:"format"`
	ContentSHA256 string                   `json:"content_sha256"`
	Bytes         int                      `json:"bytes"`
	Output        *targetidentity.Identity `json:"output,omitempty"`
}
type DashboardRenderRequest struct {
	CaseID               string `json:"case_id"`
	Profile              string `json:"profile,omitempty"`
	Classification       string `json:"classification,omitempty"`
	Actor                string `json:"actor,omitempty"`
	OutputPath           string `json:"output_path"`
	ExpectedOutputSHA256 string `json:"expected_output_sha256,omitempty"`
}
type DashboardRenderResult struct {
	Document      reporting.Document       `json:"document"`
	ContentSHA256 string                   `json:"content_sha256"`
	Bytes         int                      `json:"bytes"`
	Output        targetidentity.Identity  `json:"output"`
	Collaboration *collaboration.Workspace `json:"collaboration,omitempty"`
}
type CollaborationInitRequest struct {
	CaseID string `json:"case_id"`
	Owner  string `json:"owner"`
}
type CollaborationParticipantRequest struct {
	CaseID           string `json:"case_id"`
	ExpectedRevision string `json:"expected_revision"`
	Actor            string `json:"actor"`
	Subject          string `json:"subject"`
	Role             string `json:"role"`
}
type FindingOwnerRequest struct {
	CaseID           string `json:"case_id"`
	ExpectedRevision string `json:"expected_revision"`
	Actor            string `json:"actor"`
	FindingID        string `json:"finding_id"`
	Owner            string `json:"owner"`
}
type CollaborationTaskRequest struct {
	CaseID           string `json:"case_id"`
	ExpectedRevision string `json:"expected_revision"`
	Actor            string `json:"actor"`
	Title            string `json:"title"`
	Owner            string `json:"owner,omitempty"`
}
type CollaborationTaskUpdateRequest struct {
	CaseID           string `json:"case_id"`
	ExpectedRevision string `json:"expected_revision"`
	Actor            string `json:"actor"`
	TaskID           string `json:"task_id"`
	Status           string `json:"status"`
}
type CollaborationCommentRequest struct {
	CaseID           string `json:"case_id"`
	ExpectedRevision string `json:"expected_revision"`
	Actor            string `json:"actor"`
	Body             string `json:"body"`
	ObjectType       string `json:"object_type,omitempty"`
	ObjectID         string `json:"object_id,omitempty"`
}
type CollaborationApprovalRequest struct {
	CaseID           string `json:"case_id"`
	ExpectedRevision string `json:"expected_revision"`
	Actor            string `json:"actor"`
	Kind             string `json:"kind"`
	SubjectID        string `json:"subject_id"`
	Decision         string `json:"decision"`
	Notes            string `json:"notes,omitempty"`
}
type EvidenceLockRequest struct {
	CaseID           string `json:"case_id"`
	ExpectedRevision string `json:"expected_revision"`
	Actor            string `json:"actor"`
	EvidenceID       string `json:"evidence_id"`
	Reason           string `json:"reason,omitempty"`
}
type RemoteAgentRegisterRequest struct {
	ManifestPath     string `json:"manifest_path"`
	ExpectedRevision string `json:"expected_revision,omitempty"`
	AuthorityRole    string `json:"authority_role"`
}
type RemoteAgentRegisterResult struct {
	Source       targetidentity.Identity  `json:"source"`
	Registration remoteagent.Registration `json:"registration"`
}
type RemoteJobValidationRequest struct {
	AgentID string `json:"agent_id"`
	JobPath string `json:"job_path"`
}
type RemoteJobValidationResult struct {
	Source             targetidentity.Identity  `json:"source"`
	Agent              remoteagent.Registration `json:"agent"`
	Job                remoteagent.JobRequest   `json:"job"`
	Valid              bool                     `json:"valid"`
	ExecutionPerformed bool                     `json:"execution_performed"`
}
type RemoteResultVerificationRequest struct {
	AgentID    string `json:"agent_id"`
	ResultPath string `json:"result_path"`
}
type RemoteResultVerificationResult struct {
	Source   targetidentity.Identity    `json:"source"`
	Result   remoteagent.ResultEnvelope `json:"result"`
	Verified bool                       `json:"verified"`
}
type PackVerificationRequest struct {
	Root         string `json:"root"`
	ManifestPath string `json:"manifest_path"`
	TrustPath    string `json:"trust_path"`
}
type PackVerificationResult struct {
	ManifestSource targetidentity.Identity   `json:"manifest_source"`
	TrustSource    targetidentity.Identity   `json:"trust_source"`
	Verification   packregistry.Verification `json:"verification"`
}

func (s *Service) RenderCaseReport(request ReportRenderRequest) (ReportRenderResult, error) {
	request.CaseID = strings.TrimSpace(request.CaseID)
	request.Profile = strings.TrimSpace(request.Profile)
	request.Classification = strings.TrimSpace(request.Classification)
	request.Format = strings.ToLower(strings.TrimSpace(request.Format))
	request.Status = strings.ToLower(strings.TrimSpace(request.Status))
	request.OutputPath = strings.TrimSpace(request.OutputPath)
	request.ExpectedOutputSHA256 = strings.ToLower(strings.TrimSpace(request.ExpectedOutputSHA256))
	if request.CaseID == "" || request.Profile == "" || request.Format == "" {
		return ReportRenderResult{}, errors.New("case_id, profile, and format are required")
	}
	if request.Status == "" {
		request.Status = "draft"
	}
	if request.Status != "draft" && request.Status != "final" {
		return ReportRenderResult{}, errors.New("status must be draft or final")
	}
	if request.Status == "final" {
		review, err := s.cases.Review(request.CaseID)
		if err != nil {
			return ReportRenderResult{}, err
		}
		if !review.Ready {
			return ReportRenderResult{}, fmt.Errorf("final report requires ready Case review with %d issue(s)", len(review.Issues))
		}
		c, revision, err := s.cases.Snapshot(request.CaseID)
		if err != nil {
			return ReportRenderResult{}, err
		}
		if review.CaseSHA256 != revision {
			return ReportRenderResult{}, errors.New("case changed after final review")
		}
		return s.renderCaseReportSnapshot(c, revision, request)
	}
	c, revision, err := s.cases.Snapshot(request.CaseID)
	if err != nil {
		return ReportRenderResult{}, err
	}
	return s.renderCaseReportSnapshot(c, revision, request)
}
func (s *Service) renderCaseReportSnapshot(c casebook.Case, revision string, request ReportRenderRequest) (ReportRenderResult, error) {
	doc, err := reporting.Build(c, revision, request.Profile, request.Classification)
	if err != nil {
		return ReportRenderResult{}, err
	}
	doc, err = reporting.FilterSections(doc, request.Sections)
	if err != nil {
		return ReportRenderResult{}, err
	}
	body, err := reporting.Render(doc, request.Format)
	if err != nil {
		return ReportRenderResult{}, err
	}
	sum := sha256.Sum256(body)
	result := ReportRenderResult{Document: doc, Format: request.Format, ContentSHA256: hex.EncodeToString(sum[:]), Bytes: len(body)}
	if request.OutputPath == "" {
		return result, nil
	}
	path, err := filepath.Abs(request.OutputPath)
	if err != nil {
		return ReportRenderResult{}, err
	}
	info, statErr := os.Lstat(path)
	if statErr == nil {
		if !info.Mode().IsRegular() {
			return ReportRenderResult{}, errors.New("report output must be a regular file")
		}
		if request.ExpectedOutputSHA256 == "" {
			return ReportRenderResult{}, errors.New("expected_output_sha256 is required to replace existing report output")
		}
		current, err := targetidentity.Inspect(path)
		if err != nil {
			return ReportRenderResult{}, err
		}
		if current.SHA256 != request.ExpectedOutputSHA256 {
			return ReportRenderResult{}, fmt.Errorf("report output changed: expected %s current %s", request.ExpectedOutputSHA256, current.SHA256)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return ReportRenderResult{}, statErr
	} else if request.ExpectedOutputSHA256 != "" {
		return ReportRenderResult{}, errors.New("expected_output_sha256 supplied but output does not exist")
	}
	if err := recordio.WriteFile(path, body, 0o600); err != nil {
		return ReportRenderResult{}, err
	}
	identity, err := targetidentity.Inspect(path)
	if err != nil {
		return ReportRenderResult{}, err
	}
	if identity.SHA256 != result.ContentSHA256 {
		return ReportRenderResult{}, errors.New("report output identity mismatch after publish")
	}
	result.Output = &identity
	return result, nil
}

func (s *Service) RenderCaseDashboard(request DashboardRenderRequest) (DashboardRenderResult, error) {
	request.CaseID = strings.TrimSpace(request.CaseID)
	request.Profile = strings.TrimSpace(request.Profile)
	request.Classification = strings.TrimSpace(request.Classification)
	request.Actor = strings.TrimSpace(request.Actor)
	request.OutputPath = strings.TrimSpace(request.OutputPath)
	request.ExpectedOutputSHA256 = strings.ToLower(strings.TrimSpace(request.ExpectedOutputSHA256))
	if request.CaseID == "" || request.OutputPath == "" {
		return DashboardRenderResult{}, errors.New("case_id and output_path are required")
	}
	if request.Profile == "" {
		request.Profile = "general"
	}
	c, revision, err := s.cases.Snapshot(request.CaseID)
	if err != nil {
		return DashboardRenderResult{}, err
	}
	doc, err := reporting.Build(c, revision, request.Profile, request.Classification)
	if err != nil {
		return DashboardRenderResult{}, err
	}
	var workspace *collaboration.Workspace
	var reviewQueue []collaboration.ReviewQueueItem
	if request.Actor != "" {
		value, err := s.GetCaseCollaboration(request.CaseID, request.Actor)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return DashboardRenderResult{}, err
			}
		} else {
			workspace = &value
			reviewQueue, err = s.GetCaseCollaborationReviewQueue(CollaborationReviewQueueRequest{CaseID: request.CaseID, Actor: request.Actor})
			if err != nil {
				return DashboardRenderResult{}, err
			}
		}
	}
	jobs, err := s.jobs.ListRecent(500)
	if err != nil {
		return DashboardRenderResult{}, err
	}
	index, err := toolindex.Scan(s.root)
	if err != nil {
		return DashboardRenderResult{}, err
	}
	agents, err := s.dashboardAgentFleetProjection()
	if err != nil {
		return DashboardRenderResult{}, err
	}
	packState, err := s.dashboardPackRegistryProjection()
	if err != nil {
		return DashboardRenderResult{}, err
	}
	body, err := dashboard.Render(doc, workspace, dashboard.Operations{Jobs: jobs, Tools: index.Tools, Agents: agents, PackRegistry: packState, ReviewQueue: reviewQueue})
	if err != nil {
		return DashboardRenderResult{}, err
	}
	sum := sha256.Sum256(body)
	path, err := filepath.Abs(request.OutputPath)
	if err != nil {
		return DashboardRenderResult{}, err
	}
	info, statErr := os.Lstat(path)
	if statErr == nil {
		if !info.Mode().IsRegular() {
			return DashboardRenderResult{}, errors.New("dashboard output must be a regular file")
		}
		if request.ExpectedOutputSHA256 == "" {
			return DashboardRenderResult{}, errors.New("expected_output_sha256 is required to replace existing dashboard output")
		}
		current, err := targetidentity.Inspect(path)
		if err != nil {
			return DashboardRenderResult{}, err
		}
		if current.SHA256 != request.ExpectedOutputSHA256 {
			return DashboardRenderResult{}, fmt.Errorf("dashboard output changed: expected %s current %s", request.ExpectedOutputSHA256, current.SHA256)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return DashboardRenderResult{}, statErr
	} else if request.ExpectedOutputSHA256 != "" {
		return DashboardRenderResult{}, errors.New("expected_output_sha256 supplied but dashboard output does not exist")
	}
	if err := recordio.WriteFile(path, body, 0o600); err != nil {
		return DashboardRenderResult{}, err
	}
	identity, err := targetidentity.Inspect(path)
	if err != nil {
		return DashboardRenderResult{}, err
	}
	contentSHA := hex.EncodeToString(sum[:])
	if identity.SHA256 != contentSHA {
		return DashboardRenderResult{}, errors.New("dashboard output identity mismatch after publish")
	}
	return DashboardRenderResult{Document: doc, ContentSHA256: contentSHA, Bytes: len(body), Output: identity, Collaboration: workspace}, nil
}

func (s *Service) collaborationStore() (*collaboration.Store, error) {
	return collaboration.New(filepath.Join(s.root, "state", "collaboration"))
}
func (s *Service) InitCaseCollaboration(request CollaborationInitRequest) (collaboration.Workspace, error) {
	request.CaseID = strings.TrimSpace(request.CaseID)
	request.Owner = strings.TrimSpace(request.Owner)
	if request.CaseID == "" || request.Owner == "" {
		return collaboration.Workspace{}, errors.New("case_id and owner are required")
	}
	if _, err := s.cases.Get(request.CaseID); err != nil {
		return collaboration.Workspace{}, err
	}
	store, err := s.collaborationStore()
	if err != nil {
		return collaboration.Workspace{}, err
	}
	return store.Init(request.CaseID, request.Owner)
}
func (s *Service) GetCaseCollaboration(caseID, actor string) (collaboration.Workspace, error) {
	store, w, err := s.authorizeCollaboration(caseID, actor, rbac.ActionCaseRead)
	_ = store
	return w, err
}
func (s *Service) AddCaseParticipant(request CollaborationParticipantRequest) (collaboration.Workspace, error) {
	store, _, err := s.authorizeCollaboration(request.CaseID, request.Actor, rbac.ActionCollaborationManage)
	if err != nil {
		return collaboration.Workspace{}, err
	}
	role, err := rbac.NormalizeRole(request.Role)
	if err != nil {
		return collaboration.Workspace{}, err
	}
	return store.AddParticipant(request.CaseID, request.ExpectedRevision, request.Subject, string(role))
}
func (s *Service) AssignCaseFindingOwner(request FindingOwnerRequest) (collaboration.Workspace, error) {
	store, _, err := s.authorizeCollaboration(request.CaseID, request.Actor, rbac.ActionCollaborationManage)
	if err != nil {
		return collaboration.Workspace{}, err
	}
	c, _, err := s.cases.Snapshot(request.CaseID)
	if err != nil {
		return collaboration.Workspace{}, err
	}
	if !caseHasFinding(c, request.FindingID) {
		return collaboration.Workspace{}, fmt.Errorf("unknown finding id %q", request.FindingID)
	}
	return store.AssignFinding(request.CaseID, request.ExpectedRevision, request.FindingID, request.Owner)
}
func (s *Service) AddCaseCollaborationTask(request CollaborationTaskRequest) (collaboration.Workspace, collaboration.Task, error) {
	store, _, err := s.authorizeCollaboration(request.CaseID, request.Actor, rbac.ActionTaskWrite)
	if err != nil {
		return collaboration.Workspace{}, collaboration.Task{}, err
	}
	return store.AddTask(request.CaseID, request.ExpectedRevision, request.Title, request.Owner)
}
func (s *Service) UpdateCaseCollaborationTask(request CollaborationTaskUpdateRequest) (collaboration.Workspace, error) {
	store, _, err := s.authorizeCollaboration(request.CaseID, request.Actor, rbac.ActionTaskWrite)
	if err != nil {
		return collaboration.Workspace{}, err
	}
	return store.UpdateTask(request.CaseID, request.ExpectedRevision, request.TaskID, request.Status)
}
func (s *Service) AddCaseCollaborationComment(request CollaborationCommentRequest) (collaboration.Workspace, collaboration.Comment, error) {
	store, _, err := s.authorizeCollaboration(request.CaseID, request.Actor, rbac.ActionCommentAdd)
	if err != nil {
		return collaboration.Workspace{}, collaboration.Comment{}, err
	}
	return store.AddComment(request.CaseID, request.ExpectedRevision, request.Actor, request.Body, request.ObjectType, request.ObjectID)
}
func (s *Service) AddCaseCollaborationApproval(request CollaborationApprovalRequest) (collaboration.Workspace, collaboration.Approval, error) {
	store, _, err := s.authorizeCollaboration(request.CaseID, request.Actor, rbac.ActionApprove)
	if err != nil {
		return collaboration.Workspace{}, collaboration.Approval{}, err
	}
	_, caseRevision, err := s.cases.Snapshot(request.CaseID)
	if err != nil {
		return collaboration.Workspace{}, collaboration.Approval{}, err
	}
	return store.AddApproval(request.CaseID, request.ExpectedRevision, collaboration.Approval{Kind: request.Kind, SubjectID: request.SubjectID, Reviewer: request.Actor, Decision: request.Decision, Notes: request.Notes, SourceRevision: caseRevision})
}
func (s *Service) LockCaseEvidence(request EvidenceLockRequest) (collaboration.Workspace, error) {
	store, _, err := s.authorizeCollaboration(request.CaseID, request.Actor, rbac.ActionEvidenceLock)
	if err != nil {
		return collaboration.Workspace{}, err
	}
	c, _, err := s.cases.Snapshot(request.CaseID)
	if err != nil {
		return collaboration.Workspace{}, err
	}
	if !caseHasEvidence(c, request.EvidenceID) {
		return collaboration.Workspace{}, fmt.Errorf("unknown evidence id %q", request.EvidenceID)
	}
	return store.LockEvidence(request.CaseID, request.ExpectedRevision, request.EvidenceID, request.Actor, request.Reason)
}
func (s *Service) UnlockCaseEvidence(request EvidenceLockRequest) (collaboration.Workspace, error) {
	store, _, err := s.authorizeCollaboration(request.CaseID, request.Actor, rbac.ActionEvidenceLock)
	if err != nil {
		return collaboration.Workspace{}, err
	}
	return store.UnlockEvidence(request.CaseID, request.ExpectedRevision, request.EvidenceID)
}
func (s *Service) authorizeCollaboration(caseID, actor string, action rbac.Action) (*collaboration.Store, collaboration.Workspace, error) {
	caseID = strings.TrimSpace(caseID)
	actor = strings.TrimSpace(actor)
	if caseID == "" || actor == "" {
		return nil, collaboration.Workspace{}, errors.New("case_id and actor are required")
	}
	store, err := s.collaborationStore()
	if err != nil {
		return nil, collaboration.Workspace{}, err
	}
	w, err := store.Get(caseID)
	if err != nil {
		return nil, collaboration.Workspace{}, err
	}
	var roleText string
	for _, p := range w.Participants {
		if p.Subject == actor && p.Status == "active" {
			roleText = p.Role
			break
		}
	}
	if roleText == "" {
		return nil, collaboration.Workspace{}, fmt.Errorf("actor %q is not an active case participant", actor)
	}
	role, err := rbac.NormalizeRole(roleText)
	if err != nil {
		return nil, collaboration.Workspace{}, err
	}
	if err := rbac.Require(role, action); err != nil {
		return nil, collaboration.Workspace{}, err
	}
	return store, w, nil
}
func caseHasFinding(c casebook.Case, id string) bool {
	for _, x := range c.Findings {
		if x.ID == id {
			return true
		}
	}
	return false
}
func caseHasEvidence(c casebook.Case, id string) bool {
	for _, x := range c.Evidence {
		if x.ID == id {
			return true
		}
	}
	return false
}

func (s *Service) remoteAgentStore() (*remoteagent.Store, error) {
	return remoteagent.NewStore(filepath.Join(s.root, "state", "remote-agents"))
}
func (s *Service) RegisterRemoteAgent(request RemoteAgentRegisterRequest) (RemoteAgentRegisterResult, error) {
	role, err := rbac.NormalizeRole(request.AuthorityRole)
	if err != nil {
		return RemoteAgentRegisterResult{}, err
	}
	if err := rbac.Require(role, rbac.ActionAgentManage); err != nil {
		return RemoteAgentRegisterResult{}, err
	}
	var manifest remoteagent.Manifest
	source, err := readStableJSON(request.ManifestPath, 1<<20, &manifest)
	if err != nil {
		return RemoteAgentRegisterResult{}, err
	}
	store, err := s.remoteAgentStore()
	if err != nil {
		return RemoteAgentRegisterResult{}, err
	}
	reg, err := store.Register(manifest, request.ExpectedRevision)
	if err != nil {
		return RemoteAgentRegisterResult{}, err
	}
	return RemoteAgentRegisterResult{Source: source, Registration: reg}, nil
}
func (s *Service) GetRemoteAgent(agentID string) (remoteagent.Registration, error) {
	store, err := s.remoteAgentStore()
	if err != nil {
		return remoteagent.Registration{}, err
	}
	return store.Get(agentID)
}
func (s *Service) ListRemoteAgents() ([]remoteagent.Registration, error) {
	store, err := s.remoteAgentStore()
	if err != nil {
		return nil, err
	}
	return store.List()
}
func (s *Service) ValidateRemoteAgentJob(request RemoteJobValidationRequest) (RemoteJobValidationResult, error) {
	store, err := s.remoteAgentStore()
	if err != nil {
		return RemoteJobValidationResult{}, err
	}
	reg, err := store.Get(strings.TrimSpace(request.AgentID))
	if err != nil {
		return RemoteJobValidationResult{}, err
	}
	var job remoteagent.JobRequest
	source, err := readStableJSON(request.JobPath, 1<<20, &job)
	if err != nil {
		return RemoteJobValidationResult{}, err
	}
	if err := remoteagent.ValidateJob(reg.Manifest, job); err != nil {
		return RemoteJobValidationResult{}, err
	}
	return RemoteJobValidationResult{Source: source, Agent: reg, Job: job, Valid: true, ExecutionPerformed: false}, nil
}
func (s *Service) VerifyRemoteAgentResult(request RemoteResultVerificationRequest) (RemoteResultVerificationResult, error) {
	store, err := s.remoteAgentStore()
	if err != nil {
		return RemoteResultVerificationResult{}, err
	}
	reg, err := store.Get(strings.TrimSpace(request.AgentID))
	if err != nil {
		return RemoteResultVerificationResult{}, err
	}
	var result remoteagent.ResultEnvelope
	source, err := readStableJSON(request.ResultPath, 4<<20, &result)
	if err != nil {
		return RemoteResultVerificationResult{}, err
	}
	keyBytes, err := base64.StdEncoding.DecodeString(reg.Manifest.PublicKey)
	if err != nil {
		return RemoteResultVerificationResult{}, err
	}
	if err := remoteagent.VerifyResult(result, ed25519.PublicKey(keyBytes)); err != nil {
		return RemoteResultVerificationResult{}, err
	}
	if result.AgentID != reg.Manifest.AgentID {
		return RemoteResultVerificationResult{}, errors.New("remote result agent identity mismatch")
	}
	return RemoteResultVerificationResult{Source: source, Result: result, Verified: true}, nil
}
func (s *Service) VerifySignedPack(request PackVerificationRequest) (PackVerificationResult, error) {
	var manifest packregistry.Manifest
	manifestSource, err := readStableJSON(request.ManifestPath, 4<<20, &manifest)
	if err != nil {
		return PackVerificationResult{}, err
	}
	var trust packregistry.TrustStore
	trustSource, err := readStableJSON(request.TrustPath, 4<<20, &trust)
	if err != nil {
		return PackVerificationResult{}, err
	}
	verification, err := packregistry.Verify(request.Root, manifest, trust)
	if err != nil {
		return PackVerificationResult{}, err
	}
	return PackVerificationResult{ManifestSource: manifestSource, TrustSource: trustSource, Verification: verification}, nil
}
func readStableJSON(path string, maxBytes int64, out any) (targetidentity.Identity, error) {
	source, err := targetidentity.InspectBounded(path, maxBytes)
	if err != nil {
		return targetidentity.Identity{}, err
	}
	if source.Size > maxBytes {
		return targetidentity.Identity{}, fmt.Errorf("JSON input exceeds max_bytes: size=%d max=%d", source.Size, maxBytes)
	}
	body, err := os.ReadFile(source.Path)
	if err != nil {
		return targetidentity.Identity{}, err
	}
	if err := json.Unmarshal(body, out); err != nil {
		return targetidentity.Identity{}, err
	}
	after, err := targetidentity.InspectBounded(source.Path, maxBytes)
	if err != nil {
		return targetidentity.Identity{}, err
	}
	if after.ID != source.ID || after.Size != source.Size || after.ModifiedUTC != source.ModifiedUTC {
		return targetidentity.Identity{}, errors.New("JSON input changed during read")
	}
	return source, nil
}
