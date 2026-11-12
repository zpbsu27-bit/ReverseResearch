package collaboration

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"reverseresearch/internal/recordio"
)

const SchemaVersion = 1

type Participant struct {
	Subject string `json:"subject"`
	Role    string `json:"role"`
	Status  string `json:"status"`
}
type Task struct {
	ID         string `json:"id"`
	Title      string `json:"title"`
	Owner      string `json:"owner,omitempty"`
	Status     string `json:"status"`
	CreatedUTC string `json:"created_utc"`
	UpdatedUTC string `json:"updated_utc"`
}
type Comment struct {
	ID         string `json:"id"`
	Author     string `json:"author"`
	Body       string `json:"body"`
	ObjectType string `json:"object_type,omitempty"`
	ObjectID   string `json:"object_id,omitempty"`
	CreatedUTC string `json:"created_utc"`
}
type Approval struct {
	ID             string `json:"id"`
	Kind           string `json:"kind"`
	SubjectID      string `json:"subject_id"`
	Reviewer       string `json:"reviewer"`
	Decision       string `json:"decision"`
	Notes          string `json:"notes,omitempty"`
	SourceRevision string `json:"source_revision"`
	CreatedUTC     string `json:"created_utc"`
}
type EvidenceLock struct {
	EvidenceID string `json:"evidence_id"`
	LockedBy   string `json:"locked_by"`
	Reason     string `json:"reason"`
	LockedUTC  string `json:"locked_utc"`
}
type ReviewRequest struct {
	ID               string `json:"id"`
	Kind             string `json:"kind"`
	SubjectID        string `json:"subject_id"`
	RequestedBy      string `json:"requested_by"`
	SourceRevision   string `json:"source_revision"`
	Status           string `json:"status"`
	LatestApprovalID string `json:"latest_approval_id,omitempty"`
	CreatedUTC       string `json:"created_utc"`
	UpdatedUTC       string `json:"updated_utc"`
}
type HistoryEvent struct {
	ID             string `json:"id"`
	Action         string `json:"action"`
	Actor          string `json:"actor,omitempty"`
	SubjectType    string `json:"subject_type,omitempty"`
	SubjectID      string `json:"subject_id,omitempty"`
	SourceRevision string `json:"source_revision,omitempty"`
	CreatedUTC     string `json:"created_utc"`
}
type ReviewQueueItem struct {
	Review ReviewRequest `json:"review"`
	State  string        `json:"state"`
}
type Workspace struct {
	SchemaVersion int               `json:"schema_version"`
	CaseID        string            `json:"case_id"`
	CaseOwner     string            `json:"case_owner,omitempty"`
	Participants  []Participant     `json:"participants,omitempty"`
	FindingOwners map[string]string `json:"finding_owners,omitempty"`
	Tasks         []Task            `json:"tasks,omitempty"`
	Comments      []Comment         `json:"comments,omitempty"`
	Approvals     []Approval        `json:"approvals,omitempty"`
	EvidenceLocks []EvidenceLock    `json:"evidence_locks,omitempty"`
	Reviews       []ReviewRequest   `json:"reviews,omitempty"`
	History       []HistoryEvent    `json:"history,omitempty"`
	UpdatedUTC    string            `json:"updated_utc"`
	Revision      string            `json:"revision"`
}
type Store struct{ root string }

func New(root string) (*Store, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("collaboration root is required")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, err
	}
	return &Store{root: abs}, nil
}
func (s *Store) Init(caseID, owner string) (Workspace, error) {
	caseID = strings.TrimSpace(caseID)
	owner = strings.TrimSpace(owner)
	if caseID == "" || owner == "" {
		return Workspace{}, errors.New("case_id and owner are required")
	}
	if err := validateCollaborationStorageID("case_id", caseID); err != nil {
		return Workspace{}, err
	}
	return s.mutate(caseID, "", func(w *Workspace) error {
		if w.CaseID != "" {
			return errors.New("collaboration workspace already exists")
		}
		w.CaseID = caseID
		w.CaseOwner = owner
		w.FindingOwners = map[string]string{}
		w.Participants = []Participant{{Subject: owner, Role: "owner", Status: "active"}}
		return nil
	})
}
func (s *Store) Get(caseID string) (Workspace, error) {
	caseID = strings.TrimSpace(caseID)
	if caseID == "" {
		return Workspace{}, errors.New("case_id is required")
	}
	if err := validateCollaborationStorageID("case_id", caseID); err != nil {
		return Workspace{}, err
	}
	body, err := recordio.ReadFileLimit(s.path(caseID), MaxWorkspaceRecordBytes)
	if err != nil {
		return Workspace{}, err
	}
	return decode(body, caseID)
}
func (s *Store) AddParticipant(caseID, expectedRevision, subject, role string) (Workspace, error) {
	subject = strings.TrimSpace(subject)
	role = strings.ToLower(strings.TrimSpace(role))
	if subject == "" || role == "" {
		return Workspace{}, errors.New("participant subject and role are required")
	}
	return s.mutate(caseID, expectedRevision, func(w *Workspace) error {
		for i := range w.Participants {
			if w.Participants[i].Subject == subject {
				w.Participants[i].Role = role
				w.Participants[i].Status = "active"
				return nil
			}
		}
		w.Participants = append(w.Participants, Participant{Subject: subject, Role: role, Status: "active"})
		sort.Slice(w.Participants, func(i, j int) bool { return w.Participants[i].Subject < w.Participants[j].Subject })
		return nil
	})
}
func (s *Store) AssignFinding(caseID, expectedRevision, findingID, owner string) (Workspace, error) {
	findingID = strings.TrimSpace(findingID)
	owner = strings.TrimSpace(owner)
	if findingID == "" || owner == "" {
		return Workspace{}, errors.New("finding_id and owner are required")
	}
	return s.mutate(caseID, expectedRevision, func(w *Workspace) error {
		if !activeParticipant(*w, owner) {
			return fmt.Errorf("finding owner %q is not an active participant", owner)
		}
		if w.FindingOwners == nil {
			w.FindingOwners = map[string]string{}
		}
		w.FindingOwners[findingID] = owner
		return nil
	})
}
func (s *Store) AddTask(caseID, expectedRevision, title, owner string) (Workspace, Task, error) {
	title = strings.TrimSpace(title)
	owner = strings.TrimSpace(owner)
	if title == "" {
		return Workspace{}, Task{}, errors.New("task title is required")
	}
	var created Task
	w, err := s.mutate(caseID, expectedRevision, func(w *Workspace) error {
		if owner != "" && !activeParticipant(*w, owner) {
			return fmt.Errorf("task owner %q is not an active participant", owner)
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		created = Task{ID: newID("task", caseID+title+now), Title: title, Owner: owner, Status: "planned", CreatedUTC: now, UpdatedUTC: now}
		w.Tasks = append(w.Tasks, created)
		return nil
	})
	return w, created, err
}
func (s *Store) UpdateTask(caseID, expectedRevision, taskID, status string) (Workspace, error) {
	taskID = strings.TrimSpace(taskID)
	status = strings.ToLower(strings.TrimSpace(status))
	switch status {
	case "planned", "running", "blocked", "done", "cancelled":
	default:
		return Workspace{}, fmt.Errorf("invalid task status %q", status)
	}
	return s.mutate(caseID, expectedRevision, func(w *Workspace) error {
		for i := range w.Tasks {
			if w.Tasks[i].ID == taskID {
				w.Tasks[i].Status = status
				w.Tasks[i].UpdatedUTC = time.Now().UTC().Format(time.RFC3339Nano)
				return nil
			}
		}
		return fmt.Errorf("unknown task %q", taskID)
	})
}
func (s *Store) AddComment(caseID, expectedRevision, author, body, objectType, objectID string) (Workspace, Comment, error) {
	author = strings.TrimSpace(author)
	body = strings.TrimSpace(body)
	if author == "" || body == "" {
		return Workspace{}, Comment{}, errors.New("comment author and body are required")
	}
	var created Comment
	w, err := s.mutate(caseID, expectedRevision, func(w *Workspace) error {
		if !activeParticipant(*w, author) {
			return fmt.Errorf("comment author %q is not an active participant", author)
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		created = Comment{ID: newID("comment", caseID+author+now), Author: author, Body: body, ObjectType: strings.TrimSpace(objectType), ObjectID: strings.TrimSpace(objectID), CreatedUTC: now}
		w.Comments = append(w.Comments, created)
		return nil
	})
	return w, created, err
}
func (s *Store) AddApproval(caseID, expectedRevision string, item Approval) (Workspace, Approval, error) {
	item.Kind = strings.TrimSpace(item.Kind)
	item.SubjectID = strings.TrimSpace(item.SubjectID)
	item.Reviewer = strings.TrimSpace(item.Reviewer)
	item.Decision = strings.ToLower(strings.TrimSpace(item.Decision))
	item.Notes = strings.TrimSpace(item.Notes)
	item.SourceRevision = strings.TrimSpace(item.SourceRevision)
	if item.Kind == "" || item.SubjectID == "" || item.Reviewer == "" || item.SourceRevision == "" {
		return Workspace{}, Approval{}, errors.New("approval kind, subject_id, reviewer, and source_revision are required")
	}
	if item.Decision != "approved" && item.Decision != "rejected" {
		return Workspace{}, Approval{}, errors.New("approval decision must be approved or rejected")
	}
	var created Approval
	event := HistoryEvent{Action: "review.decision", Actor: item.Reviewer, SubjectType: item.Kind, SubjectID: item.SubjectID, SourceRevision: item.SourceRevision}
	w, err := s.mutateAction(caseID, expectedRevision, event, func(w *Workspace) error {
		if !activeParticipant(*w, item.Reviewer) {
			return fmt.Errorf("reviewer %q is not an active participant", item.Reviewer)
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		item.ID = newID("approval", caseID+item.SubjectID+now)
		item.CreatedUTC = now
		created = item
		w.Approvals = append(w.Approvals, item)
		for i := range w.Reviews {
			if w.Reviews[i].Kind == item.Kind && w.Reviews[i].SubjectID == item.SubjectID && w.Reviews[i].SourceRevision == item.SourceRevision && w.Reviews[i].Status == "pending" {
				w.Reviews[i].Status = item.Decision
				w.Reviews[i].LatestApprovalID = item.ID
				w.Reviews[i].UpdatedUTC = now
			}
		}
		return nil
	})
	return w, created, err
}
func (s *Store) RequestReview(caseID, expectedRevision, actor, kind, subjectID, sourceRevision string) (Workspace, ReviewRequest, error) {
	actor = strings.TrimSpace(actor)
	kind = strings.TrimSpace(kind)
	subjectID = strings.TrimSpace(subjectID)
	sourceRevision = strings.TrimSpace(sourceRevision)
	if actor == "" || kind == "" || subjectID == "" || sourceRevision == "" {
		return Workspace{}, ReviewRequest{}, errors.New("actor, kind, subject_id, and source_revision are required")
	}
	var created ReviewRequest
	event := HistoryEvent{Action: "review.request", Actor: actor, SubjectType: kind, SubjectID: subjectID, SourceRevision: sourceRevision}
	w, err := s.mutateAction(caseID, expectedRevision, event, func(w *Workspace) error {
		if !activeParticipant(*w, actor) {
			return fmt.Errorf("review requester %q is not an active participant", actor)
		}
		for _, review := range w.Reviews {
			if review.Kind == kind && review.SubjectID == subjectID && review.SourceRevision == sourceRevision && review.Status == "pending" {
				return fmt.Errorf("pending review already exists for %s %q at source revision %s", kind, subjectID, sourceRevision)
			}
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		created = ReviewRequest{
			ID:   newID("review", caseID+kind+subjectID+sourceRevision+actor+now),
			Kind: kind, SubjectID: subjectID, RequestedBy: actor, SourceRevision: sourceRevision,
			Status: "pending", CreatedUTC: now, UpdatedUTC: now,
		}
		w.Reviews = append(w.Reviews, created)
		return nil
	})
	return w, created, err
}

func (s *Store) ReviewQueue(caseID, currentSourceRevision string) ([]ReviewQueueItem, error) {
	currentSourceRevision = strings.TrimSpace(currentSourceRevision)
	if currentSourceRevision == "" {
		return nil, errors.New("current_source_revision is required")
	}
	w, err := s.Get(caseID)
	if err != nil {
		return nil, err
	}
	out := []ReviewQueueItem{}
	for _, review := range w.Reviews {
		state := review.Status
		if review.SourceRevision != currentSourceRevision {
			state = "stale"
		} else if state == "approved" || state == "cancelled" {
			continue
		}
		out = append(out, ReviewQueueItem{Review: review, State: state})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].State != out[j].State {
			return out[i].State < out[j].State
		}
		if out[i].Review.CreatedUTC != out[j].Review.CreatedUTC {
			return out[i].Review.CreatedUTC < out[j].Review.CreatedUTC
		}
		return out[i].Review.ID < out[j].Review.ID
	})
	return out, nil
}

func (s *Store) History(caseID string) ([]HistoryEvent, error) {
	w, err := s.Get(caseID)
	if err != nil {
		return nil, err
	}
	archived, err := s.readArchivedHistory(caseID)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]HistoryEvent, len(archived)+len(w.History))
	for _, event := range archived {
		byID[event.ID] = event
	}
	for _, event := range w.History {
		if existing, ok := byID[event.ID]; ok && existing != event {
			return nil, fmt.Errorf("collaboration history event %q conflicts with archived copy", event.ID)
		}
		byID[event.ID] = event
	}
	out := make([]HistoryEvent, 0, len(byID))
	for _, event := range byID {
		out = append(out, event)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedUTC != out[j].CreatedUTC {
			return out[i].CreatedUTC < out[j].CreatedUTC
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}
func (s *Store) LockEvidence(caseID, expectedRevision, evidenceID, actor, reason string) (Workspace, error) {
	evidenceID = strings.TrimSpace(evidenceID)
	actor = strings.TrimSpace(actor)
	reason = strings.TrimSpace(reason)
	if evidenceID == "" || actor == "" || reason == "" {
		return Workspace{}, errors.New("evidence_id, actor, and reason are required")
	}
	return s.mutate(caseID, expectedRevision, func(w *Workspace) error {
		if !activeParticipant(*w, actor) {
			return fmt.Errorf("actor %q is not an active participant", actor)
		}
		for _, x := range w.EvidenceLocks {
			if x.EvidenceID == evidenceID {
				return fmt.Errorf("evidence %q already locked", evidenceID)
			}
		}
		w.EvidenceLocks = append(w.EvidenceLocks, EvidenceLock{EvidenceID: evidenceID, LockedBy: actor, Reason: reason, LockedUTC: time.Now().UTC().Format(time.RFC3339Nano)})
		return nil
	})
}
func (s *Store) UnlockEvidence(caseID, expectedRevision, evidenceID string) (Workspace, error) {
	evidenceID = strings.TrimSpace(evidenceID)
	if evidenceID == "" {
		return Workspace{}, errors.New("evidence_id is required")
	}
	return s.mutate(caseID, expectedRevision, func(w *Workspace) error {
		out := w.EvidenceLocks[:0]
		found := false
		for _, x := range w.EvidenceLocks {
			if x.EvidenceID == evidenceID {
				found = true
				continue
			}
			out = append(out, x)
		}
		if !found {
			return fmt.Errorf("evidence %q is not locked", evidenceID)
		}
		w.EvidenceLocks = out
		return nil
	})
}
func (s *Store) mutate(caseID, expectedRevision string, fn func(*Workspace) error) (Workspace, error) {
	return s.mutateAction(caseID, expectedRevision, HistoryEvent{Action: "workspace.update"}, fn)
}

func (s *Store) mutateAction(caseID, expectedRevision string, event HistoryEvent, fn func(*Workspace) error) (result Workspace, err error) {
	caseID = strings.TrimSpace(caseID)
	if caseID == "" {
		return Workspace{}, errors.New("case_id is required")
	}
	if err := validateCollaborationStorageID("case_id", caseID); err != nil {
		return Workspace{}, err
	}
	event.Action = strings.TrimSpace(event.Action)
	event.Actor = strings.TrimSpace(event.Actor)
	event.SubjectType = strings.TrimSpace(event.SubjectType)
	event.SubjectID = strings.TrimSpace(event.SubjectID)
	if event.Action == "" {
		return Workspace{}, errors.New("history action is required")
	}
	release, err := recordio.Acquire(s.lockPath(caseID), 2*time.Second)
	if err != nil {
		return Workspace{}, err
	}
	defer func() { err = errors.Join(err, release()) }()
	var w Workspace
	body, readErr := recordio.ReadFileLimit(s.path(caseID), MaxWorkspaceRecordBytes)
	if readErr == nil {
		w, err = decode(body, caseID)
		if err != nil {
			return Workspace{}, err
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return Workspace{}, readErr
	}
	if expectedRevision != "" && w.Revision != expectedRevision {
		return Workspace{}, fmt.Errorf("collaboration revision changed: expected %s current %s", expectedRevision, w.Revision)
	}
	beforeRevision := w.Revision
	if err := fn(&w); err != nil {
		return Workspace{}, err
	}
	if w.CaseID == "" {
		w.CaseID = caseID
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if event.SourceRevision == "" {
		event.SourceRevision = beforeRevision
	}
	event.CreatedUTC = now
	event.ID = newID("history", caseID+event.Action+event.Actor+event.SubjectType+event.SubjectID+event.SourceRevision+now)
	w.History = append(w.History, event)
	if err := s.archiveHistoryOverflow(caseID, &w); err != nil {
		return Workspace{}, err
	}
	w.SchemaVersion = SchemaVersion
	w.UpdatedUTC = now
	w.Revision = ""
	plain, err := json.Marshal(w)
	if err != nil {
		return Workspace{}, err
	}
	sum := sha256.Sum256(plain)
	w.Revision = hex.EncodeToString(sum[:])
	body, err = json.MarshalIndent(w, "", "  ")
	if err != nil {
		return Workspace{}, err
	}
	body = append(body, '\n')
	if len(body) > MaxWorkspaceRecordBytes {
		return Workspace{}, fmt.Errorf("collaboration workspace exceeds durable size limit: %d > %d", len(body), MaxWorkspaceRecordBytes)
	}
	if err := recordio.WriteFile(s.path(caseID), body, 0o600); err != nil {
		return Workspace{}, err
	}
	return w, nil
}
func decode(body []byte, caseID string) (Workspace, error) {
	var w Workspace
	if err := json.Unmarshal(body, &w); err != nil {
		return Workspace{}, err
	}
	if w.SchemaVersion != SchemaVersion {
		return Workspace{}, fmt.Errorf("unsupported collaboration schema %d", w.SchemaVersion)
	}
	if w.CaseID != caseID {
		return Workspace{}, errors.New("collaboration case identity mismatch")
	}
	rev := w.Revision
	w.Revision = ""
	plain, _ := json.Marshal(w)
	sum := sha256.Sum256(plain)
	actual := hex.EncodeToString(sum[:])
	if rev != actual {
		return Workspace{}, errors.New("collaboration revision mismatch")
	}
	w.Revision = rev
	return w, nil
}
func activeParticipant(w Workspace, subject string) bool {
	for _, p := range w.Participants {
		if p.Subject == subject && p.Status == "active" {
			return true
		}
	}
	return false
}
func (s *Store) path(caseID string) string     { return filepath.Join(s.root, caseID+".json") }
func (s *Store) lockPath(caseID string) string { return filepath.Join(s.root, caseID+".lock") }
func newID(prefix, seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return prefix + "_" + hex.EncodeToString(sum[:8])
}
