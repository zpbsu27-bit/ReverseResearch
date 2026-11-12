package job

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"reverseresearch/internal/engagement"
	"reverseresearch/internal/recordio"
)

type State string

const (
	StatePlanned    State = "planned"
	StatePrepared   State = "prepared"
	StateRunning    State = "running"
	StateApplied    State = "applied"
	StateFailed     State = "failed"
	StateUncertain  State = "uncertain"
	StateRolledBack State = "rolled_back"
	StateCancelled  State = "cancelled"
)

var operationIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$`)

type ScopeAuthorizer interface {
	AuthorizeEffect(id, target, action, effectClass string, at time.Time) (engagement.Decision, error)
}

type PlanRequest struct {
	OperationID   string   `json:"operation_id"`
	EngagementID  string   `json:"engagement_id"`
	Target        string   `json:"target"`
	Action        string   `json:"action"`
	EffectClass   string   `json:"effect_class"`
	ToolIdentity  string   `json:"tool_identity,omitempty"`
	InputRevision string   `json:"input_revision,omitempty"`
	EvidenceIDs   []string `json:"evidence_ids,omitempty"`
}

type TransitionRequest struct {
	JobID          string   `json:"job_id"`
	OperationID    string   `json:"operation_id"`
	To             State    `json:"to"`
	ResultIdentity string   `json:"result_identity,omitempty"`
	CleanupState   string   `json:"cleanup_state,omitempty"`
	EvidenceIDs    []string `json:"evidence_ids,omitempty"`
	Failure        string   `json:"failure,omitempty"`
}

type Job struct {
	ID             string   `json:"job_id"`
	OperationID    string   `json:"operation_id"`
	RequestSHA256  string   `json:"request_sha256"`
	EngagementID   string   `json:"engagement_id"`
	Target         string   `json:"target"`
	Action         string   `json:"action"`
	EffectClass    string   `json:"effect_class"`
	ToolIdentity   string   `json:"tool_identity,omitempty"`
	InputRevision  string   `json:"input_revision,omitempty"`
	State          State    `json:"state"`
	PlannedUTC     string   `json:"planned_at"`
	PreparedUTC    string   `json:"prepared_at,omitempty"`
	StartedUTC     string   `json:"started_at,omitempty"`
	CompletedUTC   string   `json:"completed_at,omitempty"`
	ResultIdentity string   `json:"result_identity,omitempty"`
	CleanupState   string   `json:"cleanup_state,omitempty"`
	EvidenceIDs    []string `json:"evidence_ids,omitempty"`
	Failure        string   `json:"failure,omitempty"`
}

type Store struct {
	root       string
	authorizer ScopeAuthorizer
}

func New(root string, authorizer ScopeAuthorizer) (*Store, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("job store root is required")
	}
	if authorizer == nil {
		return nil, errors.New("job scope authorizer is required")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve job store root: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(absolute, "jobs"), 0o700); err != nil {
		return nil, fmt.Errorf("create job store: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(absolute, "operations"), 0o700); err != nil {
		return nil, fmt.Errorf("create job operation store: %w", err)
	}
	return &Store{root: absolute, authorizer: authorizer}, nil
}

func (s *Store) Plan(request PlanRequest) (result Job, err error) {
	return s.PlanContext(context.Background(), request)
}

func (s *Store) PlanContext(ctx context.Context, request PlanRequest) (result Job, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	request = normalizePlan(request)
	if err := validatePlan(request); err != nil {
		return Job{}, err
	}
	digest, err := requestDigest(request)
	if err != nil {
		return Job{}, err
	}
	jobID := "job_" + digest[:16]
	lockPath := s.operationLockPath(request.OperationID)
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		return Job{}, err
	}
	release, err := recordio.AcquireContext(ctx, lockPath, 10*time.Second)
	if err != nil {
		return Job{}, err
	}
	defer func() { err = errors.Join(err, release()) }()

	if existing, loadErr := s.loadOperation(request.OperationID); loadErr == nil {
		if existing.RequestSHA256 != digest {
			return Job{}, errors.New("operation_id was already used for a different job request")
		}
		return existing, nil
	} else if !errors.Is(loadErr, os.ErrNotExist) {
		return Job{}, loadErr
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	value := Job{
		ID: jobID, OperationID: request.OperationID, RequestSHA256: digest,
		EngagementID: request.EngagementID, Target: request.Target, Action: request.Action,
		EffectClass: request.EffectClass, ToolIdentity: request.ToolIdentity,
		InputRevision: request.InputRevision, EvidenceIDs: append([]string(nil), request.EvidenceIDs...),
		State: StatePlanned, PlannedUTC: now,
	}
	if err := s.saveNewContext(ctx, value); err != nil {
		return Job{}, err
	}
	return value, nil
}

func (s *Store) Get(jobID string) (Job, error) {
	jobID = strings.TrimSpace(jobID)
	if jobID == "" || strings.ContainsAny(jobID, `/\`) || strings.Contains(jobID, "..") {
		return Job{}, errors.New("invalid job_id")
	}
	body, err := recordio.ReadFileLimit(s.jobPath(jobID), MaxJobRecordBytes)
	if errors.Is(err, os.ErrNotExist) {
		body, err = recordio.ReadFileLimit(s.legacyJobPath(jobID), MaxJobRecordBytes)
	}
	if err != nil {
		return Job{}, err
	}
	var value Job
	if err := json.Unmarshal(body, &value); err != nil {
		return Job{}, fmt.Errorf("decode job: %w", err)
	}
	if value.ID != jobID {
		return Job{}, errors.New("job identity mismatch")
	}
	return value, nil
}

func (s *Store) Prepare(jobID, operationID string) (result Job, err error) {
	return s.PrepareContext(context.Background(), jobID, operationID)
}

func (s *Store) PrepareContext(ctx context.Context, jobID, operationID string) (result Job, err error) {
	return s.transitionContext(ctx, jobID, operationID, StatePrepared, "", "", nil, "", true)
}

func (s *Store) Transition(request TransitionRequest) (result Job, err error) {
	return s.TransitionContext(context.Background(), request)
}

func (s *Store) TransitionContext(ctx context.Context, request TransitionRequest) (result Job, err error) {
	if request.To == StatePrepared {
		return Job{}, errors.New("prepared state requires Prepare so current Engagement/Scope authorization cannot be bypassed")
	}
	authorize := request.To == StateRunning
	return s.transitionContext(ctx, request.JobID, request.OperationID, request.To, strings.TrimSpace(request.ResultIdentity), strings.TrimSpace(request.CleanupState), request.EvidenceIDs, strings.TrimSpace(request.Failure), authorize)
}

func (s *Store) transitionContext(ctx context.Context, jobID, operationID string, to State, resultIdentity, cleanupState string, evidenceIDs []string, failure string, authorize bool) (result Job, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	operationID = strings.TrimSpace(operationID)
	if !operationIDPattern.MatchString(operationID) {
		return Job{}, errors.New("operation_id must match [A-Za-z0-9][A-Za-z0-9._:-]{0,159}")
	}
	lockPath := s.operationLockPath(operationID)
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		return Job{}, err
	}
	release, err := recordio.AcquireContext(ctx, lockPath, 10*time.Second)
	if err != nil {
		return Job{}, err
	}
	defer func() { err = errors.Join(err, release()) }()
	value, err := s.Get(jobID)
	if err != nil {
		return Job{}, err
	}
	if value.OperationID != operationID {
		return Job{}, errors.New("operation_id does not own this job")
	}
	if value.State == to {
		return value, nil
	}
	if value.State == StateUncertain {
		return Job{}, errors.New("uncertain job state cannot be automatically replayed or advanced; reconcile effect evidence explicitly")
	}
	if authorize {
		decision, err := s.authorizer.AuthorizeEffect(value.EngagementID, value.Target, value.Action, value.EffectClass, time.Now().UTC())
		if err != nil {
			return Job{}, err
		}
		if !decision.Allowed {
			return Job{}, fmt.Errorf("scope denied job transition: %s", decision.Reason)
		}
	}
	if !allowedTransition(value.State, to) {
		return Job{}, fmt.Errorf("invalid job transition %s -> %s", value.State, to)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	value.State = to
	switch to {
	case StatePrepared:
		value.PreparedUTC = now
	case StateRunning:
		value.StartedUTC = now
	case StateApplied, StateFailed, StateUncertain, StateRolledBack, StateCancelled:
		value.CompletedUTC = now
	}
	if resultIdentity != "" {
		value.ResultIdentity = resultIdentity
	}
	if cleanupState != "" {
		value.CleanupState = cleanupState
	}
	if len(evidenceIDs) > 0 {
		value.EvidenceIDs = cleanUnique(append(value.EvidenceIDs, evidenceIDs...))
	}
	if failure != "" {
		value.Failure = failure
	}
	if err := s.saveContext(ctx, value); err != nil {
		return Job{}, err
	}
	return value, nil
}

func allowedTransition(from, to State) bool {
	switch from {
	case StatePlanned:
		return to == StatePrepared || to == StateCancelled
	case StatePrepared:
		return to == StateRunning || to == StateFailed || to == StateUncertain || to == StateCancelled
	case StateRunning:
		return to == StateApplied || to == StateFailed || to == StateUncertain
	case StateApplied:
		return to == StateRolledBack
	default:
		return false
	}
}

func normalizePlan(request PlanRequest) PlanRequest {
	request.OperationID = strings.TrimSpace(request.OperationID)
	request.EngagementID = strings.TrimSpace(request.EngagementID)
	request.Target = strings.TrimSpace(request.Target)
	request.Action = strings.TrimSpace(request.Action)
	request.EffectClass = strings.TrimSpace(request.EffectClass)
	request.ToolIdentity = strings.TrimSpace(request.ToolIdentity)
	request.InputRevision = strings.TrimSpace(request.InputRevision)
	request.EvidenceIDs = cleanUnique(request.EvidenceIDs)
	return request
}

func validatePlan(request PlanRequest) error {
	if !operationIDPattern.MatchString(request.OperationID) {
		return errors.New("operation_id must match [A-Za-z0-9][A-Za-z0-9._:-]{0,159}")
	}
	if request.EngagementID == "" || request.Target == "" || request.Action == "" || request.EffectClass == "" {
		return errors.New("engagement_id, target, action, and effect_class are required")
	}
	return nil
}

func requestDigest(request PlanRequest) (string, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:]), nil
}

func cleanUnique(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

func (s *Store) saveContext(ctx context.Context, value Job) error {
	if ctx == nil {
		ctx = context.Background()
	}
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if len(body) > MaxJobRecordBytes {
		return fmt.Errorf("job record exceeds durable size limit: %d > %d", len(body), MaxJobRecordBytes)
	}
	jobPath := s.jobPath(value.ID)
	operationPath := s.operationPath(value.OperationID)
	for _, path := range []string{jobPath, operationPath} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
	}
	if err := recordio.CheckShardQuotaContext(ctx, operationPath, int64(len(body)), MaxJobShardFiles, MaxJobShardBytes); err != nil {
		return fmt.Errorf("reserve job operation receipt durable shard quota: %w", err)
	}

	previousJob, previousJobErr := recordio.ReadFileLimit(jobPath, MaxJobRecordBytes)
	jobExisted := previousJobErr == nil
	if previousJobErr != nil && !errors.Is(previousJobErr, os.ErrNotExist) {
		return fmt.Errorf("read previous job before durable update: %w", previousJobErr)
	}

	if err := recordio.WriteFileShardQuotaContext(ctx, jobPath, body, 0o600, MaxJobShardFiles, MaxJobShardBytes); err != nil {
		return fmt.Errorf("write job within durable shard quota: %w", err)
	}
	if err := recordio.WriteFileShardQuotaContext(ctx, operationPath, body, 0o600, MaxJobShardFiles, MaxJobShardBytes); err != nil {
		var restoreErr error
		if jobExisted {
			restoreErr = recordio.WriteFile(jobPath, previousJob, 0o600)
		} else if removeErr := os.Remove(jobPath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			restoreErr = removeErr
		}
		return errors.Join(
			fmt.Errorf("write job operation receipt within durable shard quota: %w", err),
			restoreErr,
		)
	}
	_ = os.Remove(s.legacyJobPath(value.ID))
	_ = os.Remove(s.legacyOperationPath(value.OperationID))
	return nil
}

func (s *Store) loadOperation(operationID string) (Job, error) {
	body, err := recordio.ReadFileLimit(s.operationPath(operationID), MaxJobRecordBytes)
	if errors.Is(err, os.ErrNotExist) {
		body, err = recordio.ReadFileLimit(s.legacyOperationPath(operationID), MaxJobRecordBytes)
	}
	if err != nil {
		return Job{}, err
	}
	var value Job
	if err := json.Unmarshal(body, &value); err != nil {
		return Job{}, err
	}
	if value.OperationID != operationID {
		return Job{}, errors.New("job operation receipt identity mismatch")
	}
	return value, nil
}

func jobStorageKey(jobID string) string {
	sum := sha256.Sum256([]byte(jobID))
	return hex.EncodeToString(sum[:])
}

func (s *Store) jobPath(jobID string) string {
	key := jobStorageKey(jobID)
	return filepath.Join(s.root, "jobs", key[:2], key+".json")
}

func (s *Store) legacyJobPath(jobID string) string {
	return filepath.Join(s.root, "jobs", jobID+".json")
}

func operationFileKey(operationID string) string {
	if !strings.Contains(operationID, ":") {
		return operationID
	}
	sum := sha256.Sum256([]byte(operationID))
	return "op_" + hex.EncodeToString(sum[:16])
}

func operationStorageKey(operationID string) string {
	sum := sha256.Sum256([]byte(operationID))
	return hex.EncodeToString(sum[:])
}

func (s *Store) operationPath(operationID string) string {
	key := operationStorageKey(operationID)
	return filepath.Join(s.root, "operations", key[:2], key+".json")
}

func (s *Store) legacyOperationPath(operationID string) string {
	return filepath.Join(s.root, "operations", operationFileKey(operationID)+".json")
}

func (s *Store) operationLockPath(operationID string) string {
	key := operationStorageKey(operationID)
	return filepath.Join(s.root, "operations", "locks", key[:2], key+".lock")
}
