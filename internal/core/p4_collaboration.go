package core

import (
	"errors"
	"fmt"
	"strings"

	"reverseresearch/internal/casebook"
	"reverseresearch/internal/collaboration"
	"reverseresearch/internal/rbac"
)

type CollaborationReviewRequest struct {
	CaseID           string `json:"case_id"`
	ExpectedRevision string `json:"expected_revision"`
	Actor            string `json:"actor"`
	Kind             string `json:"kind"`
	SubjectID        string `json:"subject_id"`
}

type CollaborationReviewQueueRequest struct {
	CaseID string `json:"case_id"`
	Actor  string `json:"actor"`
}

type CollaborationHistoryRequest struct {
	CaseID string `json:"case_id"`
	Actor  string `json:"actor"`
}

func (s *Service) RequestCaseCollaborationReview(request CollaborationReviewRequest) (collaboration.Workspace, collaboration.ReviewRequest, error) {
	store, _, err := s.authorizeCollaboration(request.CaseID, request.Actor, rbac.ActionTaskWrite)
	if err != nil {
		return collaboration.Workspace{}, collaboration.ReviewRequest{}, err
	}
	c, caseRevision, err := s.cases.Snapshot(request.CaseID)
	if err != nil {
		return collaboration.Workspace{}, collaboration.ReviewRequest{}, err
	}
	kind := strings.ToLower(strings.TrimSpace(request.Kind))
	subjectID := strings.TrimSpace(request.SubjectID)
	if err := validateReviewSubject(c, kind, subjectID); err != nil {
		return collaboration.Workspace{}, collaboration.ReviewRequest{}, err
	}
	return store.RequestReview(request.CaseID, request.ExpectedRevision, request.Actor, kind, subjectID, caseRevision)
}

func (s *Service) GetCaseCollaborationReviewQueue(request CollaborationReviewQueueRequest) ([]collaboration.ReviewQueueItem, error) {
	store, _, err := s.authorizeCollaboration(request.CaseID, request.Actor, rbac.ActionCaseRead)
	if err != nil {
		return nil, err
	}
	_, caseRevision, err := s.cases.Snapshot(request.CaseID)
	if err != nil {
		return nil, err
	}
	return store.ReviewQueue(request.CaseID, caseRevision)
}

func (s *Service) GetCaseCollaborationHistory(request CollaborationHistoryRequest) ([]collaboration.HistoryEvent, error) {
	store, _, err := s.authorizeCollaboration(request.CaseID, request.Actor, rbac.ActionCaseRead)
	if err != nil {
		return nil, err
	}
	return store.History(request.CaseID)
}

func validateReviewSubject(c casebook.Case, kind, subjectID string) error {
	if kind == "" || subjectID == "" {
		return errors.New("review kind and subject_id are required")
	}
	switch kind {
	case "case":
		if subjectID != c.ID {
			return fmt.Errorf("review case subject must equal case id %q", c.ID)
		}
	case "finding":
		if !caseHasFinding(c, subjectID) {
			return fmt.Errorf("unknown finding id %q", subjectID)
		}
	case "evidence":
		if !caseHasEvidence(c, subjectID) {
			return fmt.Errorf("unknown evidence id %q", subjectID)
		}
	case "report":
		for _, report := range c.Reports {
			if report.ID == subjectID {
				return nil
			}
		}
		return fmt.Errorf("unknown report id %q", subjectID)
	default:
		return fmt.Errorf("unsupported review kind %q", kind)
	}
	return nil
}
