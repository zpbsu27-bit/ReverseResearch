package core

import (
	"reverseresearch/internal/casebook"
	"reverseresearch/internal/knowledge"
)

func (s *Service) ListCases(limit int) ([]casebook.Case, error) {
	return s.cases.List(limit)
}

func (s *Service) VerifyCase(id string) (casebook.Verification, error) {
	return s.cases.Verify(id)
}

func (s *Service) CaseResearchView(id string, o casebook.ResearchViewOptions) (casebook.ResearchView, error) {
	return s.cases.ResearchView(id, o)
}

func (s *Service) GetKnowledge(id string) (knowledge.Note, error) {
	return s.knowledge.Get(id)
}

func (s *Service) ReadKnowledge(request knowledge.ReadRequest) (knowledge.Excerpt, error) {
	return s.knowledge.Read(request)
}
