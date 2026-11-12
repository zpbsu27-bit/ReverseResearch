package core

import "reverseresearch/internal/casebook"

func (s *Service) AddCaseHypothesis(caseID string, request casebook.HypothesisRequest) (casebook.Hypothesis, error) {
	return s.cases.AddHypothesis(caseID, request)
}

func (s *Service) UpdateCaseHypothesis(caseID, hypothesisID string, request casebook.HypothesisUpdateRequest) (casebook.Hypothesis, error) {
	return s.cases.UpdateHypothesis(caseID, hypothesisID, request)
}

func (s *Service) AddCaseDetection(caseID string, request casebook.DetectionRequest) (casebook.Detection, error) {
	return s.cases.AddDetection(caseID, request)
}

func (s *Service) AddCaseRetest(caseID string, request casebook.RetestRequest) (casebook.Retest, error) {
	return s.cases.AddRetest(caseID, request)
}

func (s *Service) AddCaseArtifact(caseID string, request casebook.ArtifactRequest) (casebook.Artifact, error) {
	return s.cases.AddArtifact(caseID, request)
}

func (s *Service) AddCaseObservation(caseID string, request casebook.ObservationRequest) (casebook.Observation, error) {
	return s.cases.AddObservation(caseID, request)
}

func (s *Service) AddCaseVulnerability(caseID string, request casebook.VulnerabilityRequest) (casebook.Vulnerability, error) {
	return s.cases.AddVulnerability(caseID, request)
}

func (s *Service) AddCaseIOC(caseID string, request casebook.IOCRequest) (casebook.IOC, error) {
	return s.cases.AddIOC(caseID, request)
}

func (s *Service) AddCaseTTP(caseID string, request casebook.TTPRequest) (casebook.TTP, error) {
	return s.cases.AddTTP(caseID, request)
}

func (s *Service) AddCaseMitigation(caseID string, request casebook.MitigationRequest) (casebook.Mitigation, error) {
	return s.cases.AddMitigation(caseID, request)
}

func (s *Service) AddCaseReport(caseID string, request casebook.ReportRequest) (casebook.Report, error) {
	return s.cases.AddReport(caseID, request)
}

func (s *Service) AssignCaseRole(caseID string, request casebook.RoleAssignmentRequest) (casebook.RoleAssignment, error) {
	return s.cases.AssignRole(caseID, request)
}

func (s *Service) AddCaseWorkItem(caseID string, request casebook.WorkItemRequest) (casebook.WorkItem, error) {
	return s.cases.AddWorkItem(caseID, request)
}

func (s *Service) UpdateCaseWorkItem(caseID, workItemID string, request casebook.WorkItemUpdateRequest) (casebook.WorkItem, error) {
	return s.cases.UpdateWorkItem(caseID, workItemID, request)
}

func (s *Service) AddCaseTimeline(caseID string, request casebook.TimelineRequest) (casebook.TimelineEntry, error) {
	return s.cases.AddTimeline(caseID, request)
}

func (s *Service) ReviewCase(caseID string) (casebook.Review, error) {
	return s.cases.Review(caseID)
}
