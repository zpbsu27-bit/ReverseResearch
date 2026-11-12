package core

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"reverseresearch/internal/capability"
	"reverseresearch/internal/casebook"
	"reverseresearch/internal/compatibility"
	"reverseresearch/internal/die"
	"reverseresearch/internal/engagement"
	"reverseresearch/internal/hookplan"
	"reverseresearch/internal/job"
	"reverseresearch/internal/knowledge"
	"reverseresearch/internal/patchplan"
	"reverseresearch/internal/processcontrol"
	"reverseresearch/internal/provision"
	"reverseresearch/internal/router"
	"reverseresearch/internal/sandbox"
	"reverseresearch/internal/securefile"
	"reverseresearch/internal/statecompat"
	"reverseresearch/internal/targetidentity"
	"reverseresearch/internal/toolindex"
	"reverseresearch/internal/webinspect"
)

type Service struct {
	root        string
	patcher     *patchplan.Manager
	hooks       *hookplan.Manager
	cases       *casebook.Store
	compat      *compatibility.Store
	knowledge   *knowledge.Store
	processes   *processcontrol.LeaseStore
	detector    *die.Adapter
	engagements *engagement.Store
	jobs        *job.Store
}

func New(root string) (*Service, error) {
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	stateRoot := filepath.Join(absolute, "state")
	if err := os.MkdirAll(stateRoot, 0o700); err != nil {
		return nil, err
	}
	if err := securefile.RestrictDir(stateRoot); err != nil {
		return nil, fmt.Errorf("restrict private state root: %w", err)
	}
	if _, err := statecompat.Ensure(absolute); err != nil {
		return nil, fmt.Errorf("state layout compatibility: %w", err)
	}
	evidenceRoot := filepath.Join(absolute, "evidence")
	if err := os.MkdirAll(evidenceRoot, 0o700); err != nil {
		return nil, err
	}
	if err := securefile.RestrictDir(evidenceRoot); err != nil {
		return nil, fmt.Errorf("restrict private evidence root: %w", err)
	}
	patcher, err := patchplan.New(filepath.Join(absolute, "state", "patches"))
	if err != nil {
		return nil, err
	}
	hooks, err := hookplan.New(absolute, filepath.Join(absolute, "state", "hooks"))
	if err != nil {
		return nil, err
	}
	researchRoot := filepath.Join(absolute, "state", "research")
	cases, err := casebook.New(researchRoot)
	if err != nil {
		return nil, err
	}
	engagements, err := engagement.New(researchRoot)
	if err != nil {
		return nil, err
	}
	jobs, err := job.New(filepath.Join(absolute, "state", "jobs"), engagements)
	if err != nil {
		return nil, err
	}
	compatStore, err := compatibility.New(filepath.Join(absolute, "state", "compatibility"), hooks, cases)
	if err != nil {
		return nil, err
	}
	knowledgeStore, err := knowledge.New(filepath.Join(absolute, "state", "knowledge"))
	if err != nil {
		return nil, err
	}
	processes, err := processcontrol.NewLeaseStore(filepath.Join(absolute, "state", "process-control"))
	if err != nil {
		return nil, err
	}
	return &Service{root: absolute, patcher: patcher, hooks: hooks, cases: cases, compat: compatStore, knowledge: knowledgeStore, processes: processes, detector: die.New(absolute), engagements: engagements, jobs: jobs}, nil
}

func (s *Service) Root() string {
	return s.root
}

func (s *Service) Identify(path string) (targetidentity.Identity, error) {
	return s.IdentifyContext(context.Background(), path)
}

func (s *Service) IdentifyContext(ctx context.Context, path string) (targetidentity.Identity, error) {
	return targetidentity.InspectContext(ctx, path)
}

func (s *Service) Compare(leftPath, rightPath string) (targetidentity.Comparison, error) {
	return s.CompareContext(context.Background(), leftPath, rightPath)
}

func (s *Service) CompareContext(ctx context.Context, leftPath, rightPath string) (targetidentity.Comparison, error) {
	return targetidentity.CompareContext(ctx, leftPath, rightPath)
}

func (s *Service) ScanDIE(ctx context.Context, path string, options die.ScanOptions) (die.Report, error) {
	return s.detector.Scan(ctx, path, options)
}

func (s *Service) InspectProcess(pid uint32) (processcontrol.Identity, error) {
	return processcontrol.Inspect(pid)
}

func (s *Service) AcquireProcessControl(pid uint32, processKey, owner string) (processcontrol.Lease, error) {
	current, err := processcontrol.Inspect(pid)
	if err != nil {
		return processcontrol.Lease{}, err
	}
	processKey = strings.TrimSpace(processKey)
	if processKey == "" || current.Key != processKey {
		return processcontrol.Lease{}, fmt.Errorf("%w: expected key %q current %q", processcontrol.ErrProcessChanged, processKey, current.Key)
	}
	return s.processes.Acquire(processcontrol.AcquireRequest{Expected: current, Owner: owner})
}

func (s *Service) GetProcessControl(pid uint32) (processcontrol.Lease, error) {
	return s.processes.Get(pid)
}

func (s *Service) ReleaseProcessControl(pid uint32, processKey, owner, leaseID string) error {
	return s.processes.Release(processcontrol.ReleaseRequest{
		PID: pid, ProcessKey: strings.TrimSpace(processKey), Owner: owner, LeaseID: strings.TrimSpace(leaseID),
	})
}

func (s *Service) PlanHook(ctx context.Context, request hookplan.PlanRequest) (hookplan.Hook, error) {
	return s.hooks.Plan(ctx, request)
}

func (s *Service) GetHook(hookID string) (hookplan.Hook, error) {
	return s.hooks.Get(hookID)
}

func (s *Service) ListHooks(path string) ([]hookplan.Hook, error) {
	return s.hooks.List(path)
}

func (s *Service) ApplyHook(request hookplan.ApplyRequest) (hookplan.Hook, error) {
	return s.hooks.Apply(request)
}

func (s *Service) VerifyHook(hookID string) (hookplan.VerifyResult, error) {
	return s.hooks.Verify(hookID)
}

func (s *Service) RollbackHook(request hookplan.RollbackRequest) (hookplan.Hook, error) {
	return s.hooks.Rollback(request)
}

func (s *Service) CancelHook(request hookplan.CancelRequest) (hookplan.Hook, error) {
	return s.hooks.Cancel(request)
}

func (s *Service) AddCompatibility(request compatibility.AddRequest) (compatibility.Record, error) {
	return s.AddCompatibilityContext(context.Background(), request)
}

func (s *Service) AddCompatibilityContext(ctx context.Context, request compatibility.AddRequest) (compatibility.Record, error) {
	return s.compat.AddContext(ctx, request)
}

func (s *Service) ImportCompatibilityManifest(path string) (compatibility.ImportResult, error) {
	return s.ImportCompatibilityManifestContext(context.Background(), path)
}

func (s *Service) ImportCompatibilityManifestContext(ctx context.Context, path string) (compatibility.ImportResult, error) {
	return s.compat.ImportManifestContext(ctx, path)
}

func (s *Service) GetCompatibility(recordID string) (compatibility.Record, error) {
	return s.compat.Get(recordID)
}

func (s *Service) ListCompatibility(filter compatibility.Filter) ([]compatibility.Record, error) {
	return s.compat.List(filter)
}

func (s *Service) VerifyCompatibility(recordID string) (compatibility.Verification, error) {
	return s.VerifyCompatibilityContext(context.Background(), recordID)
}

func (s *Service) VerifyCompatibilityContext(ctx context.Context, recordID string) (compatibility.Verification, error) {
	return s.compat.VerifyContext(ctx, recordID)
}

func (s *Service) PlanPatch(request patchplan.PlanRequest) (patchplan.Plan, error) {
	return s.patcher.Plan(request)
}

func (s *Service) GetPatch(planID string) (patchplan.Plan, error) {
	return s.patcher.Get(planID)
}

func (s *Service) DryRunPatch(planID string) (patchplan.DryRunResult, error) {
	return s.patcher.DryRun(planID)
}

func (s *Service) ApplyPatch(request patchplan.ApplyRequest) (patchplan.Plan, error) {
	return s.patcher.Apply(request)
}

func (s *Service) VerifyPatch(planID string) (patchplan.VerifyResult, error) {
	return s.patcher.Verify(planID)
}

func (s *Service) RollbackPatch(planID string) (patchplan.Plan, error) {
	return s.patcher.Rollback(planID)
}

func (s *Service) RollbackPatchOperation(request patchplan.RollbackRequest) (patchplan.Plan, error) {
	return s.patcher.RollbackOperation(request)
}

func (s *Service) Route(text string) (router.Result, error) {
	engine, err := router.Load(filepath.Join(s.root, "config", "routes.json"))
	if err != nil {
		return router.Result{}, err
	}
	return engine.Route(text), nil
}

func (s *Service) ScanTools() (toolindex.Index, error) {
	index, err := toolindex.Scan(s.root)
	if err != nil {
		return toolindex.Index{}, err
	}
	if err := toolindex.Save(filepath.Join(s.root, "state", "tool-index.json"), index); err != nil {
		return toolindex.Index{}, err
	}
	return index, nil
}

func (s *Service) LoadToolIndex() (toolindex.Index, error) {
	return toolindex.Load(filepath.Join(s.root, "state", "tool-index.json"))
}

func (s *Service) WebBackends() (webinspect.BackendStatus, error) {
	index, err := s.ScanTools()
	if err != nil {
		return webinspect.BackendStatus{}, err
	}
	return webinspect.Backends(index), nil
}

func (s *Service) PrepareWebProfile(profileID, browser string) (webinspect.ProfilePlan, error) {
	index, err := s.ScanTools()
	if err != nil {
		return webinspect.ProfilePlan{}, err
	}
	return webinspect.PrepareProfile(s.root, profileID, browser, index)
}

func (s *Service) InspectWebCDP(ctx context.Context, endpoint string, timeout time.Duration) (webinspect.CDPReport, error) {
	return webinspect.InspectCDP(ctx, endpoint, timeout)
}

func (s *Service) AnalyzeWebSource(path string) (webinspect.SourceReport, error) {
	return webinspect.AnalyzeSource(path)
}

func (s *Service) ReadWebSourceMap(path string, options webinspect.SourceMapReadOptions) (webinspect.SourceMapReadReport, error) {
	return webinspect.ReadSourceMap(path, options)
}

func (s *Service) InspectWebHAR(path string, options webinspect.HAROptions) (webinspect.HARReport, error) {
	return webinspect.InspectHAR(path, options)
}

func (s *Service) InspectWebSSE(path string, options webinspect.SSEOptions) (webinspect.SSEReport, error) {
	return webinspect.InspectSSE(path, options)
}

func (s *Service) InspectWebWASM(path string) (webinspect.WASMReport, error) {
	return webinspect.InspectWASM(path)
}

func (s *Service) InspectWebWASMWithOptions(ctx context.Context, path string, options webinspect.WASMOptions) (webinspect.WASMReport, error) {
	return webinspect.InspectWASMWithOptions(ctx, s.root, path, options)
}

func (s *Service) CapabilityStatus(routeID string) (capability.Status, error) {
	evaluator, err := s.capabilityEvaluator()
	if err != nil {
		return capability.Status{}, err
	}
	return evaluator.Route(routeID)
}

func (s *Service) CapabilityStatuses() ([]capability.Status, error) {
	evaluator, err := s.capabilityEvaluator()
	if err != nil {
		return nil, err
	}
	return evaluator.All(), nil
}

func (s *Service) capabilityEvaluator() (*capability.Evaluator, error) {
	engine, err := router.Load(filepath.Join(s.root, "config", "routes.json"))
	if err != nil {
		return nil, err
	}
	index, err := s.ScanTools()
	if err != nil {
		return nil, err
	}
	manifest, err := provision.LoadManifest(filepath.Join(s.root, "config", "tool-recipes.json"))
	if err != nil {
		return nil, err
	}
	return capability.New(engine.Routes(), index, manifest), nil
}

func (s *Service) PlanTools(names []string) (provision.Plan, error) {
	index, err := s.ScanTools()
	if err != nil {
		return provision.Plan{}, err
	}
	manifest, err := provision.LoadManifest(filepath.Join(s.root, "config", "tool-recipes.json"))
	if err != nil {
		return provision.Plan{}, err
	}
	return provision.NewPlanner(manifest, index).Plan(names)
}

func (s *Service) PlanSandbox(request sandbox.PlanRequest) (sandbox.Plan, error) {
	index, err := s.ScanTools()
	if err != nil {
		return sandbox.Plan{}, err
	}
	manager, err := sandbox.New(filepath.Join(s.root, "state"), index)
	if err != nil {
		return sandbox.Plan{}, err
	}
	return manager.Plan(request)
}

func (s *Service) CreateSandbox(plan sandbox.Plan) (sandbox.Plan, error) {
	index, err := s.ScanTools()
	if err != nil {
		return sandbox.Plan{}, err
	}
	manager, err := sandbox.New(filepath.Join(s.root, "state"), index)
	if err != nil {
		return sandbox.Plan{}, err
	}
	return manager.Create(plan)
}

func (s *Service) CreateCase(request casebook.CreateRequest) (casebook.Case, error) {
	return s.cases.Create(request)
}

func (s *Service) GetCase(caseID string) (casebook.Case, error) {
	return s.cases.Get(caseID)
}

func (s *Service) AddCaseEvidence(caseID string, request casebook.EvidenceRequest) (casebook.Evidence, error) {
	return s.cases.AddEvidence(caseID, request)
}

func (s *Service) AddCaseFinding(caseID string, request casebook.FindingRequest) (casebook.Finding, error) {
	return s.cases.AddFinding(caseID, request)
}

func (s *Service) AddCasePath(caseID string, request casebook.PathRequest) (casebook.ResearchPath, error) {
	return s.cases.AddPath(caseID, request)
}

func (s *Service) AddKnowledge(request knowledge.AddRequest) (knowledge.Note, error) {
	return s.knowledge.Add(request)
}

func (s *Service) SearchKnowledge(query string, limit int) ([]knowledge.SearchResult, error) {
	return s.knowledge.Search(query, limit)
}

func (s *Service) SearchKnowledgeFiltered(request knowledge.SearchRequest) ([]knowledge.SearchResult, error) {
	return s.knowledge.SearchFiltered(request)
}

func (s *Service) CreateEngagement(request engagement.CreateRequest) (engagement.Engagement, error) {
	return s.engagements.Create(request)
}

func (s *Service) GetEngagement(id string) (engagement.Engagement, error) {
	return s.engagements.Get(id)
}

func (s *Service) AuthorizeEngagement(id, target, action string, at time.Time) (engagement.Decision, error) {
	return s.engagements.Authorize(id, target, action, at)
}

func (s *Service) AuthorizeEngagementEffect(id, target, action, effectClass string, at time.Time) (engagement.Decision, error) {
	return s.engagements.AuthorizeEffect(id, target, action, effectClass, at)
}

func (s *Service) PlanJob(request job.PlanRequest) (job.Job, error) {
	return s.PlanJobContext(context.Background(), request)
}

func (s *Service) PlanJobContext(ctx context.Context, request job.PlanRequest) (job.Job, error) {
	return s.jobs.PlanContext(ctx, request)
}

func (s *Service) PrepareJob(jobID, operationID string) (job.Job, error) {
	return s.PrepareJobContext(context.Background(), jobID, operationID)
}

func (s *Service) PrepareJobContext(ctx context.Context, jobID, operationID string) (job.Job, error) {
	return s.jobs.PrepareContext(ctx, jobID, operationID)
}

func (s *Service) GetJob(jobID string) (job.Job, error) {
	return s.jobs.Get(jobID)
}

func (s *Service) TransitionJob(request job.TransitionRequest) (job.Job, error) {
	return s.TransitionJobContext(context.Background(), request)
}

func (s *Service) TransitionJobContext(ctx context.Context, request job.TransitionRequest) (job.Job, error) {
	return s.jobs.TransitionContext(ctx, request)
}
