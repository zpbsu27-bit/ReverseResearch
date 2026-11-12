package server

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	researchcore "reverseresearch/internal/core"
	"reverseresearch/internal/rbac"
)

type collaborationApplyArgs struct {
	Operation        string `json:"operation"`
	CaseID           string `json:"case_id"`
	ExpectedRevision string `json:"expected_revision,omitempty"`
	Actor            string `json:"actor,omitempty"`
	Owner            string `json:"owner,omitempty"`
	Subject          string `json:"subject,omitempty"`
	Role             string `json:"role,omitempty"`
	FindingID        string `json:"finding_id,omitempty"`
	Title            string `json:"title,omitempty"`
	TaskID           string `json:"task_id,omitempty"`
	Status           string `json:"status,omitempty"`
	Body             string `json:"body,omitempty"`
	ObjectType       string `json:"object_type,omitempty"`
	ObjectID         string `json:"object_id,omitempty"`
	Kind             string `json:"kind,omitempty"`
	SubjectID        string `json:"subject_id,omitempty"`
	Decision         string `json:"decision,omitempty"`
	Notes            string `json:"notes,omitempty"`
	EvidenceID       string `json:"evidence_id,omitempty"`
	Reason           string `json:"reason,omitempty"`
}

type remoteAgentToolArgs struct {
	Operation           string `json:"operation"`
	AgentID             string `json:"agent_id,omitempty"`
	ManifestPath        string `json:"manifest_path,omitempty"`
	ExpectedRevision    string `json:"expected_revision,omitempty"`
	AuthorityRole       string `json:"authority_role,omitempty"`
	JobPath             string `json:"job_path,omitempty"`
	ResultPath          string `json:"result_path,omitempty"`
	Endpoint            string `json:"endpoint,omitempty"`
	ClientCertPath      string `json:"client_cert_path,omitempty"`
	ClientKeyPath       string `json:"client_key_path,omitempty"`
	ServerCAPath        string `json:"server_ca_path,omitempty"`
	TimeoutSeconds      int    `json:"timeout_seconds,omitempty"`
	StaleAfterSeconds   int    `json:"stale_after_seconds,omitempty"`
	OfflineAfterSeconds int    `json:"offline_after_seconds,omitempty"`
}

func (r *Runtime) addP3ProductTools() {
	r.addTool(&mcp.Tool{
		Name:        "report_render",
		Description: "Render a Case-revision-pinned report projection (JSON/Markdown/HTML/SARIF/STIX). Existing output replacement requires its current SHA-256. The report is a projection and does not become a second source of truth.",
		InputSchema: objectSchema(map[string]any{
			"case_id":                map[string]any{"type": "string", "minLength": 1},
			"profile":                map[string]any{"type": "string", "minLength": 1},
			"classification":         map[string]any{"type": "string"},
			"format":                 map[string]any{"type": "string", "enum": []string{"json", "markdown", "html", "sarif", "stix"}},
			"status":                 map[string]any{"type": "string", "enum": []string{"draft", "final"}},
			"sections":               map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"output_path":            map[string]any{"type": "string", "minLength": 1},
			"expected_output_sha256": map[string]any{"type": "string"},
		}, "case_id", "profile", "format", "output_path"),
	}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args researchcore.ReportRenderRequest
		if err := decodeArguments(req, &args); err != nil {
			return nil, err
		}
		value, err := r.core.RenderCaseReport(args)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "dashboard_render",
		Description: "Render a local read-only Case dashboard HTML projection with optional collaboration view. Existing output replacement requires its current SHA-256.",
		InputSchema: objectSchema(map[string]any{
			"case_id":                map[string]any{"type": "string", "minLength": 1},
			"profile":                map[string]any{"type": "string"},
			"classification":         map[string]any{"type": "string"},
			"actor":                  map[string]any{"type": "string"},
			"output_path":            map[string]any{"type": "string", "minLength": 1},
			"expected_output_sha256": map[string]any{"type": "string"},
		}, "case_id", "output_path"),
	}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args researchcore.DashboardRenderRequest
		if err := decodeArguments(req, &args); err != nil {
			return nil, err
		}
		value, err := r.core.RenderCaseDashboard(args)
		if err != nil {
			return nil, err
		}
		return structuredResult(value)
	})

	r.addTool(&mcp.Tool{
		Name:        "collaboration_get",
		Description: "Read the collaboration sidecar, revision-bound review queue, or audit history for a Case. Actor must be an active participant with case.read permission.",
		InputSchema: objectSchema(map[string]any{
			"case_id": map[string]any{"type": "string", "minLength": 1},
			"actor":   map[string]any{"type": "string", "minLength": 1},
			"view":    map[string]any{"type": "string", "enum": []string{"workspace", "review_queue", "history"}},
		}, "case_id", "actor"),
	}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			CaseID string `json:"case_id"`
			Actor  string `json:"actor"`
			View   string `json:"view,omitempty"`
		}
		if err := decodeArguments(req, &args); err != nil {
			return nil, err
		}
		switch strings.ToLower(strings.TrimSpace(args.View)) {
		case "", "workspace":
			value, err := r.core.GetCaseCollaboration(args.CaseID, args.Actor)
			if err != nil {
				return nil, err
			}
			return structuredResult(value)
		case "review_queue":
			value, err := r.core.GetCaseCollaborationReviewQueue(researchcore.CollaborationReviewQueueRequest{CaseID: args.CaseID, Actor: args.Actor})
			if err != nil {
				return nil, err
			}
			return structuredResult(value)
		case "history":
			value, err := r.core.GetCaseCollaborationHistory(researchcore.CollaborationHistoryRequest{CaseID: args.CaseID, Actor: args.Actor})
			if err != nil {
				return nil, err
			}
			return structuredResult(value)
		default:
			return nil, fmt.Errorf("unsupported collaboration view %q", args.View)
		}
	})

	r.addTool(&mcp.Tool{
		Name:        "collaboration_apply",
		Description: "Apply one typed collaboration mutation with optimistic revision checks and RBAC from the active participant role. Operations: init, add_participant, assign_finding, add_task, update_task, comment, review_request, approval, lock_evidence, unlock_evidence.",
		InputSchema: objectSchema(map[string]any{
			"operation":         map[string]any{"type": "string", "enum": []string{"init", "add_participant", "assign_finding", "add_task", "update_task", "comment", "review_request", "approval", "lock_evidence", "unlock_evidence"}},
			"case_id":           map[string]any{"type": "string", "minLength": 1},
			"expected_revision": map[string]any{"type": "string"},
			"actor":             map[string]any{"type": "string"},
			"owner":             map[string]any{"type": "string"},
			"subject":           map[string]any{"type": "string"},
			"role":              map[string]any{"type": "string"},
			"finding_id":        map[string]any{"type": "string"},
			"title":             map[string]any{"type": "string"},
			"task_id":           map[string]any{"type": "string"},
			"status":            map[string]any{"type": "string"},
			"body":              map[string]any{"type": "string"},
			"object_type":       map[string]any{"type": "string"},
			"object_id":         map[string]any{"type": "string"},
			"kind":              map[string]any{"type": "string"},
			"subject_id":        map[string]any{"type": "string"},
			"decision":          map[string]any{"type": "string"},
			"notes":             map[string]any{"type": "string"},
			"evidence_id":       map[string]any{"type": "string"},
			"reason":            map[string]any{"type": "string"},
		}, "operation", "case_id"),
	}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var a collaborationApplyArgs
		if err := decodeArguments(req, &a); err != nil {
			return nil, err
		}
		switch strings.ToLower(strings.TrimSpace(a.Operation)) {
		case "init":
			v, err := r.core.InitCaseCollaboration(researchcore.CollaborationInitRequest{CaseID: a.CaseID, Owner: a.Owner})
			if err != nil {
				return nil, err
			}
			return structuredResult(v)
		case "add_participant":
			v, err := r.core.AddCaseParticipant(researchcore.CollaborationParticipantRequest{CaseID: a.CaseID, ExpectedRevision: a.ExpectedRevision, Actor: a.Actor, Subject: a.Subject, Role: a.Role})
			if err != nil {
				return nil, err
			}
			return structuredResult(v)
		case "assign_finding":
			v, err := r.core.AssignCaseFindingOwner(researchcore.FindingOwnerRequest{CaseID: a.CaseID, ExpectedRevision: a.ExpectedRevision, Actor: a.Actor, FindingID: a.FindingID, Owner: a.Owner})
			if err != nil {
				return nil, err
			}
			return structuredResult(v)
		case "add_task":
			w, item, err := r.core.AddCaseCollaborationTask(researchcore.CollaborationTaskRequest{CaseID: a.CaseID, ExpectedRevision: a.ExpectedRevision, Actor: a.Actor, Title: a.Title, Owner: a.Owner})
			if err != nil {
				return nil, err
			}
			return structuredResult(map[string]any{"workspace": w, "task": item})
		case "update_task":
			v, err := r.core.UpdateCaseCollaborationTask(researchcore.CollaborationTaskUpdateRequest{CaseID: a.CaseID, ExpectedRevision: a.ExpectedRevision, Actor: a.Actor, TaskID: a.TaskID, Status: a.Status})
			if err != nil {
				return nil, err
			}
			return structuredResult(v)
		case "comment":
			w, item, err := r.core.AddCaseCollaborationComment(researchcore.CollaborationCommentRequest{CaseID: a.CaseID, ExpectedRevision: a.ExpectedRevision, Actor: a.Actor, Body: a.Body, ObjectType: a.ObjectType, ObjectID: a.ObjectID})
			if err != nil {
				return nil, err
			}
			return structuredResult(map[string]any{"workspace": w, "comment": item})
		case "review_request":
			w, item, err := r.core.RequestCaseCollaborationReview(researchcore.CollaborationReviewRequest{CaseID: a.CaseID, ExpectedRevision: a.ExpectedRevision, Actor: a.Actor, Kind: a.Kind, SubjectID: a.SubjectID})
			if err != nil {
				return nil, err
			}
			return structuredResult(map[string]any{"workspace": w, "review": item})
		case "approval":
			w, item, err := r.core.AddCaseCollaborationApproval(researchcore.CollaborationApprovalRequest{CaseID: a.CaseID, ExpectedRevision: a.ExpectedRevision, Actor: a.Actor, Kind: a.Kind, SubjectID: a.SubjectID, Decision: a.Decision, Notes: a.Notes})
			if err != nil {
				return nil, err
			}
			return structuredResult(map[string]any{"workspace": w, "approval": item})
		case "lock_evidence":
			v, err := r.core.LockCaseEvidence(researchcore.EvidenceLockRequest{CaseID: a.CaseID, ExpectedRevision: a.ExpectedRevision, Actor: a.Actor, EvidenceID: a.EvidenceID, Reason: a.Reason})
			if err != nil {
				return nil, err
			}
			return structuredResult(v)
		case "unlock_evidence":
			v, err := r.core.UnlockCaseEvidence(researchcore.EvidenceLockRequest{CaseID: a.CaseID, ExpectedRevision: a.ExpectedRevision, Actor: a.Actor, EvidenceID: a.EvidenceID})
			if err != nil {
				return nil, err
			}
			return structuredResult(v)
		default:
			return nil, fmt.Errorf("unsupported collaboration operation %q", a.Operation)
		}
	})

	r.addTool(&mcp.Tool{
		Name:        "rbac_check",
		Description: "Evaluate the built-in productization RBAC policy without mutating state.",
		InputSchema: objectSchema(map[string]any{
			"role":   map[string]any{"type": "string"},
			"action": map[string]any{"type": "string"},
		}, "role", "action"),
	}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var a struct {
			Role   string `json:"role"`
			Action string `json:"action"`
		}
		if err := decodeArguments(req, &a); err != nil {
			return nil, err
		}
		return structuredResult(rbac.Evaluate(rbac.Role(a.Role), rbac.Action(a.Action)))
	})

	r.addTool(&mcp.Tool{
		Name:        "remote_agent_manage",
		Description: "Register/list/get signed Remote Agent manifests, read authenticated fleet/status projections, refresh signed status over verified mTLS, validate bounded typed jobs, or verify signed results. This owner never executes jobs and explicitly has no arbitrary remote-shell capability.",
		InputSchema: objectSchema(map[string]any{
			"operation":             map[string]any{"type": "string", "enum": []string{"register", "list", "get", "status", "fleet", "refresh_status", "validate_job", "verify_result"}},
			"agent_id":              map[string]any{"type": "string"},
			"manifest_path":         map[string]any{"type": "string"},
			"expected_revision":     map[string]any{"type": "string"},
			"authority_role":        map[string]any{"type": "string"},
			"job_path":              map[string]any{"type": "string"},
			"result_path":           map[string]any{"type": "string"},
			"endpoint":              map[string]any{"type": "string"},
			"client_cert_path":      map[string]any{"type": "string"},
			"client_key_path":       map[string]any{"type": "string"},
			"server_ca_path":        map[string]any{"type": "string"},
			"timeout_seconds":       map[string]any{"type": "integer", "minimum": 1, "maximum": 30},
			"stale_after_seconds":   map[string]any{"type": "integer", "minimum": 1},
			"offline_after_seconds": map[string]any{"type": "integer", "minimum": 2},
		}, "operation"),
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var a remoteAgentToolArgs
		if err := decodeArguments(req, &a); err != nil {
			return nil, err
		}
		switch strings.ToLower(strings.TrimSpace(a.Operation)) {
		case "register":
			v, err := r.core.RegisterRemoteAgent(researchcore.RemoteAgentRegisterRequest{ManifestPath: a.ManifestPath, ExpectedRevision: a.ExpectedRevision, AuthorityRole: a.AuthorityRole})
			if err != nil {
				return nil, err
			}
			return structuredResult(v)
		case "list":
			v, err := r.core.ListRemoteAgents()
			if err != nil {
				return nil, err
			}
			return structuredResult(v)
		case "get":
			v, err := r.core.GetRemoteAgent(a.AgentID)
			if err != nil {
				return nil, err
			}
			return structuredResult(v)
		case "status":
			v, err := r.core.GetRemoteAgentStatus(a.AgentID)
			if err != nil {
				return nil, err
			}
			return structuredResult(v)
		case "fleet":
			v, err := r.core.ListRemoteAgentFleet(researchcore.RemoteAgentFleetRequest{
				StaleAfterSeconds: a.StaleAfterSeconds, OfflineAfterSeconds: a.OfflineAfterSeconds,
			})
			if err != nil {
				return nil, err
			}
			return structuredResult(v)
		case "refresh_status":
			v, err := r.core.RefreshRemoteAgentStatusContext(ctx, researchcore.RemoteAgentStatusRefreshRequest{
				AgentID: a.AgentID, Endpoint: a.Endpoint,
				ClientCertPath: a.ClientCertPath, ClientKeyPath: a.ClientKeyPath, ServerCAPath: a.ServerCAPath,
				ExpectedRevision: a.ExpectedRevision, AuthorityRole: a.AuthorityRole, TimeoutSeconds: a.TimeoutSeconds,
			})
			if err != nil {
				return nil, err
			}
			return structuredResult(v)
		case "validate_job":
			v, err := r.core.ValidateRemoteAgentJob(researchcore.RemoteJobValidationRequest{AgentID: a.AgentID, JobPath: a.JobPath})
			if err != nil {
				return nil, err
			}
			return structuredResult(v)
		case "verify_result":
			v, err := r.core.VerifyRemoteAgentResult(researchcore.RemoteResultVerificationRequest{AgentID: a.AgentID, ResultPath: a.ResultPath})
			if err != nil {
				return nil, err
			}
			return structuredResult(v)
		default:
			return nil, errors.New("unsupported remote-agent operation")
		}
	})

	r.addTool(&mcp.Tool{
		Name:        "pack_verify",
		Description: "Verify a signed Skill/Domain/Knowledge/Plugin pack against an explicit trust store and exact file SHA-256 values. Verification does not load or execute plugin code.",
		InputSchema: objectSchema(map[string]any{
			"root":          map[string]any{"type": "string", "minLength": 1},
			"manifest_path": map[string]any{"type": "string", "minLength": 1},
			"trust_path":    map[string]any{"type": "string", "minLength": 1},
		}, "root", "manifest_path", "trust_path"),
	}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var a researchcore.PackVerificationRequest
		if err := decodeArguments(req, &a); err != nil {
			return nil, err
		}
		v, err := r.core.VerifySignedPack(a)
		if err != nil {
			return nil, err
		}
		return structuredResult(v)
	})

	r.addTool(&mcp.Tool{
		Name:        "pack_registry",
		Description: "Manage signed pack trust, verification, data-only activation, quarantine, rollback, and current active entrypoint reads. Executable plugin code is never loaded in-process.",
		InputSchema: objectSchema(map[string]any{
			"operation":         map[string]any{"type": "string", "enum": []string{"get", "trust_add", "trust_remove", "verify", "activate", "quarantine", "rollback", "active", "read_entrypoint"}},
			"authority_role":    map[string]any{"type": "string"},
			"expected_revision": map[string]any{"type": "string"},
			"key_id":            map[string]any{"type": "string"},
			"public_key":        map[string]any{"type": "string"},
			"publisher":         map[string]any{"type": "string"},
			"root":              map[string]any{"type": "string"},
			"manifest_path":     map[string]any{"type": "string"},
			"receipt_id":        map[string]any{"type": "string"},
			"pack_id":           map[string]any{"type": "string"},
			"target_receipt_id": map[string]any{"type": "string"},
			"reason":            map[string]any{"type": "string"},
			"entrypoint":        map[string]any{"type": "string"},
			"max_bytes":         map[string]any{"type": "integer", "minimum": 1, "maximum": 4194304},
			"include_archived":  map[string]any{"type": "boolean", "description": "For operation=get only. Default false keeps reads bounded to hot registry state; true explicitly hydrates cold history."},
		}, "operation", "authority_role"),
	}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var a struct {
			Operation        string `json:"operation"`
			AuthorityRole    string `json:"authority_role"`
			ExpectedRevision string `json:"expected_revision,omitempty"`
			KeyID            string `json:"key_id,omitempty"`
			PublicKey        string `json:"public_key,omitempty"`
			Publisher        string `json:"publisher,omitempty"`
			Root             string `json:"root,omitempty"`
			ManifestPath     string `json:"manifest_path,omitempty"`
			ReceiptID        string `json:"receipt_id,omitempty"`
			PackID           string `json:"pack_id,omitempty"`
			TargetReceiptID  string `json:"target_receipt_id,omitempty"`
			Reason           string `json:"reason,omitempty"`
			Entrypoint       string `json:"entrypoint,omitempty"`
			MaxBytes         int    `json:"max_bytes,omitempty"`
			IncludeArchived  bool   `json:"include_archived,omitempty"`
		}
		if err := decodeArguments(req, &a); err != nil {
			return nil, err
		}
		switch strings.ToLower(strings.TrimSpace(a.Operation)) {
		case "get":
			v, err := r.core.GetPackRegistry(researchcore.PackRegistryGetRequest{AuthorityRole: a.AuthorityRole, IncludeArchived: a.IncludeArchived})
			if err != nil {
				return nil, err
			}
			return structuredResult(v)
		case "trust_add":
			v, err := r.core.TrustPackPublisher(researchcore.PackRegistryTrustRequest{AuthorityRole: a.AuthorityRole, ExpectedRevision: a.ExpectedRevision, KeyID: a.KeyID, PublicKey: a.PublicKey, Publisher: a.Publisher})
			if err != nil {
				return nil, err
			}
			return structuredResult(v)
		case "trust_remove":
			v, err := r.core.RemoveTrustedPackPublisher(researchcore.PackRegistryRemoveRequest{AuthorityRole: a.AuthorityRole, ExpectedRevision: a.ExpectedRevision, KeyID: a.KeyID})
			if err != nil {
				return nil, err
			}
			return structuredResult(v)
		case "verify":
			v, err := r.core.VerifyAndRecordPack(researchcore.PackRegistryVerifyRequest{AuthorityRole: a.AuthorityRole, ExpectedRevision: a.ExpectedRevision, Root: a.Root, ManifestPath: a.ManifestPath})
			if err != nil {
				return nil, err
			}
			return structuredResult(v)
		case "activate":
			state, record, err := r.core.ActivateVerifiedPack(researchcore.PackLifecycleRequest{AuthorityRole: a.AuthorityRole, ExpectedRevision: a.ExpectedRevision, ReceiptID: a.ReceiptID})
			if err != nil {
				return nil, err
			}
			return structuredResult(map[string]any{"state": state, "pack": record})
		case "quarantine":
			state, record, err := r.core.QuarantineVerifiedPack(researchcore.PackLifecycleRequest{AuthorityRole: a.AuthorityRole, ExpectedRevision: a.ExpectedRevision, ReceiptID: a.ReceiptID, Reason: a.Reason})
			if err != nil {
				return nil, err
			}
			return structuredResult(map[string]any{"state": state, "pack": record})
		case "rollback":
			state, record, err := r.core.RollbackVerifiedPack(researchcore.PackLifecycleRequest{AuthorityRole: a.AuthorityRole, ExpectedRevision: a.ExpectedRevision, PackID: a.PackID, TargetReceiptID: a.TargetReceiptID})
			if err != nil {
				return nil, err
			}
			return structuredResult(map[string]any{"state": state, "pack": record})
		case "active":
			state, record, err := r.core.GetActivePack(researchcore.PackActiveRequest{AuthorityRole: a.AuthorityRole, PackID: a.PackID})
			if err != nil {
				return nil, err
			}
			return structuredResult(map[string]any{"state": state, "pack": record})
		case "read_entrypoint":
			v, err := r.core.ReadActivePackEntrypoint(researchcore.PackEntrypointReadRequest{AuthorityRole: a.AuthorityRole, PackID: a.PackID, Entrypoint: a.Entrypoint, MaxBytes: a.MaxBytes})
			if err != nil {
				return nil, err
			}
			return structuredResult(v)
		default:
			return nil, fmt.Errorf("unsupported pack-registry operation %q", a.Operation)
		}
	})
}
