package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	researchcore "reverseresearch/internal/core"
	"reverseresearch/internal/rbac"
)

type stringListFlag []string

func (v *stringListFlag) String() string {
	return strings.Join(*v, ",")
}

func (v *stringListFlag) Set(value string) error {
	*v = append(*v, value)
	return nil
}

func runReportCLI(service *researchcore.Service, args []string, stdout, stderr io.Writer) error {
	if len(args) < 2 || args[0] != "render" {
		return errors.New("usage: ReverseResearch report render <case-id> --profile <profile> --format <json|markdown|html|sarif|stix> --out <path> [--section <name[,name...]>]... [--classification <text>] [--status draft|final] [--expected-output-sha <sha256>]")
	}
	flags := flag.NewFlagSet("report render", flag.ContinueOnError)
	flags.SetOutput(stderr)
	req := researchcore.ReportRenderRequest{CaseID: args[1]}
	var sections stringListFlag
	flags.StringVar(&req.Profile, "profile", "general", "report profile")
	flags.StringVar(&req.Classification, "classification", "internal", "report classification")
	flags.StringVar(&req.Format, "format", "json", "json|markdown|html|sarif|stix")
	flags.StringVar(&req.Status, "status", "draft", "draft|final")
	flags.Var(&sections, "section", "report section; repeatable or comma-separated")
	flags.StringVar(&req.OutputPath, "out", "", "output path")
	flags.StringVar(&req.ExpectedOutputSHA256, "expected-output-sha", "", "required current SHA-256 when replacing an existing output")
	if err := flags.Parse(args[2:]); err != nil {
		return err
	}
	req.Sections = []string(sections)
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected report arguments: %s", strings.Join(flags.Args(), " "))
	}
	if strings.TrimSpace(req.OutputPath) == "" {
		return errors.New("report render requires --out")
	}
	value, err := service.RenderCaseReport(req)
	if err != nil {
		return err
	}
	return writeJSON(stdout, value)
}

func runDashboardCLI(service *researchcore.Service, args []string, stdout, stderr io.Writer) error {
	if len(args) < 2 || args[0] != "render" {
		return errors.New("usage: ReverseResearch dashboard render <case-id> --out <dashboard.html> [--actor <participant>] [--profile <profile>] [--classification <text>] [--expected-output-sha <sha256>]")
	}
	flags := flag.NewFlagSet("dashboard render", flag.ContinueOnError)
	flags.SetOutput(stderr)
	req := researchcore.DashboardRenderRequest{CaseID: args[1]}
	flags.StringVar(&req.OutputPath, "out", "", "dashboard HTML output")
	flags.StringVar(&req.Actor, "actor", "", "optional active participant to include collaboration view")
	flags.StringVar(&req.Profile, "profile", "general", "report/dashboard profile")
	flags.StringVar(&req.Classification, "classification", "internal", "classification")
	flags.StringVar(&req.ExpectedOutputSHA256, "expected-output-sha", "", "required current SHA-256 when replacing an existing output")
	if err := flags.Parse(args[2:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected dashboard arguments: %s", strings.Join(flags.Args(), " "))
	}
	if strings.TrimSpace(req.OutputPath) == "" {
		return errors.New("dashboard render requires --out")
	}
	value, err := service.RenderCaseDashboard(req)
	if err != nil {
		return err
	}
	return writeJSON(stdout, value)
}

func runCollaborationCLI(service *researchcore.Service, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("collab subcommand required: init|get|participant|assign-finding|task-add|task-update|comment|review-request|review-queue|history|approve|lock|unlock")
	}
	switch args[0] {
	case "init":
		if len(args) < 2 {
			return errors.New("usage: ReverseResearch collab init <case-id> --owner <subject>")
		}
		flags := flag.NewFlagSet("collab init", flag.ContinueOnError)
		flags.SetOutput(stderr)
		req := researchcore.CollaborationInitRequest{CaseID: args[1]}
		flags.StringVar(&req.Owner, "owner", "", "case owner subject")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected collab init arguments")
		}
		value, err := service.InitCaseCollaboration(req)
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	case "get":
		if len(args) < 2 {
			return errors.New("usage: ReverseResearch collab get <case-id> --actor <subject>")
		}
		flags := flag.NewFlagSet("collab get", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var actor string
		flags.StringVar(&actor, "actor", "", "active participant")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected collab get arguments")
		}
		value, err := service.GetCaseCollaboration(args[1], actor)
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	case "participant":
		if len(args) < 2 {
			return errors.New("usage: ReverseResearch collab participant <case-id> --expected-revision <sha> --actor <subject> --subject <subject> --role <role>")
		}
		flags := flag.NewFlagSet("collab participant", flag.ContinueOnError)
		flags.SetOutput(stderr)
		req := researchcore.CollaborationParticipantRequest{CaseID: args[1]}
		flags.StringVar(&req.ExpectedRevision, "expected-revision", "", "current collaboration revision")
		flags.StringVar(&req.Actor, "actor", "", "acting participant")
		flags.StringVar(&req.Subject, "subject", "", "participant subject")
		flags.StringVar(&req.Role, "role", "", "owner|lead|analyst|reviewer|viewer|agent")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected participant arguments")
		}
		value, err := service.AddCaseParticipant(req)
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	case "assign-finding":
		if len(args) < 2 {
			return errors.New("usage: ReverseResearch collab assign-finding <case-id> --expected-revision <sha> --actor <subject> --finding <id> --owner <subject>")
		}
		flags := flag.NewFlagSet("collab assign-finding", flag.ContinueOnError)
		flags.SetOutput(stderr)
		req := researchcore.FindingOwnerRequest{CaseID: args[1]}
		flags.StringVar(&req.ExpectedRevision, "expected-revision", "", "current collaboration revision")
		flags.StringVar(&req.Actor, "actor", "", "acting participant")
		flags.StringVar(&req.FindingID, "finding", "", "finding ID")
		flags.StringVar(&req.Owner, "owner", "", "finding owner")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected assign-finding arguments")
		}
		value, err := service.AssignCaseFindingOwner(req)
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	case "task-add":
		if len(args) < 2 {
			return errors.New("usage: ReverseResearch collab task-add <case-id> --expected-revision <sha> --actor <subject> --title <text> [--owner <subject>]")
		}
		flags := flag.NewFlagSet("collab task-add", flag.ContinueOnError)
		flags.SetOutput(stderr)
		req := researchcore.CollaborationTaskRequest{CaseID: args[1]}
		flags.StringVar(&req.ExpectedRevision, "expected-revision", "", "current collaboration revision")
		flags.StringVar(&req.Actor, "actor", "", "acting participant")
		flags.StringVar(&req.Title, "title", "", "task title")
		flags.StringVar(&req.Owner, "owner", "", "task owner")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected task-add arguments")
		}
		w, item, err := service.AddCaseCollaborationTask(req)
		if err != nil {
			return err
		}
		return writeJSON(stdout, map[string]any{"workspace": w, "task": item})
	case "task-update":
		if len(args) < 2 {
			return errors.New("usage: ReverseResearch collab task-update <case-id> --expected-revision <sha> --actor <subject> --task <id> --status <planned|running|blocked|done|cancelled>")
		}
		flags := flag.NewFlagSet("collab task-update", flag.ContinueOnError)
		flags.SetOutput(stderr)
		req := researchcore.CollaborationTaskUpdateRequest{CaseID: args[1]}
		flags.StringVar(&req.ExpectedRevision, "expected-revision", "", "current collaboration revision")
		flags.StringVar(&req.Actor, "actor", "", "acting participant")
		flags.StringVar(&req.TaskID, "task", "", "task ID")
		flags.StringVar(&req.Status, "status", "", "new status")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected task-update arguments")
		}
		value, err := service.UpdateCaseCollaborationTask(req)
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	case "comment":
		if len(args) < 2 {
			return errors.New("usage: ReverseResearch collab comment <case-id> --expected-revision <sha> --actor <subject> --body <text> [--object-type <type> --object-id <id>]")
		}
		flags := flag.NewFlagSet("collab comment", flag.ContinueOnError)
		flags.SetOutput(stderr)
		req := researchcore.CollaborationCommentRequest{CaseID: args[1]}
		flags.StringVar(&req.ExpectedRevision, "expected-revision", "", "current collaboration revision")
		flags.StringVar(&req.Actor, "actor", "", "acting participant")
		flags.StringVar(&req.Body, "body", "", "comment body")
		flags.StringVar(&req.ObjectType, "object-type", "", "linked object type")
		flags.StringVar(&req.ObjectID, "object-id", "", "linked object ID")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected comment arguments")
		}
		w, item, err := service.AddCaseCollaborationComment(req)
		if err != nil {
			return err
		}
		return writeJSON(stdout, map[string]any{"workspace": w, "comment": item})
	case "review-request":
		if len(args) < 2 {
			return errors.New("usage: ReverseResearch collab review-request <case-id> --expected-revision <sha> --actor <subject> --kind <case|finding|evidence|report> --subject-id <id>")
		}
		flags := flag.NewFlagSet("collab review-request", flag.ContinueOnError)
		flags.SetOutput(stderr)
		req := researchcore.CollaborationReviewRequest{CaseID: args[1]}
		flags.StringVar(&req.ExpectedRevision, "expected-revision", "", "current collaboration revision")
		flags.StringVar(&req.Actor, "actor", "", "requesting participant")
		flags.StringVar(&req.Kind, "kind", "", "case|finding|evidence|report")
		flags.StringVar(&req.SubjectID, "subject-id", "", "review subject ID")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected review-request arguments")
		}
		w, item, err := service.RequestCaseCollaborationReview(req)
		if err != nil {
			return err
		}
		return writeJSON(stdout, map[string]any{"workspace": w, "review": item})
	case "review-queue":
		if len(args) < 2 {
			return errors.New("usage: ReverseResearch collab review-queue <case-id> --actor <subject>")
		}
		flags := flag.NewFlagSet("collab review-queue", flag.ContinueOnError)
		flags.SetOutput(stderr)
		req := researchcore.CollaborationReviewQueueRequest{CaseID: args[1]}
		flags.StringVar(&req.Actor, "actor", "", "active participant")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected review-queue arguments")
		}
		value, err := service.GetCaseCollaborationReviewQueue(req)
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	case "history":
		if len(args) < 2 {
			return errors.New("usage: ReverseResearch collab history <case-id> --actor <subject>")
		}
		flags := flag.NewFlagSet("collab history", flag.ContinueOnError)
		flags.SetOutput(stderr)
		req := researchcore.CollaborationHistoryRequest{CaseID: args[1]}
		flags.StringVar(&req.Actor, "actor", "", "active participant")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected history arguments")
		}
		value, err := service.GetCaseCollaborationHistory(req)
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	case "approve":
		if len(args) < 2 {
			return errors.New("usage: ReverseResearch collab approve <case-id> --expected-revision <sha> --actor <reviewer> --kind <kind> --subject-id <id> --decision <approved|rejected> [--notes <text>]")
		}
		flags := flag.NewFlagSet("collab approve", flag.ContinueOnError)
		flags.SetOutput(stderr)
		req := researchcore.CollaborationApprovalRequest{CaseID: args[1]}
		flags.StringVar(&req.ExpectedRevision, "expected-revision", "", "current collaboration revision")
		flags.StringVar(&req.Actor, "actor", "", "reviewer")
		flags.StringVar(&req.Kind, "kind", "", "approval kind")
		flags.StringVar(&req.SubjectID, "subject-id", "", "subject ID")
		flags.StringVar(&req.Decision, "decision", "", "approved|rejected")
		flags.StringVar(&req.Notes, "notes", "", "review notes")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected approval arguments")
		}
		w, item, err := service.AddCaseCollaborationApproval(req)
		if err != nil {
			return err
		}
		return writeJSON(stdout, map[string]any{"workspace": w, "approval": item})
	case "lock", "unlock":
		if len(args) < 2 {
			return errors.New("usage: ReverseResearch collab lock|unlock <case-id> --expected-revision <sha> --actor <subject> --evidence <id> [--reason <text>]")
		}
		flags := flag.NewFlagSet("collab "+args[0], flag.ContinueOnError)
		flags.SetOutput(stderr)
		req := researchcore.EvidenceLockRequest{CaseID: args[1]}
		flags.StringVar(&req.ExpectedRevision, "expected-revision", "", "current collaboration revision")
		flags.StringVar(&req.Actor, "actor", "", "acting participant")
		flags.StringVar(&req.EvidenceID, "evidence", "", "evidence ID")
		flags.StringVar(&req.Reason, "reason", "", "lock reason")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected evidence-lock arguments")
		}
		var value any
		var err error
		if args[0] == "lock" {
			value, err = service.LockCaseEvidence(req)
		} else {
			value, err = service.UnlockCaseEvidence(req)
		}
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	default:
		return fmt.Errorf("unknown collab subcommand %q", args[0])
	}
}

func runRBACCLI(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "check" {
		return errors.New("usage: ReverseResearch rbac check --role <role> --action <action>")
	}
	flags := flag.NewFlagSet("rbac check", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var role, action string
	flags.StringVar(&role, "role", "", "role")
	flags.StringVar(&action, "action", "", "action")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected rbac arguments")
	}
	return writeJSON(stdout, rbac.Evaluate(rbac.Role(role), rbac.Action(action)))
}

func runAgentCLI(service *researchcore.Service, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("agent subcommand required: register|list|get|status|fleet|refresh-status|validate-job|verify-result")
	}
	switch args[0] {
	case "register":
		if len(args) < 2 {
			return errors.New("usage: ReverseResearch agent register <manifest.json> --authority-role owner [--expected-revision <sha>]")
		}
		flags := flag.NewFlagSet("agent register", flag.ContinueOnError)
		flags.SetOutput(stderr)
		req := researchcore.RemoteAgentRegisterRequest{ManifestPath: args[1]}
		flags.StringVar(&req.AuthorityRole, "authority-role", "", "RBAC authority role")
		flags.StringVar(&req.ExpectedRevision, "expected-revision", "", "current registration revision for explicit replacement")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected agent register arguments")
		}
		value, err := service.RegisterRemoteAgent(req)
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	case "list":
		if len(args) != 1 {
			return errors.New("usage: ReverseResearch agent list")
		}
		value, err := service.ListRemoteAgents()
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	case "get":
		if len(args) != 2 {
			return errors.New("usage: ReverseResearch agent get <agent-id>")
		}
		value, err := service.GetRemoteAgent(args[1])
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	case "status":
		if len(args) != 2 {
			return errors.New("usage: ReverseResearch agent status <agent-id>")
		}
		value, err := service.GetRemoteAgentStatus(args[1])
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	case "fleet":
		flags := flag.NewFlagSet("agent fleet", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var req researchcore.RemoteAgentFleetRequest
		flags.IntVar(&req.StaleAfterSeconds, "stale-after-seconds", 0, "seconds before an authenticated observation becomes stale")
		flags.IntVar(&req.OfflineAfterSeconds, "offline-after-seconds", 0, "seconds before an authenticated observation is projected offline")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected agent fleet arguments")
		}
		value, err := service.ListRemoteAgentFleet(req)
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	case "refresh-status":
		if len(args) < 2 {
			return errors.New("usage: ReverseResearch agent refresh-status <agent-id> --endpoint <https-url> --client-cert <pem> --client-key <pem> --server-ca <pem> --authority-role <role> [--expected-revision <sha>]")
		}
		flags := flag.NewFlagSet("agent refresh-status", flag.ContinueOnError)
		flags.SetOutput(stderr)
		req := researchcore.RemoteAgentStatusRefreshRequest{AgentID: args[1]}
		flags.StringVar(&req.Endpoint, "endpoint", "", "Remote Agent HTTPS base endpoint")
		flags.StringVar(&req.ClientCertPath, "client-cert", "", "mTLS client certificate PEM")
		flags.StringVar(&req.ClientKeyPath, "client-key", "", "mTLS client private key PEM")
		flags.StringVar(&req.ServerCAPath, "server-ca", "", "trusted Remote Agent server CA PEM")
		flags.StringVar(&req.ExpectedRevision, "expected-revision", "", "current status revision for explicit replacement")
		flags.StringVar(&req.AuthorityRole, "authority-role", "", "RBAC authority role")
		flags.IntVar(&req.TimeoutSeconds, "timeout-seconds", 0, "bounded status request timeout")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected refresh-status arguments")
		}
		value, err := service.RefreshRemoteAgentStatus(req)
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	case "validate-job":
		if len(args) < 2 {
			return errors.New("usage: ReverseResearch agent validate-job <agent-id> --job <job.json>")
		}
		flags := flag.NewFlagSet("agent validate-job", flag.ContinueOnError)
		flags.SetOutput(stderr)
		req := researchcore.RemoteJobValidationRequest{AgentID: args[1]}
		flags.StringVar(&req.JobPath, "job", "", "bounded job JSON")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected validate-job arguments")
		}
		value, err := service.ValidateRemoteAgentJob(req)
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	case "verify-result":
		if len(args) < 2 {
			return errors.New("usage: ReverseResearch agent verify-result <agent-id> --result <result.json>")
		}
		flags := flag.NewFlagSet("agent verify-result", flag.ContinueOnError)
		flags.SetOutput(stderr)
		req := researchcore.RemoteResultVerificationRequest{AgentID: args[1]}
		flags.StringVar(&req.ResultPath, "result", "", "signed result JSON")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected verify-result arguments")
		}
		value, err := service.VerifyRemoteAgentResult(req)
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	default:
		return fmt.Errorf("unknown agent subcommand %q", args[0])
	}
}

func runPackCLI(service *researchcore.Service, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("pack subcommand required: verify|registry|trust-add|trust-remove|verify-registry|activate|quarantine|rollback|active|read-entrypoint")
	}
	switch args[0] {
	case "verify":
		flags := flag.NewFlagSet("pack verify", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var req researchcore.PackVerificationRequest
		flags.StringVar(&req.Root, "root", "", "pack root")
		flags.StringVar(&req.ManifestPath, "manifest", "", "signed manifest JSON")
		flags.StringVar(&req.TrustPath, "trust", "", "trusted public keys JSON")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected pack verify arguments")
		}
		value, err := service.VerifySignedPack(req)
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	case "registry":
		flags := flag.NewFlagSet("pack registry", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var role string
		flags.StringVar(&role, "authority-role", "", "RBAC role with registry.read")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected pack registry arguments")
		}
		value, err := service.GetPackRegistry(researchcore.PackRegistryGetRequest{AuthorityRole: role})
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	case "trust-add":
		flags := flag.NewFlagSet("pack trust-add", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var req researchcore.PackRegistryTrustRequest
		flags.StringVar(&req.AuthorityRole, "authority-role", "", "RBAC role with registry.manage")
		flags.StringVar(&req.ExpectedRevision, "expected-revision", "", "current registry revision; omit only for a new registry")
		flags.StringVar(&req.KeyID, "key-id", "", "publisher key ID")
		flags.StringVar(&req.PublicKey, "public-key", "", "base64 Ed25519 public key")
		flags.StringVar(&req.Publisher, "publisher", "", "publisher identity")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected pack trust-add arguments")
		}
		value, err := service.TrustPackPublisher(req)
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	case "trust-remove":
		flags := flag.NewFlagSet("pack trust-remove", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var req researchcore.PackRegistryRemoveRequest
		flags.StringVar(&req.AuthorityRole, "authority-role", "", "RBAC role with registry.manage")
		flags.StringVar(&req.ExpectedRevision, "expected-revision", "", "current registry revision")
		flags.StringVar(&req.KeyID, "key-id", "", "publisher key ID")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected pack trust-remove arguments")
		}
		value, err := service.RemoveTrustedPackPublisher(req)
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	case "verify-registry":
		flags := flag.NewFlagSet("pack verify-registry", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var req researchcore.PackRegistryVerifyRequest
		flags.StringVar(&req.AuthorityRole, "authority-role", "", "RBAC role with registry.read")
		flags.StringVar(&req.ExpectedRevision, "expected-revision", "", "current registry revision")
		flags.StringVar(&req.Root, "root", "", "pack root")
		flags.StringVar(&req.ManifestPath, "manifest", "", "signed manifest JSON")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected pack verify-registry arguments")
		}
		value, err := service.VerifyAndRecordPack(req)
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	case "activate":
		flags := flag.NewFlagSet("pack activate", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var req researchcore.PackLifecycleRequest
		flags.StringVar(&req.AuthorityRole, "authority-role", "", "RBAC role with registry.manage")
		flags.StringVar(&req.ExpectedRevision, "expected-revision", "", "current registry revision")
		flags.StringVar(&req.ReceiptID, "receipt-id", "", "verified pack receipt ID")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected pack activate arguments")
		}
		state, pack, err := service.ActivateVerifiedPack(req)
		if err != nil {
			return err
		}
		return writeJSON(stdout, map[string]any{"state": state, "pack": pack})
	case "quarantine":
		flags := flag.NewFlagSet("pack quarantine", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var req researchcore.PackLifecycleRequest
		flags.StringVar(&req.AuthorityRole, "authority-role", "", "RBAC role with registry.manage")
		flags.StringVar(&req.ExpectedRevision, "expected-revision", "", "current registry revision")
		flags.StringVar(&req.ReceiptID, "receipt-id", "", "verified pack receipt ID")
		flags.StringVar(&req.Reason, "reason", "", "quarantine reason")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected pack quarantine arguments")
		}
		state, pack, err := service.QuarantineVerifiedPack(req)
		if err != nil {
			return err
		}
		return writeJSON(stdout, map[string]any{"state": state, "pack": pack})
	case "rollback":
		flags := flag.NewFlagSet("pack rollback", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var req researchcore.PackLifecycleRequest
		flags.StringVar(&req.AuthorityRole, "authority-role", "", "RBAC role with registry.manage")
		flags.StringVar(&req.ExpectedRevision, "expected-revision", "", "current registry revision")
		flags.StringVar(&req.PackID, "pack-id", "", "pack ID")
		flags.StringVar(&req.TargetReceiptID, "target-receipt-id", "", "previous verified receipt ID")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected pack rollback arguments")
		}
		state, pack, err := service.RollbackVerifiedPack(req)
		if err != nil {
			return err
		}
		return writeJSON(stdout, map[string]any{"state": state, "pack": pack})
	case "active":
		flags := flag.NewFlagSet("pack active", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var req researchcore.PackActiveRequest
		flags.StringVar(&req.AuthorityRole, "authority-role", "", "RBAC role with registry.read")
		flags.StringVar(&req.PackID, "pack-id", "", "pack ID")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected pack active arguments")
		}
		state, pack, err := service.GetActivePack(req)
		if err != nil {
			return err
		}
		return writeJSON(stdout, map[string]any{"state": state, "pack": pack})
	case "read-entrypoint":
		flags := flag.NewFlagSet("pack read-entrypoint", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var req researchcore.PackEntrypointReadRequest
		flags.StringVar(&req.AuthorityRole, "authority-role", "", "RBAC role with registry.read")
		flags.StringVar(&req.PackID, "pack-id", "", "pack ID")
		flags.StringVar(&req.Entrypoint, "entrypoint", "", "data-only entrypoint name")
		flags.IntVar(&req.MaxBytes, "max-bytes", 0, "bounded entrypoint bytes")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected pack read-entrypoint arguments")
		}
		value, err := service.ReadActivePackEntrypoint(req)
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	default:
		return fmt.Errorf("unknown pack subcommand %q", args[0])
	}
}

func p3ProductHelp(w io.Writer) {
	fmt.Fprintln(w, "  ReverseResearch report render <case-id> --profile <profile> --format <json|markdown|html|sarif|stix> --out <path>")
	fmt.Fprintln(w, "  ReverseResearch dashboard render <case-id> --out <dashboard.html> [--actor <participant>]")
	fmt.Fprintln(w, "  ReverseResearch collab init|get|participant|assign-finding|task-add|task-update|comment|review-request|review-queue|history|approve|lock|unlock ...")
	fmt.Fprintln(w, "  ReverseResearch rbac check --role <role> --action <action>")
	fmt.Fprintln(w, "  ReverseResearch agent register|list|get|status|fleet|refresh-status|validate-job|verify-result ...   # no arbitrary remote shell")
	fmt.Fprintln(w, "  ReverseResearch pack verify|registry|trust-add|trust-remove|verify-registry|activate|quarantine|rollback|active|read-entrypoint ...")
}
