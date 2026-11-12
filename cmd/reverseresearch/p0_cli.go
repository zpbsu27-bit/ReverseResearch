package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"reverseresearch/internal/casebook"
	researchcore "reverseresearch/internal/core"
	"reverseresearch/internal/engagement"
	"reverseresearch/internal/job"
)

func runEngagementCLI(service *researchcore.Service, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("engagement subcommand is required: create, show, or authorize")
	}
	switch args[0] {
	case "create":
		flags := flag.NewFlagSet("engagement create", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var organization, operator, targetsRaw, excludedRaw, surfacesRaw, actionsRaw, excludedActionsRaw, credentialsRaw, cleanupRaw string
		var sensitivity, dataHandlingRaw, stealth, deliverablesRaw, reportClass, startsUTC, endsUTC string
		var authStatus, authBasis, authEvidenceRaw, networkMode, networkNotes string
		flags.StringVar(&organization, "organization", "", "engagement organization")
		flags.StringVar(&operator, "operator", "", "operator identity")
		flags.StringVar(&targetsRaw, "targets", "", "comma-separated exact scope targets")
		flags.StringVar(&excludedRaw, "exclude", "", "comma-separated explicitly excluded targets")
		flags.StringVar(&surfacesRaw, "surfaces", "", "comma-separated in-scope surfaces/protocols/apps")
		flags.StringVar(&actionsRaw, "actions", "", "comma-separated allowed actions")
		flags.StringVar(&excludedActionsRaw, "exclude-actions", "", "comma-separated explicitly excluded actions")
		flags.StringVar(&authStatus, "auth-status", "", "granted|pending|denied")
		flags.StringVar(&authBasis, "auth-basis", "", "authorization basis/reference")
		flags.StringVar(&authEvidenceRaw, "auth-evidence", "", "comma-separated authorization evidence references")
		flags.StringVar(&networkMode, "network-profile", "", "offline|lab_only|authorized_target_only|unrestricted_lab")
		flags.StringVar(&networkNotes, "network-notes", "", "network profile notes")
		flags.StringVar(&credentialsRaw, "credentials", "", "comma-separated credential references")
		flags.StringVar(&cleanupRaw, "cleanup", "", "comma-separated cleanup requirements")
		flags.StringVar(&sensitivity, "sensitivity", "", "data sensitivity")
		flags.StringVar(&dataHandlingRaw, "data-handling", "", "comma-separated data handling rules")
		flags.StringVar(&stealth, "stealth", "", "low|medium|high")
		flags.StringVar(&deliverablesRaw, "deliverables", "", "comma-separated deliverables")
		flags.StringVar(&reportClass, "report-class", "", "report classification")
		flags.StringVar(&startsUTC, "starts", "", "optional RFC3339 scope start")
		flags.StringVar(&endsUTC, "ends", "", "optional RFC3339 scope end")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || strings.TrimSpace(organization) == "" || strings.TrimSpace(operator) == "" || len(splitCSV(targetsRaw)) == 0 || len(splitCSV(actionsRaw)) == 0 || strings.TrimSpace(authStatus) == "" || strings.TrimSpace(networkMode) == "" {
			return errors.New("usage: ReverseResearch engagement create --organization <name> --operator <id> --targets <t,t> --actions <a,a> --auth-status <granted|pending|denied> --network-profile <offline|lab_only|authorized_target_only|unrestricted_lab> [scope flags]")
		}
		value, err := service.CreateEngagement(engagement.CreateRequest{
			Organization: organization,
			Operator:     operator,
			Scope: engagement.Scope{
				Targets:         splitCSV(targetsRaw),
				ExcludedTargets: splitCSV(excludedRaw),
				Surfaces:        splitCSV(surfacesRaw),
				AllowedActions:  splitCSV(actionsRaw),
				ExcludedActions: splitCSV(excludedActionsRaw),
				Authorization: engagement.Authorization{
					Status: authStatus, Basis: authBasis, EvidenceRefs: splitCSV(authEvidenceRaw),
				},
				NetworkProfile:  engagement.NetworkProfile{Mode: networkMode, Notes: networkNotes},
				CredentialRefs:  splitCSV(credentialsRaw),
				DataSensitivity: sensitivity,
				DataHandling:    splitCSV(dataHandlingRaw),
				Stealth:         stealth,
				Deliverables:    splitCSV(deliverablesRaw),
				Cleanup:         splitCSV(cleanupRaw),
				ReportClass:     reportClass,
				StartsUTC:       startsUTC,
				EndsUTC:         endsUTC,
			},
		})
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	case "show":
		if len(args) != 2 {
			return errors.New("usage: ReverseResearch engagement show <engagement-id>")
		}
		value, err := service.GetEngagement(args[1])
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	case "authorize":
		if len(args) < 2 {
			return errors.New("usage: ReverseResearch engagement authorize <engagement-id> --target <target> --action <action> [--at RFC3339]")
		}
		flags := flag.NewFlagSet("engagement authorize", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var target, action, effectClass, atRaw string
		flags.StringVar(&target, "target", "", "exact target")
		flags.StringVar(&action, "action", "", "exact action")
		flags.StringVar(&effectClass, "effect-class", "observation", "effect class for scope/network-profile evaluation")
		flags.StringVar(&atRaw, "at", "", "optional RFC3339 time; defaults to current UTC")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || strings.TrimSpace(target) == "" || strings.TrimSpace(action) == "" {
			return errors.New("usage: ReverseResearch engagement authorize <engagement-id> --target <target> --action <action> [--at RFC3339]")
		}
		at := time.Now().UTC()
		if strings.TrimSpace(atRaw) != "" {
			parsed, err := time.Parse(time.RFC3339, atRaw)
			if err != nil {
				return fmt.Errorf("parse --at: %w", err)
			}
			at = parsed
		}
		value, err := service.AuthorizeEngagementEffect(args[1], target, action, effectClass, at)
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	default:
		return fmt.Errorf("unknown engagement subcommand %q", args[0])
	}
}

func runJobCLI(service *researchcore.Service, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("job subcommand is required: plan, show, prepare, or transition")
	}
	switch args[0] {
	case "plan":
		flags := flag.NewFlagSet("job plan", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var request job.PlanRequest
		var evidenceRaw string
		flags.StringVar(&request.OperationID, "operation-id", "", "durable replay identity")
		flags.StringVar(&request.EngagementID, "engagement", "", "engagement id")
		flags.StringVar(&request.Target, "target", "", "exact target identity")
		flags.StringVar(&request.Action, "action", "", "exact scoped action")
		flags.StringVar(&request.EffectClass, "effect-class", "", "observation/local mutation/runtime mutation/active network interaction/etc")
		flags.StringVar(&request.ToolIdentity, "tool", "", "optional tool identity/version")
		flags.StringVar(&request.InputRevision, "input-revision", "", "optional input revision/hash")
		flags.StringVar(&evidenceRaw, "evidence", "", "comma-separated evidence IDs")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		request.EvidenceIDs = splitCSV(evidenceRaw)
		if flags.NArg() != 0 {
			return errors.New("usage: ReverseResearch job plan --operation-id <id> --engagement <id> --target <target> --action <action> --effect-class <class>")
		}
		value, err := service.PlanJob(request)
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	case "show":
		if len(args) != 2 {
			return errors.New("usage: ReverseResearch job show <job-id>")
		}
		value, err := service.GetJob(args[1])
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	case "prepare":
		if len(args) < 2 {
			return errors.New("usage: ReverseResearch job prepare <job-id> --operation-id <id>")
		}
		flags := flag.NewFlagSet("job prepare", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var operationID string
		flags.StringVar(&operationID, "operation-id", "", "operation identity that owns the job")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || strings.TrimSpace(operationID) == "" {
			return errors.New("usage: ReverseResearch job prepare <job-id> --operation-id <id>")
		}
		value, err := service.PrepareJob(args[1], operationID)
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	case "transition":
		if len(args) < 2 {
			return errors.New("usage: ReverseResearch job transition <job-id> --operation-id <id> --to <state>")
		}
		flags := flag.NewFlagSet("job transition", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var request job.TransitionRequest
		var toRaw, evidenceRaw string
		request.JobID = args[1]
		flags.StringVar(&request.OperationID, "operation-id", "", "operation identity that owns the job")
		flags.StringVar(&toRaw, "to", "", "running|applied|failed|uncertain|rolled_back|cancelled")
		flags.StringVar(&request.ResultIdentity, "result-identity", "", "optional exact result identity/hash")
		flags.StringVar(&request.CleanupState, "cleanup-state", "", "optional cleanup status")
		flags.StringVar(&request.Failure, "failure", "", "optional failure/uncertainty reason")
		flags.StringVar(&evidenceRaw, "evidence", "", "comma-separated evidence IDs")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		request.To = job.State(strings.TrimSpace(toRaw))
		request.EvidenceIDs = splitCSV(evidenceRaw)
		if flags.NArg() != 0 || strings.TrimSpace(request.OperationID) == "" || request.To == "" {
			return errors.New("usage: ReverseResearch job transition <job-id> --operation-id <id> --to <state>")
		}
		value, err := service.TransitionJob(request)
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	default:
		return fmt.Errorf("unknown job subcommand %q", args[0])
	}
}

func runDomainPackCLI(service *researchcore.Service, args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("domain-pack subcommand is required: list, show, or route")
	}
	switch args[0] {
	case "list":
		if len(args) != 1 {
			return errors.New("usage: ReverseResearch domain-pack list")
		}
		values, err := service.ListDomainPacks()
		if err != nil {
			return err
		}
		return writeJSON(stdout, values)
	case "show":
		if len(args) != 2 {
			return errors.New("usage: ReverseResearch domain-pack show <pack-id>")
		}
		value, err := service.GetDomainPack(args[1])
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	case "audit":
		if len(args) != 2 {
			return errors.New("usage: ReverseResearch domain-pack audit <pack-id>")
		}
		value, err := service.AuditDomainPack(args[1])
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	case "route":
		if len(args) != 2 {
			return errors.New("usage: ReverseResearch domain-pack route <route-id>")
		}
		value, ok, err := service.DomainPackForRoute(args[1])
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("route %q has no domain pack", args[1])
		}
		return writeJSON(stdout, value)
	default:
		return fmt.Errorf("unknown domain-pack subcommand %q", args[0])
	}
}

func runCaseV2CLI(service *researchcore.Service, args []string, stdout, stderr io.Writer) (bool, error) {
	if len(args) == 0 {
		return false, nil
	}
	if handled, err := runCaseV2ExtendedCLI(service, args, stdout, stderr); handled {
		return true, err
	}
	switch args[0] {
	case "hypothesis":
		if len(args) < 2 {
			return true, errors.New("usage: ReverseResearch case hypothesis <case-id> --text <hypothesis> [--support <e,e>] [--conflict <e,e>] [--experiment <text>]")
		}
		flags := flag.NewFlagSet("case hypothesis", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var request casebook.HypothesisRequest
		var supportRaw, conflictRaw string
		flags.StringVar(&request.Hypothesis, "text", "", "hypothesis statement")
		flags.StringVar(&supportRaw, "support", "", "comma-separated supporting evidence IDs")
		flags.StringVar(&conflictRaw, "conflict", "", "comma-separated conflicting evidence IDs")
		flags.StringVar(&request.RequiredExperiment, "experiment", "", "required experiment")
		if err := flags.Parse(args[2:]); err != nil {
			return true, err
		}
		request.SupportingEvidenceIDs = splitCSV(supportRaw)
		request.ConflictingEvidenceIDs = splitCSV(conflictRaw)
		if flags.NArg() != 0 || strings.TrimSpace(request.Hypothesis) == "" {
			return true, errors.New("usage: ReverseResearch case hypothesis <case-id> --text <hypothesis> [--support <e,e>] [--conflict <e,e>] [--experiment <text>]")
		}
		value, err := service.AddCaseHypothesis(args[1], request)
		if err != nil {
			return true, err
		}
		return true, writeJSON(stdout, value)
	case "hypothesis-update":
		if len(args) < 3 {
			return true, errors.New("usage: ReverseResearch case hypothesis-update <case-id> <hypothesis-id> --status <open|supported|rejected|retracted> [--reason <text>] [--replacement <id>]")
		}
		flags := flag.NewFlagSet("case hypothesis-update", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var request casebook.HypothesisUpdateRequest
		var statusRaw, supportRaw, conflictRaw string
		flags.StringVar(&statusRaw, "status", "", "hypothesis status")
		flags.StringVar(&supportRaw, "support", "", "comma-separated supporting evidence IDs")
		flags.StringVar(&conflictRaw, "conflict", "", "comma-separated conflicting evidence IDs")
		flags.StringVar(&request.RequiredExperiment, "experiment", "", "required experiment")
		flags.StringVar(&request.RejectedReason, "reason", "", "required reason for rejected/retracted")
		flags.StringVar(&request.ReplacementHypothesisID, "replacement", "", "optional replacement hypothesis id")
		if err := flags.Parse(args[3:]); err != nil {
			return true, err
		}
		request.Status = casebook.HypothesisStatus(strings.TrimSpace(statusRaw))
		request.SupportingEvidenceIDs = splitCSV(supportRaw)
		request.ConflictingEvidenceIDs = splitCSV(conflictRaw)
		if flags.NArg() != 0 || request.Status == "" {
			return true, errors.New("usage: ReverseResearch case hypothesis-update <case-id> <hypothesis-id> --status <status>")
		}
		value, err := service.UpdateCaseHypothesis(args[1], args[2], request)
		if err != nil {
			return true, err
		}
		return true, writeJSON(stdout, value)
	case "detection":
		if len(args) < 2 {
			return true, errors.New("usage: ReverseResearch case detection <case-id> --name <name> --kind <sigma|yara|suricata|zeek> --rule <text> --revision <rev> [validation flags]")
		}
		flags := flag.NewFlagSet("case detection", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var request casebook.DetectionRequest
		var telemetryRaw, evidenceRaw string
		flags.StringVar(&request.Name, "name", "", "detection name")
		flags.StringVar(&request.Kind, "kind", "", "detection kind")
		flags.StringVar(&request.Technique, "technique", "", "ATT&CK technique")
		flags.StringVar(&telemetryRaw, "telemetry", "", "comma-separated telemetry requirements")
		flags.StringVar(&request.Rule, "rule", "", "rule content")
		flags.StringVar(&request.Revision, "revision", "", "rule revision")
		flags.StringVar(&request.PositiveFixture, "positive-fixture", "", "positive fixture identity/path")
		flags.StringVar(&request.NegativeFixture, "negative-fixture", "", "negative fixture identity/path")
		flags.StringVar(&request.ExpectedHit, "expected-hit", "", "expected positive result")
		flags.StringVar(&request.FalsePositiveNotes, "false-positive-notes", "", "false-positive notes")
		flags.StringVar(&request.Coverage, "coverage", "", "coverage statement")
		flags.StringVar(&evidenceRaw, "evidence", "", "comma-separated evidence IDs")
		flags.BoolVar(&request.SyntaxValid, "syntax-valid", false, "record syntax validation passed")
		flags.BoolVar(&request.SchemaValid, "schema-valid", false, "record schema validation passed")
		flags.BoolVar(&request.PositivePassed, "positive-passed", false, "record positive fixture passed")
		flags.BoolVar(&request.NegativePassed, "negative-passed", false, "record negative fixture passed")
		flags.BoolVar(&request.TelemetryAvailable, "telemetry-available", false, "record required telemetry is available")
		flags.BoolVar(&request.Validated, "validated", false, "mark validated only when all validation gates are complete")
		if err := flags.Parse(args[2:]); err != nil {
			return true, err
		}
		request.TelemetryRequirement = splitCSV(telemetryRaw)
		request.EvidenceIDs = splitCSV(evidenceRaw)
		if flags.NArg() != 0 {
			return true, errors.New("unexpected positional arguments after case detection")
		}
		value, err := service.AddCaseDetection(args[1], request)
		if err != nil {
			return true, err
		}
		return true, writeJSON(stdout, value)
	case "retest":
		if len(args) < 2 {
			return true, errors.New("usage: ReverseResearch case retest <case-id> --subject-type <type> --subject-id <id> --status <status> --summary <text> [--evidence <e,e>]")
		}
		flags := flag.NewFlagSet("case retest", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var request casebook.RetestRequest
		var evidenceRaw string
		flags.StringVar(&request.SubjectType, "subject-type", "", "finding|detection|mitigation|vulnerability|hypothesis")
		flags.StringVar(&request.SubjectID, "subject-id", "", "subject object id")
		flags.StringVar(&request.Status, "status", "", "retest status")
		flags.StringVar(&request.Summary, "summary", "", "retest summary")
		flags.StringVar(&evidenceRaw, "evidence", "", "comma-separated evidence IDs")
		if err := flags.Parse(args[2:]); err != nil {
			return true, err
		}
		request.EvidenceIDs = splitCSV(evidenceRaw)
		if flags.NArg() != 0 {
			return true, errors.New("unexpected positional arguments after case retest")
		}
		value, err := service.AddCaseRetest(args[1], request)
		if err != nil {
			return true, err
		}
		return true, writeJSON(stdout, value)
	default:
		return false, nil
	}
}
