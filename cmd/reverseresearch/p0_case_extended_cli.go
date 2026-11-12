package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"reverseresearch/internal/casebook"
	researchcore "reverseresearch/internal/core"
)

func runCaseV2ExtendedCLI(service *researchcore.Service, args []string, stdout, stderr io.Writer) (bool, error) {
	switch args[0] {
	case "review":
		if len(args) != 2 {
			return true, errors.New("usage: ReverseResearch case review <case-id>")
		}
		value, err := service.ReviewCase(args[1])
		if err != nil {
			return true, err
		}
		if err := writeJSON(stdout, value); err != nil {
			return true, err
		}
		if !value.Ready {
			return true, fmt.Errorf("case strict review failed with %d issue(s); see JSON output", len(value.Issues))
		}
		return true, nil

	case "role":
		if len(args) < 2 {
			return true, errors.New("usage: ReverseResearch case role <case-id> --role <role> [--skill <specialist-skill>] [--handoff <condition>]")
		}
		flags := flag.NewFlagSet("case role", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var request casebook.RoleAssignmentRequest
		flags.StringVar(&request.Role, "role", "", "logical research role; lead is required by strict review")
		flags.StringVar(&request.SpecialistSkill, "skill", "", "optional specialist skill id/name")
		flags.StringVar(&request.HandoffWhen, "handoff", "", "optional handoff condition")
		if err := flags.Parse(args[2:]); err != nil {
			return true, err
		}
		if flags.NArg() != 0 || strings.TrimSpace(request.Role) == "" {
			return true, errors.New("usage: ReverseResearch case role <case-id> --role <role> [--skill <specialist-skill>] [--handoff <condition>]")
		}
		value, err := service.AssignCaseRole(args[1], request)
		if err != nil {
			return true, err
		}
		return true, writeJSON(stdout, value)

	case "workitem":
		if len(args) < 2 {
			return true, errors.New("usage: ReverseResearch case workitem <case-id> --title <text> [--owner-role <role>] [--coverage <text>] [--evidence <id,id>]")
		}
		flags := flag.NewFlagSet("case workitem", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var request casebook.WorkItemRequest
		var evidenceRaw string
		flags.StringVar(&request.Title, "title", "", "workitem title")
		flags.StringVar(&request.OwnerRole, "owner-role", "", "logical owner role")
		flags.StringVar(&request.Coverage, "coverage", "", "coverage/task boundary")
		flags.StringVar(&evidenceRaw, "evidence", "", "comma-separated evidence IDs")
		if err := flags.Parse(args[2:]); err != nil {
			return true, err
		}
		request.EvidenceIDs = splitCSV(evidenceRaw)
		if flags.NArg() != 0 || strings.TrimSpace(request.Title) == "" {
			return true, errors.New("usage: ReverseResearch case workitem <case-id> --title <text> [--owner-role <role>] [--coverage <text>] [--evidence <id,id>]")
		}
		value, err := service.AddCaseWorkItem(args[1], request)
		if err != nil {
			return true, err
		}
		return true, writeJSON(stdout, value)

	case "workitem-update":
		if len(args) < 3 {
			return true, errors.New("usage: ReverseResearch case workitem-update <case-id> <workitem-id> --status <planned|running|blocked|done|cancelled> [--coverage <text>] [--evidence <id,id>] [--blocked-reason <text>]")
		}
		flags := flag.NewFlagSet("case workitem-update", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var request casebook.WorkItemUpdateRequest
		var evidenceRaw string
		flags.StringVar(&request.Status, "status", "", "workitem status")
		flags.StringVar(&request.Coverage, "coverage", "", "coverage/task boundary")
		flags.StringVar(&evidenceRaw, "evidence", "", "comma-separated evidence IDs")
		flags.StringVar(&request.BlockedReason, "blocked-reason", "", "required when status=blocked")
		if err := flags.Parse(args[3:]); err != nil {
			return true, err
		}
		request.EvidenceIDs = splitCSV(evidenceRaw)
		if flags.NArg() != 0 || strings.TrimSpace(request.Status) == "" {
			return true, errors.New("usage: ReverseResearch case workitem-update <case-id> <workitem-id> --status <status>")
		}
		value, err := service.UpdateCaseWorkItem(args[1], args[2], request)
		if err != nil {
			return true, err
		}
		return true, writeJSON(stdout, value)

	case "timeline":
		if len(args) < 2 {
			return true, errors.New("usage: ReverseResearch case timeline <case-id> --kind <kind> --summary <text> [--role <role>] [--workitem <id>] [--job <id>] [--evidence <id,id>]")
		}
		flags := flag.NewFlagSet("case timeline", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var request casebook.TimelineRequest
		var evidenceRaw string
		flags.StringVar(&request.Kind, "kind", "", "timeline event kind")
		flags.StringVar(&request.Summary, "summary", "", "timeline summary")
		flags.StringVar(&request.Role, "role", "", "logical role")
		flags.StringVar(&request.WorkItemID, "workitem", "", "workitem id")
		flags.StringVar(&request.JobID, "job", "", "generic job id")
		flags.StringVar(&evidenceRaw, "evidence", "", "comma-separated evidence IDs")
		if err := flags.Parse(args[2:]); err != nil {
			return true, err
		}
		request.EvidenceIDs = splitCSV(evidenceRaw)
		if flags.NArg() != 0 || strings.TrimSpace(request.Kind) == "" || strings.TrimSpace(request.Summary) == "" {
			return true, errors.New("usage: ReverseResearch case timeline <case-id> --kind <kind> --summary <text> [links]")
		}
		value, err := service.AddCaseTimeline(args[1], request)
		if err != nil {
			return true, err
		}
		return true, writeJSON(stdout, value)

	case "artifact":
		if len(args) < 2 {
			return true, errors.New("usage: ReverseResearch case artifact <case-id> --kind <kind> --identity <identity> [--source <source>] [--sha256 <hex>] [--size N]")
		}
		flags := flag.NewFlagSet("case artifact", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var request casebook.ArtifactRequest
		flags.StringVar(&request.Kind, "kind", "", "artifact kind")
		flags.StringVar(&request.Identity, "identity", "", "stable artifact identity")
		flags.StringVar(&request.Source, "source", "", "artifact source/provenance")
		flags.StringVar(&request.SHA256, "sha256", "", "optional SHA-256")
		flags.Int64Var(&request.Size, "size", 0, "optional size")
		if err := flags.Parse(args[2:]); err != nil {
			return true, err
		}
		if flags.NArg() != 0 || strings.TrimSpace(request.Kind) == "" || strings.TrimSpace(request.Identity) == "" {
			return true, errors.New("usage: ReverseResearch case artifact <case-id> --kind <kind> --identity <identity> [metadata]")
		}
		value, err := service.AddCaseArtifact(args[1], request)
		if err != nil {
			return true, err
		}
		return true, writeJSON(stdout, value)

	case "observation":
		if len(args) < 2 {
			return true, errors.New("usage: ReverseResearch case observation <case-id> --summary <text> [--evidence <id,id>]")
		}
		flags := flag.NewFlagSet("case observation", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var request casebook.ObservationRequest
		var evidenceRaw string
		flags.StringVar(&request.Summary, "summary", "", "observation summary")
		flags.StringVar(&evidenceRaw, "evidence", "", "comma-separated evidence IDs")
		if err := flags.Parse(args[2:]); err != nil {
			return true, err
		}
		request.EvidenceIDs = splitCSV(evidenceRaw)
		if flags.NArg() != 0 || strings.TrimSpace(request.Summary) == "" {
			return true, errors.New("usage: ReverseResearch case observation <case-id> --summary <text> [--evidence <id,id>]")
		}
		value, err := service.AddCaseObservation(args[1], request)
		if err != nil {
			return true, err
		}
		return true, writeJSON(stdout, value)

	case "vulnerability":
		if len(args) < 2 {
			return true, errors.New("usage: ReverseResearch case vulnerability <case-id> --title <text> [--cwe <id,id>] [--capec <id,id>] [--cve <id,id>] [--findings <id,id>] [--evidence <id,id>]")
		}
		flags := flag.NewFlagSet("case vulnerability", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var request casebook.VulnerabilityRequest
		var cweRaw, capecRaw, cveRaw, findingsRaw, evidenceRaw string
		flags.StringVar(&request.Title, "title", "", "vulnerability title")
		flags.StringVar(&cweRaw, "cwe", "", "comma-separated CWE ids")
		flags.StringVar(&capecRaw, "capec", "", "comma-separated CAPEC ids")
		flags.StringVar(&cveRaw, "cve", "", "comma-separated CVE ids")
		flags.StringVar(&findingsRaw, "findings", "", "comma-separated finding IDs")
		flags.StringVar(&evidenceRaw, "evidence", "", "comma-separated evidence IDs")
		if err := flags.Parse(args[2:]); err != nil {
			return true, err
		}
		request.CWE, request.CAPEC, request.CVE = splitCSV(cweRaw), splitCSV(capecRaw), splitCSV(cveRaw)
		request.FindingIDs, request.EvidenceIDs = splitCSV(findingsRaw), splitCSV(evidenceRaw)
		if flags.NArg() != 0 || strings.TrimSpace(request.Title) == "" {
			return true, errors.New("usage: ReverseResearch case vulnerability <case-id> --title <text> [links]")
		}
		value, err := service.AddCaseVulnerability(args[1], request)
		if err != nil {
			return true, err
		}
		return true, writeJSON(stdout, value)

	case "ioc":
		if len(args) < 2 {
			return true, errors.New("usage: ReverseResearch case ioc <case-id> --type <type> --value <value> [--source-id <id>]")
		}
		flags := flag.NewFlagSet("case ioc", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var request casebook.IOCRequest
		flags.StringVar(&request.Type, "type", "", "IOC type")
		flags.StringVar(&request.Value, "value", "", "IOC value")
		flags.StringVar(&request.SourceID, "source-id", "", "source Evidence/Finding/Artifact/Observation id")
		if err := flags.Parse(args[2:]); err != nil {
			return true, err
		}
		if flags.NArg() != 0 || strings.TrimSpace(request.Type) == "" || strings.TrimSpace(request.Value) == "" {
			return true, errors.New("usage: ReverseResearch case ioc <case-id> --type <type> --value <value> [--source-id <id>]")
		}
		value, err := service.AddCaseIOC(args[1], request)
		if err != nil {
			return true, err
		}
		return true, writeJSON(stdout, value)

	case "ttp":
		if len(args) < 2 {
			return true, errors.New("usage: ReverseResearch case ttp <case-id> --technique <Txxxx> [--tactic <name>] [--findings <id,id>]")
		}
		flags := flag.NewFlagSet("case ttp", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var request casebook.TTPRequest
		var findingsRaw string
		flags.StringVar(&request.Technique, "technique", "", "ATT&CK technique")
		flags.StringVar(&request.Tactic, "tactic", "", "ATT&CK tactic")
		flags.StringVar(&findingsRaw, "findings", "", "comma-separated finding IDs")
		if err := flags.Parse(args[2:]); err != nil {
			return true, err
		}
		request.FindingIDs = splitCSV(findingsRaw)
		if flags.NArg() != 0 || strings.TrimSpace(request.Technique) == "" {
			return true, errors.New("usage: ReverseResearch case ttp <case-id> --technique <Txxxx> [links]")
		}
		value, err := service.AddCaseTTP(args[1], request)
		if err != nil {
			return true, err
		}
		return true, writeJSON(stdout, value)

	case "mitigation":
		if len(args) < 2 {
			return true, errors.New("usage: ReverseResearch case mitigation <case-id> --summary <text> [--technique <Txxxx>] [--findings <id,id>] [--evidence <id,id>]")
		}
		flags := flag.NewFlagSet("case mitigation", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var request casebook.MitigationRequest
		var findingsRaw, evidenceRaw string
		flags.StringVar(&request.Summary, "summary", "", "mitigation summary")
		flags.StringVar(&request.Technique, "technique", "", "technique/countermeasure relation")
		flags.StringVar(&findingsRaw, "findings", "", "comma-separated finding IDs")
		flags.StringVar(&evidenceRaw, "evidence", "", "comma-separated evidence IDs")
		if err := flags.Parse(args[2:]); err != nil {
			return true, err
		}
		request.FindingIDs, request.EvidenceIDs = splitCSV(findingsRaw), splitCSV(evidenceRaw)
		if flags.NArg() != 0 || strings.TrimSpace(request.Summary) == "" {
			return true, errors.New("usage: ReverseResearch case mitigation <case-id> --summary <text> [links]")
		}
		value, err := service.AddCaseMitigation(args[1], request)
		if err != nil {
			return true, err
		}
		return true, writeJSON(stdout, value)

	case "report":
		if len(args) < 2 {
			return true, errors.New("usage: ReverseResearch case report <case-id> --kind <kind> --format <format> --revision <rev> [--artifact-id <id>]")
		}
		flags := flag.NewFlagSet("case report", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var request casebook.ReportRequest
		var findingsRaw, evidenceRaw, sectionsRaw string
		flags.StringVar(&request.Kind, "kind", "", "report kind")
		flags.StringVar(&request.Format, "format", "", "json|sarif|stix|markdown|html|...")
		flags.StringVar(&request.Revision, "revision", "", "report revision")
		flags.StringVar(&request.Profile, "profile", "", "report profile/template")
		flags.StringVar(&request.Classification, "classification", "", "report classification")
		flags.StringVar(&request.Status, "status", "draft", "draft|final")
		flags.StringVar(&request.Summary, "summary", "", "report summary")
		flags.StringVar(&request.ArtifactID, "artifact-id", "", "optional artifact object id")
		flags.StringVar(&findingsRaw, "findings", "", "comma-separated finding IDs")
		flags.StringVar(&evidenceRaw, "evidence", "", "comma-separated evidence IDs")
		flags.StringVar(&sectionsRaw, "sections", "", "comma-separated canonical section names")
		flags.StringVar(&request.SupersedesReportID, "supersedes", "", "optional previous report id")
		if err := flags.Parse(args[2:]); err != nil {
			return true, err
		}
		request.FindingIDs = splitCSV(findingsRaw)
		request.EvidenceIDs = splitCSV(evidenceRaw)
		request.Sections = splitCSV(sectionsRaw)
		if flags.NArg() != 0 || strings.TrimSpace(request.Kind) == "" || strings.TrimSpace(request.Format) == "" || strings.TrimSpace(request.Revision) == "" {
			return true, errors.New("usage: ReverseResearch case report <case-id> --kind <kind> --format <format> --revision <rev> [--artifact-id <id>]")
		}
		value, err := service.AddCaseReport(args[1], request)
		if err != nil {
			return true, err
		}
		return true, writeJSON(stdout, value)

	default:
		return false, nil
	}
}
