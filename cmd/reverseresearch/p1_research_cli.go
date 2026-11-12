package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	researchcore "reverseresearch/internal/core"
	"reverseresearch/internal/dfir"
	"reverseresearch/internal/fuzz"
	"reverseresearch/internal/sourceaudit"
)

func runDFIRCLI(service *researchcore.Service, args []string, stdout, stderr io.Writer) error {
	if len(args) < 2 {
		return errors.New("usage: ReverseResearch dfir inspect <artifact> [--case <id>] | dfir timeline <jsonl> [options]")
	}
	switch args[0] {
	case "inspect":
		flags := flag.NewFlagSet("dfir inspect", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var caseID string
		flags.StringVar(&caseID, "case", "", "optional dfir-forensics Case ID")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected positional arguments after dfir inspect")
		}
		value, err := service.InspectDFIRArtifact(researchcore.DFIRInspectRequest{Path: args[1], CaseID: caseID})
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	case "timeline":
		flags := flag.NewFlagSet("dfir timeline", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var request researchcore.DFIRTimelineRequest
		request.Path = args[1]
		flags.StringVar(&request.CaseID, "case", "", "optional dfir-forensics Case ID")
		flags.StringVar(&request.Format, "format", "generic-jsonl", "normalized input adapter label")
		flags.Int64Var(&request.MaxBytes, "max-bytes", dfir.DefaultMaxTimelineBytes, "maximum JSONL bytes")
		flags.IntVar(&request.MaxEntries, "max-entries", dfir.DefaultMaxEntries, "maximum normalized timeline entries")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected positional arguments after dfir timeline")
		}
		value, err := service.ImportDFIRTimeline(request)
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	default:
		return fmt.Errorf("unknown dfir subcommand %q", args[0])
	}
}

func runFuzzCLI(service *researchcore.Service, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "plan" {
		return errors.New("usage: ReverseResearch fuzz plan --target <path> --harness <path> --corpus <dir> --engine <libfuzzer|afl++|winafl|jazzer> [--case <id>] [--sanitizers <s,s>]")
	}
	flags := flag.NewFlagSet("fuzz plan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var request researchcore.FuzzPlanRequest
	var engineRaw, sanitizersRaw string
	flags.StringVar(&request.CaseID, "case", "", "optional vuln-research Case ID")
	flags.StringVar(&request.TargetPath, "target", "", "target binary or component")
	flags.StringVar(&request.Harness, "harness", "", "fuzz harness path")
	flags.StringVar(&request.CorpusDir, "corpus", "", "seed corpus directory")
	flags.StringVar(&engineRaw, "engine", "", "libfuzzer|afl++|winafl|jazzer")
	flags.StringVar(&sanitizersRaw, "sanitizers", "", "comma-separated sanitizer labels")
	flags.Int64Var(&request.Seed, "seed", 1, "deterministic engine seed")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments after fuzz plan")
	}
	request.Engine = fuzz.Engine(strings.ToLower(strings.TrimSpace(engineRaw)))
	request.Sanitizers = splitCSV(sanitizersRaw)
	value, err := service.BuildFuzzPlan(request)
	if err != nil {
		return err
	}
	return writeJSON(stdout, value)
}

func runCrashCLI(service *researchcore.Service, args []string, stdout, stderr io.Writer) error {
	if len(args) > 0 && (args[0] == "inspect" || args[0] == "note") {
		return runRecordedCoreCLI(service, args, stdout, stderr)
	}
	if len(args) == 0 {
		return errors.New("crash subcommand is required: fingerprint, dedupe, or record")
	}
	switch args[0] {
	case "fingerprint":
		flags := flag.NewFlagSet("crash fingerprint", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var path string
		flags.StringVar(&path, "json", "", "JSON file containing one crash record")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || strings.TrimSpace(path) == "" {
			return errors.New("usage: ReverseResearch crash fingerprint --json <crash.json>")
		}
		var crash fuzz.Crash
		if err := readJSONFile(path, &crash); err != nil {
			return err
		}
		value, err := service.FingerprintCrash(crash)
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	case "dedupe":
		flags := flag.NewFlagSet("crash dedupe", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var path string
		flags.StringVar(&path, "json", "", "JSON file containing an array of crash records")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || strings.TrimSpace(path) == "" {
			return errors.New("usage: ReverseResearch crash dedupe --json <crashes.json>")
		}
		var crashes []fuzz.Crash
		if err := readJSONFile(path, &crashes); err != nil {
			return err
		}
		value, err := service.DedupeCrashes(crashes)
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	case "record":
		flags := flag.NewFlagSet("crash record", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var caseID, inputPath, crashPath string
		flags.StringVar(&caseID, "case", "", "required vuln-research Case ID")
		flags.StringVar(&inputPath, "input", "", "current crash reproducer input")
		flags.StringVar(&crashPath, "json", "", "JSON file containing one crash record")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || caseID == "" || inputPath == "" || crashPath == "" {
			return errors.New("usage: ReverseResearch crash record --case <id> --input <path> --json <crash.json>")
		}
		var crash fuzz.Crash
		if err := readJSONFile(crashPath, &crash); err != nil {
			return err
		}
		value, err := service.RecordCrash(researchcore.CrashRecordRequest{CaseID: caseID, InputPath: inputPath, Crash: crash})
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	default:
		return fmt.Errorf("unknown crash subcommand %q", args[0])
	}
}

func runProtocolCLI(service *researchcore.Service, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("protocol subcommand is required: infer or validate")
	}
	switch args[0] {
	case "infer":
		flags := flag.NewFlagSet("protocol infer", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var request researchcore.ProtocolFileRequest
		flags.StringVar(&request.SamplesPath, "samples", "", "JSON array of {name,hex} messages")
		flags.StringVar(&request.CaseID, "case", "", "optional traffic-protocol Case ID")
		flags.StringVar(&request.Name, "name", "candidate_protocol", "candidate schema id")
		flags.Int64Var(&request.MaxBytes, "max-bytes", 32<<20, "maximum message corpus JSON bytes")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || strings.TrimSpace(request.SamplesPath) == "" {
			return errors.New("usage: ReverseResearch protocol infer --samples <messages.json> [options]")
		}
		value, err := service.InferProtocolFile(request)
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	case "validate":
		flags := flag.NewFlagSet("protocol validate", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var request researchcore.ProtocolValidationRequest
		flags.StringVar(&request.ModelSamplesPath, "model", "", "model-discovery sample corpus JSON")
		flags.StringVar(&request.FixturesPath, "fixtures", "", "independent validation fixture corpus JSON")
		flags.StringVar(&request.CaseID, "case", "", "optional traffic-protocol Case ID")
		flags.StringVar(&request.Name, "name", "candidate_protocol", "candidate schema id")
		flags.Int64Var(&request.MaxBytes, "max-bytes", 32<<20, "maximum bytes per JSON corpus")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || strings.TrimSpace(request.ModelSamplesPath) == "" || strings.TrimSpace(request.FixturesPath) == "" {
			return errors.New("usage: ReverseResearch protocol validate --model <model.json> --fixtures <fixtures.json> [options]")
		}
		value, err := service.ValidateProtocol(request)
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	default:
		return fmt.Errorf("unknown protocol subcommand %q", args[0])
	}
}

func runSourceCLI(service *researchcore.Service, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("source subcommand is required: audit, sarif, or sbom")
	}
	switch args[0] {
	case "audit":
		if len(args) < 2 {
			return errors.New("usage: ReverseResearch source audit <repo> [--case <id>] [bounds]")
		}
		flags := flag.NewFlagSet("source audit", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var request researchcore.SourceAuditRequest
		request.Root = args[1]
		flags.StringVar(&request.CaseID, "case", "", "optional source-code-audit/supply-chain Case ID")
		flags.IntVar(&request.Options.MaxFiles, "max-files", sourceaudit.DefaultMaxFiles, "maximum regular files")
		flags.Int64Var(&request.Options.MaxFileBytes, "max-file-bytes", sourceaudit.DefaultMaxFileBytes, "maximum bytes read from one file")
		flags.Int64Var(&request.Options.MaxTotalBytes, "max-total-bytes", sourceaudit.DefaultMaxTotalBytes, "maximum aggregate bytes read")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected positional arguments after source audit")
		}
		value, err := service.AuditSource(request)
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	case "sarif":
		if len(args) < 2 {
			return errors.New("usage: ReverseResearch source sarif <file> [--case <id>] [bounds]")
		}
		flags := flag.NewFlagSet("source sarif", flag.ContinueOnError)
		flags.SetOutput(stderr)
		request := researchcore.SARIFImportRequest{Path: args[1]}
		flags.StringVar(&request.CaseID, "case", "", "optional source-code-audit/supply-chain Case ID")
		flags.Int64Var(&request.MaxBytes, "max-bytes", sourceaudit.DefaultMaxSARIFBytes, "maximum SARIF bytes")
		flags.IntVar(&request.MaxResults, "max-results", sourceaudit.DefaultMaxSARIFResults, "maximum SARIF results")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected positional arguments after source sarif")
		}
		value, err := service.ImportSARIF(request)
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	case "sbom":
		if len(args) < 2 {
			return errors.New("usage: ReverseResearch source sbom <file> [--case <id>] [bounds]")
		}
		flags := flag.NewFlagSet("source sbom", flag.ContinueOnError)
		flags.SetOutput(stderr)
		request := researchcore.SBOMImportRequest{Path: args[1]}
		flags.StringVar(&request.CaseID, "case", "", "optional source-code-audit/supply-chain Case ID")
		flags.Int64Var(&request.MaxBytes, "max-bytes", sourceaudit.DefaultMaxSBOMBytes, "maximum SBOM bytes")
		flags.IntVar(&request.MaxComponents, "max-components", sourceaudit.DefaultMaxSBOMComponents, "maximum SBOM components")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected positional arguments after source sbom")
		}
		value, err := service.ImportSBOM(request)
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	default:
		return fmt.Errorf("unknown source subcommand %q", args[0])
	}
}

func readJSONFile(path string, destination any) error {
	body, err := os.ReadFile(strings.TrimSpace(path))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, destination); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

func p1ResearchHelp(w io.Writer) {
	fmt.Fprintln(w, "  ReverseResearch dfir inspect <artifact> [--case <id>]")
	fmt.Fprintln(w, "  ReverseResearch dfir timeline <jsonl> [--format <adapter>] [--case <id>]")
	fmt.Fprintln(w, "  ReverseResearch fuzz plan --target <path> --harness <path> --corpus <dir> --engine <engine> [--case <id>]")
	fmt.Fprintln(w, "  ReverseResearch crash fingerprint|dedupe --json <file> | crash record --case <id> --input <path> --json <file>")
	fmt.Fprintln(w, "  ReverseResearch protocol infer --samples <messages.json> [--case <id>] [--name <id>]")
	fmt.Fprintln(w, "  ReverseResearch protocol validate --model <model.json> --fixtures <fixtures.json> [--case <id>] [--name <id>]")
	fmt.Fprintln(w, "  ReverseResearch source audit <repo> [--case <id>] [bounds]")
	fmt.Fprintln(w, "  ReverseResearch source sarif <file> [--case <id>] [bounds] | source sbom <file> [--case <id>] [bounds]")
}
