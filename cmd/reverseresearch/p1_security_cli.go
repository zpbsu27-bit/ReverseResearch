package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	researchcore "reverseresearch/internal/core"
	"reverseresearch/internal/malware"
)

func runMalwareCLI(ctx context.Context, service *researchcore.Service, args []string, stdout, stderr io.Writer) error {
	if len(args) < 2 || args[0] != "triage" {
		return errors.New("usage: ReverseResearch malware triage <path> [--case <id>] [--die=true] [--max-bytes N] [--min-string N] [--max-strings N]")
	}
	path := args[1]
	flags := flag.NewFlagSet("malware triage", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var request researchcore.MalwareTriageRequest
	request.Path = path
	flags.StringVar(&request.CaseID, "case", "", "optional malware-analysis Case ID")
	flags.BoolVar(&request.Options.UseDIE, "die", true, "run the pinned Detect It Easy static scanner")
	flags.Int64Var(&request.Options.MaxBytes, "max-bytes", malware.DefaultMaxBytes, "maximum sample bytes to read")
	flags.IntVar(&request.Options.MinStringLength, "min-string", malware.DefaultMinStringLength, "minimum bounded printable string length")
	flags.IntVar(&request.Options.MaxStrings, "max-strings", malware.DefaultMaxStrings, "maximum string samples to return")
	if err := flags.Parse(args[2:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments after malware triage")
	}
	result, err := service.TriageMalware(ctx, request)
	if err != nil {
		return err
	}
	return writeJSON(stdout, result)
}

func runDetectionCLI(service *researchcore.Service, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "sigma" {
		return errors.New("usage: ReverseResearch detection sigma --rule <path> --positive <p,p> --negative <n,n> [--case <id>] [metadata]")
	}
	flags := flag.NewFlagSet("detection sigma", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var request researchcore.SigmaValidationRequest
	var positivesRaw, negativesRaw, telemetryRaw string
	flags.StringVar(&request.RulePath, "rule", "", "Sigma YAML rule path")
	flags.StringVar(&positivesRaw, "positive", "", "comma-separated positive JSON fixture paths")
	flags.StringVar(&negativesRaw, "negative", "", "comma-separated negative JSON fixture paths")
	flags.StringVar(&request.CaseID, "case", "", "optional blue/purple/malware Case ID")
	flags.StringVar(&request.Name, "name", "", "detection name; defaults to Sigma title")
	flags.StringVar(&request.Technique, "technique", "", "optional ATT&CK technique")
	flags.StringVar(&telemetryRaw, "telemetry", "", "comma-separated telemetry requirements")
	flags.BoolVar(&request.TelemetryAvailable, "telemetry-available", false, "record that required telemetry is currently available")
	flags.StringVar(&request.FalsePositiveNotes, "false-positive-notes", "", "required for Case-bound validation")
	flags.StringVar(&request.Coverage, "coverage", "", "required coverage statement for Case-bound validation")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments after detection sigma")
	}
	request.PositiveFixtures = splitCSV(positivesRaw)
	request.NegativeFixtures = splitCSV(negativesRaw)
	request.Telemetry = splitCSV(telemetryRaw)
	if strings.TrimSpace(request.RulePath) == "" {
		return errors.New("--rule is required")
	}
	result, err := service.ValidateSigma(request)
	if err != nil {
		return err
	}
	return writeJSON(stdout, result)
}

func p1SecurityHelp(w io.Writer) {
	fmt.Fprintln(w, "  ReverseResearch malware triage <path> [--case <id>] [--die=true] [--max-bytes N] [--min-string N] [--max-strings N]")
	fmt.Fprintln(w, "  ReverseResearch detection sigma --rule <path> --positive <p,p> --negative <n,n> [--case <id> --telemetry <t,t> --telemetry-available --false-positive-notes <text> --coverage <text>]")
}
