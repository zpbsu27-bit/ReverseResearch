package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	researchcore "reverseresearch/internal/core"
)

func runAttackGraphCLI(service *researchcore.Service, args []string, stdout, stderr io.Writer) error {
	if len(args) < 2 || args[0] != "import" {
		return errors.New("usage: ReverseResearch attackgraph import <graph.json> [--case <id>] [--from <node> --to <node> --max-depth N]")
	}
	flags := flag.NewFlagSet("attackgraph import", flag.ContinueOnError)
	flags.SetOutput(stderr)
	request := researchcore.AttackGraphImportRequest{Path: args[1]}
	flags.StringVar(&request.CaseID, "case", "", "optional compatible Case ID")
	flags.StringVar(&request.From, "from", "", "optional source node for bounded shortest-path analysis")
	flags.StringVar(&request.To, "to", "", "optional target node for bounded shortest-path analysis")
	flags.IntVar(&request.MaxDepth, "max-depth", 12, "maximum directed path depth")
	flags.Int64Var(&request.MaxBytes, "max-bytes", 64<<20, "maximum graph JSON bytes")
	if err := flags.Parse(args[2:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments after attackgraph import")
	}
	value, err := service.ImportAttackGraph(request)
	if err != nil {
		return err
	}
	return writeJSON(stdout, value)
}

func runCloudCLI(service *researchcore.Service, args []string, stdout, stderr io.Writer) error {
	if len(args) < 2 || args[0] != "inventory" {
		return errors.New("usage: ReverseResearch cloud inventory <snapshot.json> [--case <id>] [--max-bytes N]")
	}
	flags := flag.NewFlagSet("cloud inventory", flag.ContinueOnError)
	flags.SetOutput(stderr)
	request := researchcore.CloudInventoryRequest{Path: args[1]}
	flags.StringVar(&request.CaseID, "case", "", "optional cloud-security/container-k8s/identity-ad Case ID")
	flags.Int64Var(&request.MaxBytes, "max-bytes", 64<<20, "maximum snapshot JSON bytes")
	if err := flags.Parse(args[2:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments after cloud inventory")
	}
	value, err := service.ImportCloudInventory(request)
	if err != nil {
		return err
	}
	return writeJSON(stdout, value)
}

func runCTICLI(service *researchcore.Service, args []string, stdout, stderr io.Writer) error {
	if len(args) < 2 || args[0] != "import" {
		return errors.New("usage: ReverseResearch cti import <stix-bundle.json> [--case <id>] [bounds]")
	}
	flags := flag.NewFlagSet("cti import", flag.ContinueOnError)
	flags.SetOutput(stderr)
	request := researchcore.STIXImportRequest{Path: args[1]}
	flags.StringVar(&request.CaseID, "case", "", "optional cti-analysis/threat-hunting/malware-analysis Case ID")
	flags.Int64Var(&request.MaxBytes, "max-bytes", 64<<20, "maximum STIX bytes")
	flags.IntVar(&request.MaxObjects, "max-objects", 50000, "maximum STIX objects")
	if err := flags.Parse(args[2:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments after cti import")
	}
	value, err := service.ImportSTIX(request)
	if err != nil {
		return err
	}
	return writeJSON(stdout, value)
}

func runHuntCLI(service *researchcore.Service, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "plan" {
		return errors.New("usage: ReverseResearch hunt plan --hypothesis <text> --telemetry <t,t> [--techniques <T,T>] [--adapters <a,a>] [--case <id>]")
	}
	flags := flag.NewFlagSet("hunt plan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var request researchcore.HuntPlanRequest
	var techniques, telemetry, adapters string
	flags.StringVar(&request.CaseID, "case", "", "optional threat-hunting/cti-analysis/blue-detection Case ID")
	flags.StringVar(&request.Hypothesis, "hypothesis", "", "hunt hypothesis")
	flags.StringVar(&techniques, "techniques", "", "comma-separated ATT&CK techniques")
	flags.StringVar(&telemetry, "telemetry", "", "comma-separated telemetry sources")
	flags.StringVar(&adapters, "adapters", "", "comma-separated query/detection adapters")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected hunt plan arguments: %s", strings.Join(flags.Args(), " "))
	}
	request.Techniques = splitCSV(techniques)
	request.Telemetry = splitCSV(telemetry)
	request.Adapters = splitCSV(adapters)
	value, err := service.BuildHuntPlan(request)
	if err != nil {
		return err
	}
	return writeJSON(stdout, value)
}

func runIOSCLI(service *researchcore.Service, args []string, stdout, stderr io.Writer) error {
	if len(args) > 0 && args[0] != "inspect" {
		return runAppleSerializationCLI(service, args, stdout, stderr)
	}
	if len(args) < 2 || args[0] != "inspect" {
		return errors.New("usage: ReverseResearch ios inspect <app.ipa> [--case <id>]")
	}
	flags := flag.NewFlagSet("ios inspect", flag.ContinueOnError)
	flags.SetOutput(stderr)
	request := researchcore.IOSInspectRequest{Path: args[1]}
	flags.StringVar(&request.CaseID, "case", "", "optional ios Case ID")
	if err := flags.Parse(args[2:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments after ios inspect")
	}
	value, err := service.InspectIOS(request)
	if err != nil {
		return err
	}
	return writeJSON(stdout, value)
}

func runFirmwareCLI(service *researchcore.Service, args []string, stdout, stderr io.Writer) error {
	if len(args) < 2 || args[0] != "inspect" {
		return errors.New("usage: ReverseResearch firmware inspect <image> [--case <id>]")
	}
	flags := flag.NewFlagSet("firmware inspect", flag.ContinueOnError)
	flags.SetOutput(stderr)
	request := researchcore.FirmwareInspectRequest{Path: args[1]}
	flags.StringVar(&request.CaseID, "case", "", "optional firmware-iot Case ID")
	if err := flags.Parse(args[2:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments after firmware inspect")
	}
	value, err := service.InspectFirmware(request)
	if err != nil {
		return err
	}
	return writeJSON(stdout, value)
}

func p2SecurityHelp(w io.Writer) {
	fmt.Fprintln(w, "  ReverseResearch attackgraph import <graph.json> [--case <id>] [--from <node> --to <node> --max-depth N]")
	fmt.Fprintln(w, "  ReverseResearch cloud inventory <snapshot.json> [--case <id>]")
	fmt.Fprintln(w, "  ReverseResearch cti import <stix-bundle.json> [--case <id>]")
	fmt.Fprintln(w, "  ReverseResearch hunt plan --hypothesis <text> --telemetry <t,t> [--techniques <T,T>] [--adapters <a,a>] [--case <id>]")
	fmt.Fprintln(w, "  ReverseResearch ios inspect <app.ipa> [--case <id>]")
	fmt.Fprintln(w, "  ReverseResearch firmware inspect <image> [--case <id>]")
}
