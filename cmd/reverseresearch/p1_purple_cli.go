package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	researchcore "reverseresearch/internal/core"
)

func runPurpleCLI(service *researchcore.Service, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("purple subcommand is required: coverage or plan")
	}
	switch args[0] {
	case "coverage":
		if len(args) != 2 {
			return errors.New("usage: ReverseResearch purple coverage <case-id>")
		}
		value, err := service.PurpleCoverage(args[1])
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	case "plan":
		if len(args) < 2 {
			return errors.New("usage: ReverseResearch purple plan <case-id> --technique <T...> --target <target> --action <action> --effect-class <class> --operation-id <id>")
		}
		flags := flag.NewFlagSet("purple plan", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var request researchcore.PurpleEmulationPlanRequest
		request.CaseID = args[1]
		var evidenceRaw string
		flags.StringVar(&request.Technique, "technique", "", "ATT&CK technique already present in the Case")
		flags.StringVar(&request.Target, "target", "", "Case-bound target identity")
		flags.StringVar(&request.Action, "action", "", "Engagement-allowed emulation action")
		flags.StringVar(&request.EffectClass, "effect-class", "", "local mutation|runtime mutation|active network interaction")
		flags.StringVar(&request.OperationID, "operation-id", "", "idempotent Generic Job operation identity")
		flags.StringVar(&request.ToolIdentity, "tool-identity", "", "optional current tool identity")
		flags.StringVar(&evidenceRaw, "evidence", "", "comma-separated existing Case evidence IDs")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return fmt.Errorf("unexpected purple plan arguments: %s", strings.Join(flags.Args(), " "))
		}
		request.EvidenceIDs = splitCSV(evidenceRaw)
		value, err := service.PreparePurpleEmulation(request)
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	default:
		return fmt.Errorf("unknown purple subcommand %q", args[0])
	}
}

func p1PurpleHelp(w io.Writer) {
	fmt.Fprintln(w, "  ReverseResearch purple coverage <case-id>")
	fmt.Fprintln(w, "  ReverseResearch purple plan <case-id> --technique <T...> --target <target> --action <action> --effect-class <class> --operation-id <id>")
}
