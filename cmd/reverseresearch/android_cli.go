package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"strings"

	"reverseresearch/internal/androidinspect"
	researchcore "reverseresearch/internal/core"
)

func runAndroidCLI(ctx context.Context, service *researchcore.Service, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("android subcommand is required: status, devices, probe, workspace, snapshot, or tap")
	}
	switch args[0] {
	case "status":
		if len(args) != 1 {
			return errors.New("usage: ReverseResearch android status")
		}
		result, err := service.AndroidStatus()
		if err != nil {
			return err
		}
		return writeJSON(stdout, result)
	case "devices":
		if len(args) != 1 {
			return errors.New("usage: ReverseResearch android devices")
		}
		result, err := service.AndroidDevices(ctx)
		if err != nil {
			return err
		}
		return writeJSON(stdout, result)
	case "probe":
		if len(args) != 2 {
			return errors.New("usage: ReverseResearch android probe <serial>")
		}
		result, err := service.ProbeAndroidDevice(ctx, args[1])
		if err != nil {
			return err
		}
		return writeJSON(stdout, result)
	case "workspace":
		if len(args) != 2 {
			return errors.New("usage: ReverseResearch android workspace <serial>")
		}
		result, err := service.PrepareAndroidWorkspace(args[1])
		if err != nil {
			return err
		}
		return writeJSON(stdout, result)
	case "snapshot":
		if len(args) != 2 {
			return errors.New("usage: ReverseResearch android snapshot <serial>")
		}
		result, err := service.SnapshotAndroidUI(ctx, args[1])
		if err != nil {
			return err
		}
		return writeJSON(stdout, result)
	case "tap":
		if len(args) < 2 {
			return errors.New("usage: ReverseResearch android tap <serial> --snapshot <id> --ui-sha <sha256> --operation-id <id> (--resource-id <id> | --text <text> | --content-desc <text>)")
		}
		serial := args[1]
		flags := flag.NewFlagSet("android tap", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var snapshotID, uiSHA, operationID string
		var selector androidinspect.Selector
		flags.StringVar(&snapshotID, "snapshot", "", "snapshot id")
		flags.StringVar(&uiSHA, "ui-sha", "", "expected UI hierarchy SHA-256")
		flags.StringVar(&operationID, "operation-id", "", "one-shot operation id")
		flags.StringVar(&selector.ResourceID, "resource-id", "", "exact Android resource-id")
		flags.StringVar(&selector.Text, "text", "", "exact node text")
		flags.StringVar(&selector.ContentDesc, "content-desc", "", "exact content-desc")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || strings.TrimSpace(snapshotID) == "" || strings.TrimSpace(uiSHA) == "" || strings.TrimSpace(operationID) == "" {
			return errors.New("usage: ReverseResearch android tap <serial> --snapshot <id> --ui-sha <sha256> --operation-id <id> (--resource-id <id> | --text <text> | --content-desc <text>)")
		}
		result, err := service.TapAndroidUI(ctx, androidinspect.TapRequest{
			Serial: serial, SnapshotID: snapshotID, ExpectedUISHA256: uiSHA, Selector: selector, OperationID: operationID,
		})
		if err != nil {
			return err
		}
		return writeJSON(stdout, result)
	default:
		return errors.New("unknown android subcommand; expected status, devices, probe, workspace, snapshot, or tap")
	}
}
