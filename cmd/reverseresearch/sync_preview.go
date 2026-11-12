package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	researchcore "reverseresearch/internal/core"
	"reverseresearch/internal/migration"
)

func runSyncCLI(service *researchcore.Service, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "preview" {
		return errors.New("usage: ReverseResearch sync preview --json-file <request.json>")
	}
	flags := flag.NewFlagSet("sync preview", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var jsonFile string
	flags.StringVar(&jsonFile, "json-file", "", "semantic sync preview request JSON")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 || jsonFile == "" {
		return errors.New("usage: ReverseResearch sync preview --json-file <request.json>")
	}
	body, err := os.ReadFile(jsonFile)
	if err != nil {
		return fmt.Errorf("read semantic sync preview request: %w", err)
	}
	var request migration.SyncPreviewRequest
	if err := json.Unmarshal(body, &request); err != nil {
		return fmt.Errorf("decode semantic sync preview request: %w", err)
	}
	result, err := service.PreviewSemanticSync(request)
	if err != nil {
		return err
	}
	return writeJSON(stdout, result)
}
