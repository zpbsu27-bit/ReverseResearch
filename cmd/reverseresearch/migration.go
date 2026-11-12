package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	researchcore "reverseresearch/internal/core"
	"reverseresearch/internal/migration"
)

func runMigrationCLI(ctx context.Context, service *researchcore.Service, args []string, stdout, stderr io.Writer) error {
	if len(args) < 2 {
		return errors.New("usage: ReverseResearch diff migrate <old-file> <new-file> --anchors <json-file> [--threshold 70]")
	}
	flags := flag.NewFlagSet("diff migrate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	anchorPath := flags.String("anchors", "", "JSON array of labeled old_rva and/or old_name selectors")
	threshold := flags.Int("threshold", 70, "minimum similarity from 1 to 100")
	if err := flags.Parse(args[2:]); err != nil {
		return err
	}
	if flags.NArg() != 0 || strings.TrimSpace(*anchorPath) == "" || *threshold < 1 || *threshold > 100 {
		return errors.New("anchors JSON is required and threshold must be between 1 and 100")
	}
	anchors, err := loadMigrationAnchors(*anchorPath)
	if err != nil {
		return err
	}
	result, err := service.MigrateFunctions(ctx, args[0], args[1], *threshold, anchors)
	if err != nil {
		return err
	}
	return writeJSON(stdout, result)
}

func loadMigrationAnchors(path string) (anchors []migration.Anchor, err error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("anchors must be a regular JSON file")
	}
	const maxBytes = 1 << 20
	body, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxBytes {
		return nil, errors.New("anchors file exceeds 1 MiB")
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&anchors); err != nil {
		return nil, fmt.Errorf("decode migration anchors: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("anchors JSON must contain exactly one array")
	}
	if err := migration.ValidateAnchors(anchors); err != nil {
		return nil, err
	}
	return anchors, nil
}
