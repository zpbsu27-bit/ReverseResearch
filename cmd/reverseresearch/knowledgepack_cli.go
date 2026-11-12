package main

import (
	"errors"
	"fmt"
	"io"

	researchcore "reverseresearch/internal/core"
)

func runKnowledgePackCLI(service *researchcore.Service, args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("knowledge-pack subcommand is required: list, show, or route")
	}
	switch args[0] {
	case "list":
		if len(args) != 1 {
			return errors.New("usage: ReverseResearch knowledge-pack list")
		}
		value, err := service.ListKnowledgePacks()
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	case "show":
		if len(args) != 2 {
			return errors.New("usage: ReverseResearch knowledge-pack show <pack-id>")
		}
		value, err := service.GetKnowledgePack(args[1])
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	case "route":
		if len(args) != 2 {
			return errors.New("usage: ReverseResearch knowledge-pack route <route-id>")
		}
		value, err := service.KnowledgePacksForRoute(args[1])
		if err != nil {
			return err
		}
		if len(value) == 0 {
			return fmt.Errorf("route %q has no knowledge packs", args[1])
		}
		return writeJSON(stdout, value)
	default:
		return fmt.Errorf("unknown knowledge-pack subcommand %q", args[0])
	}
}
