package core

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"reverseresearch/internal/capability"
	"reverseresearch/internal/domainpack"
	"reverseresearch/internal/knowledgepack"
	"reverseresearch/internal/playbook"
	"reverseresearch/internal/provision"
	"reverseresearch/internal/router"
	"reverseresearch/internal/sandbox"
)

type Preparation struct {
	Task           string               `json:"task"`
	Route          router.Result        `json:"route"`
	Playbook       *playbook.Playbook   `json:"playbook,omitempty"`
	DomainPack     *domainpack.Pack     `json:"domain_pack,omitempty"`
	KnowledgePacks []knowledgepack.Pack `json:"knowledge_packs,omitempty"`
	Capability     capability.Status    `json:"capability"`
	Provision      provision.Plan       `json:"provision"`
	Sandbox        sandbox.Plan         `json:"sandbox"`
}

func (s *Service) Prepare(task string) (Preparation, error) {
	task = strings.TrimSpace(task)
	if task == "" {
		return Preparation{}, errors.New("task text is required")
	}

	routed, err := s.Route(task)
	if err != nil {
		return Preparation{}, err
	}
	status, err := s.CapabilityStatus(routed.Route.ID)
	if err != nil {
		return Preparation{}, err
	}

	var toolPlan provision.Plan
	if len(routed.Route.Tools) > 0 {
		toolPlan, err = s.PlanTools(routed.Route.Tools)
		if err != nil {
			return Preparation{}, err
		}
	}

	sandboxPlan, err := s.PlanSandbox(sandbox.PlanRequest{
		Name:  "prepare-" + routed.Route.ID,
		Route: routed.Route.ID,
		Kind:  recommendedSandbox(routed.Route.ID),
	})
	if err != nil {
		return Preparation{}, err
	}

	var selected *playbook.Playbook
	if value, ok, err := s.PlaybookForRoute(routed.Route.ID); err != nil {
		return Preparation{}, err
	} else if ok {
		valueCopy := value
		selected = &valueCopy
	}

	registry, err := domainpack.Load(s.root, filepath.Join(s.root, "config", "domain-packs.json"))
	if err != nil {
		return Preparation{}, err
	}
	var selectedPack *domainpack.Pack
	if value, ok := registry.ForRoute(routed.Route.ID); ok {
		valueCopy := value
		selectedPack = &valueCopy
	}

	applicableKnowledge, err := s.KnowledgePacksForRoute(routed.Route.ID)
	if err != nil {
		return Preparation{}, err
	}
	if selectedPack != nil && len(selectedPack.KnowledgePacks) > 0 {
		available := make(map[string]knowledgepack.Pack, len(applicableKnowledge))
		for _, pack := range applicableKnowledge {
			available[pack.ID] = pack
		}
		selectedKnowledge := make([]knowledgepack.Pack, 0, len(selectedPack.KnowledgePacks))
		for _, id := range selectedPack.KnowledgePacks {
			pack, ok := available[id]
			if !ok {
				return Preparation{}, fmt.Errorf("domain pack %s references knowledge pack %q that is not valid for route %s", selectedPack.ID, id, routed.Route.ID)
			}
			selectedKnowledge = append(selectedKnowledge, pack)
		}
		applicableKnowledge = selectedKnowledge
	}

	return Preparation{
		Task: task, Route: routed, Playbook: selected, DomainPack: selectedPack,
		KnowledgePacks: applicableKnowledge, Capability: status, Provision: toolPlan, Sandbox: sandboxPlan,
	}, nil
}

func recommendedSandbox(routeID string) sandbox.Kind {
	switch routeID {
	case "pwn-exploit", "ctf-sandbox", "pentest-network", "firmware-iot":
		return sandbox.KindWSL
	default:
		return sandbox.KindFilesystem
	}
}
