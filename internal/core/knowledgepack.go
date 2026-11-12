package core

import (
	"path/filepath"

	"reverseresearch/internal/knowledgepack"
)

func (s *Service) ListKnowledgePacks() ([]knowledgepack.Pack, error) {
	registry, err := knowledgepack.Load(filepath.Join(s.root, "config", "knowledge-packs.json"), s.knowledge)
	if err != nil {
		return nil, err
	}
	return registry.List(), nil
}

func (s *Service) GetKnowledgePack(id string) (knowledgepack.Pack, error) {
	registry, err := knowledgepack.Load(filepath.Join(s.root, "config", "knowledge-packs.json"), s.knowledge)
	if err != nil {
		return knowledgepack.Pack{}, err
	}
	return registry.Get(id)
}

func (s *Service) KnowledgePacksForRoute(routeID string) ([]knowledgepack.Pack, error) {
	registry, err := knowledgepack.Load(filepath.Join(s.root, "config", "knowledge-packs.json"), s.knowledge)
	if err != nil {
		return nil, err
	}
	return registry.ForRoute(routeID), nil
}
