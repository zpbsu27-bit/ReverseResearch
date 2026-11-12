package core

import (
	"path/filepath"

	"reverseresearch/internal/playbook"
)

func (s *Service) playbookRegistry() (*playbook.Registry, error) {
	return playbook.Load(s.root, filepath.Join(s.root, "config", "playbooks.json"))
}

func (s *Service) GetPlaybook(playbookID string) (playbook.Playbook, error) {
	registry, err := s.playbookRegistry()
	if err != nil {
		return playbook.Playbook{}, err
	}
	return registry.Get(playbookID)
}

func (s *Service) PlaybookForRoute(routeID string) (playbook.Playbook, bool, error) {
	registry, err := s.playbookRegistry()
	if err != nil {
		return playbook.Playbook{}, false, err
	}
	value, ok := registry.ForRoute(routeID)
	return value, ok, nil
}

func (s *Service) ListPlaybooks() ([]playbook.Playbook, error) {
	registry, err := s.playbookRegistry()
	if err != nil {
		return nil, err
	}
	return registry.List(), nil
}
