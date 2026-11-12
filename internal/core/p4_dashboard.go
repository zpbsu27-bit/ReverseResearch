package core

import (
	"errors"
	"os"
	"path/filepath"
	"time"

	"reverseresearch/internal/packregistry"
	"reverseresearch/internal/remoteagent"
)

func (s *Service) dashboardAgentFleetProjection() ([]remoteagent.FleetEntry, error) {
	root := filepath.Join(s.root, "state", "remote-agents")
	info, err := os.Stat(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("remote agent state root is not a directory")
	}
	store, err := remoteagent.NewStore(root)
	if err != nil {
		return nil, err
	}
	return store.ListFleet(
		time.Now().UTC(),
		time.Duration(defaultAgentStaleAfterSeconds)*time.Second,
		time.Duration(defaultAgentOfflineAfterSeconds)*time.Second,
	)
}

func (s *Service) dashboardPackRegistryProjection() (*packregistry.RegistryState, error) {
	root := filepath.Join(s.root, "state", "pack-registry")
	info, err := os.Stat(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("pack registry state root is not a directory")
	}
	registry, err := packregistry.NewRegistry(root)
	if err != nil {
		return nil, err
	}
	state, err := registry.GetHot()
	if err != nil {
		return nil, err
	}
	return &state, nil
}
