package core

import (
	"context"
	"path/filepath"

	"reverseresearch/internal/memscan"
)

func (s *Service) StartMemoryScan(ctx context.Context, request memscan.StartRequest) (memscan.Summary, error) {
	manager, err := memscan.New(filepath.Join(s.root, "state", "memory-scans"))
	if err != nil {
		return memscan.Summary{}, err
	}
	return manager.Start(ctx, request)
}

func (s *Service) RefineMemoryScan(ctx context.Context, request memscan.RefineRequest) (memscan.Summary, error) {
	manager, err := memscan.New(filepath.Join(s.root, "state", "memory-scans"))
	if err != nil {
		return memscan.Summary{}, err
	}
	return manager.Refine(ctx, request)
}

func (s *Service) GetMemoryScan(scanID string, sampleLimit int) (memscan.Summary, error) {
	manager, err := memscan.New(filepath.Join(s.root, "state", "memory-scans"))
	if err != nil {
		return memscan.Summary{}, err
	}
	return manager.Get(scanID, sampleLimit)
}

func (s *Service) DeleteMemoryScan(ctx context.Context, request memscan.DeleteRequest) (memscan.DeleteResult, error) {
	manager, err := memscan.New(filepath.Join(s.root, "state", "memory-scans"))
	if err != nil {
		return memscan.DeleteResult{}, err
	}
	return manager.Delete(ctx, request)
}
