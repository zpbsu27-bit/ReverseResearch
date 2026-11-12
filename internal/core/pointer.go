package core

import (
	"context"
	"path/filepath"

	"reverseresearch/internal/pointermap"
)

func (s *Service) BuildPointerMap(ctx context.Context, request pointermap.BuildRequest) (pointermap.Summary, error) {
	manager, err := pointermap.New(filepath.Join(s.root, "state", "pointer-maps"))
	if err != nil {
		return pointermap.Summary{}, err
	}
	return manager.Build(ctx, request)
}

func (s *Service) GetPointerMap(mapID string, sampleLimit int) (pointermap.Summary, error) {
	manager, err := pointermap.New(filepath.Join(s.root, "state", "pointer-maps"))
	if err != nil {
		return pointermap.Summary{}, err
	}
	return manager.Get(mapID, sampleLimit)
}

func (s *Service) DeletePointerMap(ctx context.Context, request pointermap.DeleteRequest) (pointermap.DeleteResult, error) {
	manager, err := pointermap.New(filepath.Join(s.root, "state", "pointer-maps"))
	if err != nil {
		return pointermap.DeleteResult{}, err
	}
	return manager.Delete(ctx, request)
}

func (s *Service) VerifyPointerMap(ctx context.Context, request pointermap.VerifyRequest) (pointermap.Verification, error) {
	manager, err := pointermap.New(filepath.Join(s.root, "state", "pointer-maps"))
	if err != nil {
		return pointermap.Verification{}, err
	}
	return manager.Verify(ctx, request)
}
