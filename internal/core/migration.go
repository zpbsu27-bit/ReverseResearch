package core

import (
	"context"
	"errors"
	"reverseresearch/internal/bindiff"

	"reverseresearch/internal/migration"
)

// MigrateFunctions produces a candidate plan only. It does not rename symbols,
// write either binary, attach a debugger, or claim runtime verification.
func (s *Service) MigrateFunctions(ctx context.Context, oldPath, newPath string, threshold int, anchors []migration.Anchor, options ...bindiff.Options) (migration.Result, error) {
	if threshold < 1 || threshold > 100 {
		return migration.Result{}, errors.New("migration threshold must be between 1 and 100")
	}
	if err := migration.ValidateAnchors(anchors); err != nil {
		return migration.Result{}, err
	}
	diff, err := s.FunctionDiff(ctx, oldPath, newPath, threshold, options...)
	if err != nil {
		return migration.Result{}, err
	}
	return migration.Resolve(diff, anchors)
}

// PreviewSemanticSync produces a deterministic, preview-only semantic delta.
// It never starts Ghidra and never mutates either semantic snapshot.
func (s *Service) PreviewSemanticSync(request migration.SyncPreviewRequest) (migration.SyncPreview, error) {
	return migration.PreviewSemanticSync(request)
}
