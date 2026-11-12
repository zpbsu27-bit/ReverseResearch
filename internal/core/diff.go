package core

import (
	"context"
	"errors"

	"reverseresearch/internal/bindiff"
)

func (s *Service) QuickDiff(ctx context.Context, leftPath, rightPath string, options ...bindiff.Options) (bindiff.QuickResult, error) {
	analyzer, err := s.binaryDiffAnalyzer()
	if err != nil {
		return bindiff.QuickResult{}, err
	}
	return analyzer.Quick(ctx, leftPath, rightPath, options...)
}

func (s *Service) FunctionDiff(ctx context.Context, leftPath, rightPath string, threshold int, options ...bindiff.Options) (bindiff.FunctionResult, error) {
	analyzer, err := s.binaryDiffAnalyzer()
	if err != nil {
		return bindiff.FunctionResult{}, err
	}
	return analyzer.Functions(ctx, leftPath, rightPath, threshold, options...)
}

func (s *Service) binaryDiffAnalyzer() (*bindiff.Analyzer, error) {
	index, err := s.ScanTools()
	if err != nil {
		return nil, err
	}
	tool, ok := index.ByName("radiff2")
	if !ok || !tool.Available || tool.Path == "" {
		return nil, errors.New("radiff2 is unavailable; run ReverseResearch tools scan")
	}
	return bindiff.New(tool.Path)
}
