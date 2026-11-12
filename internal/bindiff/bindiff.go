package bindiff

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"reverseresearch/internal/targetidentity"
	"reverseresearch/internal/toolprocess"
)

type Analyzer struct {
	radiff2 string
}

// Options fences a caller's already-selected target versions without another
// preflight hash pass. The analyzer still rechecks both inputs after execution.
type Options struct {
	ExpectedLeftSHA256  string
	ExpectedRightSHA256 string
}

var ErrOutputLimit = errors.New("radiff2 output exceeded the bounded analysis budget; no result accepted")

type FileInfo struct {
	Filename string `json:"filename"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
}

type QuickResult struct {
	Comparison  targetidentity.Comparison `json:"comparison"`
	Files       []FileInfo                `json:"files,omitempty"`
	Changes     []map[string]any          `json:"changes,omitempty"`
	ChangeCount int                       `json:"change_count"`
}

type FunctionMatch struct {
	OldVA      uint64  `json:"old_va"`
	OldRVA     uint64  `json:"old_rva"`
	OldName    string  `json:"old_name"`
	OldSize    int64   `json:"old_size"`
	NewVA      uint64  `json:"new_va"`
	NewRVA     uint64  `json:"new_rva"`
	NewName    string  `json:"new_name"`
	NewSize    int64   `json:"new_size"`
	Match      string  `json:"match"`
	Similarity float64 `json:"similarity"`
	Confidence string  `json:"confidence"`
}

type FunctionResult struct {
	Comparison targetidentity.Comparison `json:"comparison"`
	Threshold  int                       `json:"threshold"`
	Matches    []FunctionMatch           `json:"matches"`
	Exact      int                       `json:"exact"`
	High       int                       `json:"high"`
	Medium     int                       `json:"medium"`
	Low        int                       `json:"low"`
}

type rawFunctionMatch struct {
	Addr     uint64  `json:"addr"`
	Name     string  `json:"name"`
	Size     int64   `json:"size"`
	DiffAddr uint64  `json:"diff_addr"`
	DiffName string  `json:"diff_name"`
	DiffSize int64   `json:"diff_size"`
	Match    string  `json:"match"`
	Dist     float64 `json:"dist"`
}

func New(radiff2Path string) (*Analyzer, error) {
	radiff2Path = strings.TrimSpace(radiff2Path)
	if radiff2Path == "" {
		return nil, errors.New("radiff2 path is required")
	}
	absolute, err := filepath.Abs(radiff2Path)
	if err != nil {
		return nil, fmt.Errorf("resolve radiff2 path: %w", err)
	}
	info, err := os.Stat(absolute)
	if err != nil {
		return nil, fmt.Errorf("stat radiff2: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("radiff2 is not a regular file: %s", absolute)
	}
	return &Analyzer{radiff2: filepath.Clean(absolute)}, nil
}

func (a *Analyzer) Quick(ctx context.Context, leftPath, rightPath string, options ...Options) (QuickResult, error) {
	comparison, err := targetidentity.CompareContext(ctx, leftPath, rightPath)
	if err != nil {
		return QuickResult{}, err
	}
	if err := checkExpected(comparison, options); err != nil {
		return QuickResult{}, err
	}
	stdout, stderr, err := a.run(ctx, "-j", comparison.Left.Path, comparison.Right.Path)
	if err != nil {
		return QuickResult{}, fmt.Errorf("radiff2 quick diff: %w%s", err, suffixStderr(stderr))
	}
	if err := ensureCurrentContext(ctx, comparison); err != nil {
		return QuickResult{}, err
	}
	var raw struct {
		Files   []FileInfo       `json:"files"`
		Changes []map[string]any `json:"changes"`
	}
	if err := json.Unmarshal(stdout, &raw); err != nil {
		return QuickResult{}, fmt.Errorf("decode radiff2 quick JSON: %w", err)
	}
	return QuickResult{
		Comparison:  comparison,
		Files:       raw.Files,
		Changes:     raw.Changes,
		ChangeCount: len(raw.Changes),
	}, nil
}

func (a *Analyzer) Functions(ctx context.Context, leftPath, rightPath string, threshold int, options ...Options) (FunctionResult, error) {
	if threshold <= 0 {
		threshold = 70
	}
	if threshold < 1 || threshold > 100 {
		return FunctionResult{}, errors.New("function diff threshold must be between 1 and 100")
	}
	comparison, err := targetidentity.CompareContext(ctx, leftPath, rightPath)
	if err != nil {
		return FunctionResult{}, err
	}
	if err := checkExpected(comparison, options); err != nil {
		return FunctionResult{}, err
	}

	stdout, stderr, err := a.run(
		ctx,
		"-AA",
		"-C",
		"-j",
		"-e", "bin.relocs.apply=true",
		"-t", strconv.Itoa(threshold),
		comparison.Left.Path,
		comparison.Right.Path,
	)
	if err != nil {
		return FunctionResult{}, fmt.Errorf("radiff2 function diff: %w%s", err, suffixStderr(stderr))
	}

	if err := ensureCurrentContext(ctx, comparison); err != nil {
		return FunctionResult{}, err
	}
	var raw []rawFunctionMatch
	if err := json.Unmarshal(stdout, &raw); err != nil {
		return FunctionResult{}, fmt.Errorf("decode radiff2 function JSON: %w", err)
	}

	result := FunctionResult{
		Comparison: comparison,
		Threshold:  threshold,
		Matches:    make([]FunctionMatch, 0, len(raw)),
	}
	leftBase := imageBase(comparison.Left)
	rightBase := imageBase(comparison.Right)
	for _, item := range raw {
		confidence := confidenceFor(item.Dist)
		match := FunctionMatch{
			OldVA:      item.Addr,
			OldRVA:     toRVA(item.Addr, leftBase),
			OldName:    item.Name,
			OldSize:    item.Size,
			NewVA:      item.DiffAddr,
			NewRVA:     toRVA(item.DiffAddr, rightBase),
			NewName:    item.DiffName,
			NewSize:    item.DiffSize,
			Match:      item.Match,
			Similarity: item.Dist,
			Confidence: confidence,
		}
		result.Matches = append(result.Matches, match)
		switch confidence {
		case "exact":
			result.Exact++
		case "high":
			result.High++
		case "medium":
			result.Medium++
		default:
			result.Low++
		}
	}
	return result, nil
}

// Results are refused when either target changed while the external analyzer
// ran. This is a before/after content fence, not a hostile-writer snapshot lock.
func ensureCurrentContext(ctx context.Context, comparison targetidentity.Comparison) error {
	if ctx == nil {
		ctx = context.Background()
	}
	for _, expected := range []targetidentity.Identity{comparison.Left, comparison.Right} {
		current, err := targetidentity.InspectContext(ctx, expected.Path)
		if err != nil {
			return fmt.Errorf("recheck diff target: %w", err)
		}
		if current.SHA256 != expected.SHA256 || current.Size != expected.Size {
			return fmt.Errorf("diff target changed during analysis: %s", expected.Path)
		}
	}
	return nil
}

func (a *Analyzer) run(ctx context.Context, args ...string) ([]byte, []byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	bounded, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	result := toolprocess.Run(bounded, a.radiff2, args, 8<<20, 64<<10, "")
	if bounded.Err() != nil {
		return nil, result.Stderr, bounded.Err()
	}
	if result.Truncated {
		return nil, result.Stderr, errors.Join(ErrOutputLimit, result.Err)
	}
	return result.Stdout, result.Stderr, result.Err
}

func checkExpected(comparison targetidentity.Comparison, options []Options) error {
	if len(options) > 1 {
		return errors.New("only one binary diff options value is allowed")
	}
	if len(options) == 0 {
		return nil
	}
	for _, pair := range [][2]string{
		{options[0].ExpectedLeftSHA256, comparison.Left.SHA256},
		{options[0].ExpectedRightSHA256, comparison.Right.SHA256},
	} {
		if pair[0] == "" {
			continue
		}
		digest, err := hex.DecodeString(pair[0])
		if err != nil || len(digest) != 32 {
			return errors.New("expected target revision must be a SHA-256 digest")
		}
		if !strings.EqualFold(pair[0], pair[1]) {
			return errors.New("binary diff target revision changed; select the current target before analysis")
		}
	}
	return nil
}

func imageBase(identity targetidentity.Identity) uint64 {
	if identity.PE == nil {
		return 0
	}
	return identity.PE.ImageBase
}

func toRVA(address, base uint64) uint64 {
	if base != 0 && address >= base {
		return address - base
	}
	return address
}

func confidenceFor(similarity float64) string {
	switch {
	case similarity >= 0.999:
		return "exact"
	case similarity >= 0.90:
		return "high"
	case similarity >= 0.75:
		return "medium"
	default:
		return "low"
	}
}

func suffixStderr(stderr []byte) string {
	value := strings.TrimSpace(string(stderr))
	if value == "" {
		return ""
	}
	if len(value) > 2048 {
		value = strings.ToValidUTF8(value[:2048], "") + " [diagnostic truncated]"
	}
	return ": " + value
}
