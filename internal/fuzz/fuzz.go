package fuzz

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"reverseresearch/internal/targetidentity"
)

type Engine string

const (
	EngineLibFuzzer Engine = "libfuzzer"
	EngineAFLPP     Engine = "afl++"
	EngineWinAFL    Engine = "winafl"
	EngineJazzer    Engine = "jazzer"
)

type PlanRequest struct {
	TargetPath string   `json:"target_path"`
	Harness    string   `json:"harness"`
	CorpusDir  string   `json:"corpus_dir"`
	Engine     Engine   `json:"engine"`
	Sanitizers []string `json:"sanitizers,omitempty"`
	Seed       int64    `json:"seed,omitempty"`
}

type CorpusIdentity struct {
	Path       string `json:"path"`
	SHA256     string `json:"sha256"`
	FileCount  int    `json:"file_count"`
	TotalBytes int64  `json:"total_bytes"`
}

type Plan struct {
	Target      targetidentity.Identity `json:"target"`
	Harness     targetidentity.Identity `json:"harness"`
	Corpus      CorpusIdentity          `json:"corpus"`
	Engine      Engine                  `json:"engine"`
	Sanitizers  []string                `json:"sanitizers,omitempty"`
	Seed        int64                   `json:"seed"`
	EffectClass string                  `json:"effect_class"`
	Execution   string                  `json:"execution"`
	CreatedUTC  string                  `json:"created_utc"`
}

type Frame struct {
	Module   string `json:"module,omitempty"`
	Function string `json:"function,omitempty"`
	Offset   uint64 `json:"offset,omitempty"`
}

type Crash struct {
	Exception        string  `json:"exception"`
	Module           string  `json:"module"`
	FaultInstruction string  `json:"fault_instruction"`
	Frames           []Frame `json:"frames,omitempty"`
	InputSHA256      string  `json:"input_sha256,omitempty"`
	Engine           Engine  `json:"engine,omitempty"`
	Sanitizer        string  `json:"sanitizer,omitempty"`
	ObservedUTC      string  `json:"observed_utc,omitempty"`
}

type Fingerprint struct {
	ID               string   `json:"id"`
	Exception        string   `json:"exception"`
	Module           string   `json:"module"`
	FaultInstruction string   `json:"fault_instruction"`
	StackFingerprint string   `json:"stack_fingerprint"`
	NormalizedFrames []string `json:"normalized_frames"`
}

type Group struct {
	Fingerprint Fingerprint `json:"fingerprint"`
	Count       int         `json:"count"`
	InputSHA256 []string    `json:"input_sha256,omitempty"`
	Crashes     []Crash     `json:"crashes"`
}

func BuildPlan(request PlanRequest) (Plan, error) {
	return BuildPlanContext(context.Background(), request)
}

func BuildPlanContext(ctx context.Context, request PlanRequest) (Plan, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	request.TargetPath = strings.TrimSpace(request.TargetPath)
	request.Harness = strings.TrimSpace(request.Harness)
	request.CorpusDir = strings.TrimSpace(request.CorpusDir)
	if request.TargetPath == "" || request.Harness == "" || request.CorpusDir == "" {
		return Plan{}, errors.New("target_path, harness, and corpus_dir are required")
	}
	switch request.Engine {
	case EngineLibFuzzer, EngineAFLPP, EngineWinAFL, EngineJazzer:
	default:
		return Plan{}, fmt.Errorf("unsupported fuzz engine %q", request.Engine)
	}
	target, err := targetidentity.InspectContext(ctx, request.TargetPath)
	if err != nil {
		return Plan{}, err
	}
	harness, err := targetidentity.InspectContext(ctx, request.Harness)
	if err != nil {
		return Plan{}, fmt.Errorf("inspect harness: %w", err)
	}
	corpus, err := inspectCorpusContext(ctx, request.CorpusDir)
	if err != nil {
		return Plan{}, err
	}
	sanitizers := normalizeStrings(request.Sanitizers)
	if request.Seed == 0 {
		request.Seed = 1
	}
	return Plan{
		Target: target, Harness: harness, Corpus: corpus, Engine: request.Engine,
		Sanitizers: sanitizers, Seed: request.Seed, EffectClass: "runtime mutation",
		Execution: "planned-only", CreatedUTC: time.Now().UTC().Format(time.RFC3339Nano),
	}, nil
}

func FingerprintCrash(crash Crash) (Fingerprint, error) {
	exception := normalizeToken(crash.Exception)
	module := normalizeModule(crash.Module)
	instruction := normalizeToken(crash.FaultInstruction)
	if exception == "" || module == "" || instruction == "" {
		return Fingerprint{}, errors.New("crash exception, module, and fault_instruction are required")
	}
	frames := make([]string, 0, len(crash.Frames))
	for _, frame := range crash.Frames {
		normalized := normalizeFrame(frame)
		if normalized != "" {
			frames = append(frames, normalized)
		}
		if len(frames) == 12 {
			break
		}
	}
	stackHash := sha256.Sum256([]byte(strings.Join(frames, "\n")))
	stackFingerprint := hex.EncodeToString(stackHash[:])
	key := strings.Join([]string{module, exception, instruction, stackFingerprint}, "\x00")
	digest := sha256.Sum256([]byte(key))
	return Fingerprint{
		ID: "crash:" + hex.EncodeToString(digest[:]), Exception: exception, Module: module,
		FaultInstruction: instruction, StackFingerprint: stackFingerprint, NormalizedFrames: frames,
	}, nil
}

func Dedupe(crashes []Crash) ([]Group, error) {
	byID := map[string]*Group{}
	order := make([]string, 0)
	for _, crash := range crashes {
		fp, err := FingerprintCrash(crash)
		if err != nil {
			return nil, err
		}
		group, ok := byID[fp.ID]
		if !ok {
			group = &Group{Fingerprint: fp}
			byID[fp.ID] = group
			order = append(order, fp.ID)
		}
		group.Count++
		group.Crashes = append(group.Crashes, crash)
		if value := strings.ToLower(strings.TrimSpace(crash.InputSHA256)); value != "" {
			group.InputSHA256 = append(group.InputSHA256, value)
		}
	}
	sort.Strings(order)
	result := make([]Group, 0, len(order))
	for _, id := range order {
		group := byID[id]
		group.InputSHA256 = normalizeStrings(group.InputSHA256)
		result = append(result, *group)
	}
	return result, nil
}

func InputIdentity(path string) (string, int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", 0, err
	}
	if !info.Mode().IsRegular() {
		return "", 0, errors.New("crash input is not a regular file")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return "", 0, err
	}
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:]), int64(len(body)), nil
}

func normalizeFrame(frame Frame) string {
	module := normalizeModule(frame.Module)
	function := normalizeToken(frame.Function)
	if module == "" && function == "" {
		return ""
	}
	return module + "!" + function + "+0x" + strconv.FormatUint(frame.Offset, 16)
}

func normalizeModule(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	return strings.ToLower(filepath.Base(strings.ReplaceAll(value, "\\", "/")))
}

func normalizeToken(value string) string {
	return strings.ToLower(strings.Join(strings.Fields(strings.TrimSpace(value)), " "))
}

func normalizeStrings(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}

const (
	maxCorpusFiles = 10000
	maxCorpusBytes = int64(256 << 20)
)

func inspectCorpusContext(ctx context.Context, path string) (CorpusIdentity, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	absolute, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil {
		return CorpusIdentity{}, err
	}
	info, err := os.Stat(absolute)
	if err != nil || !info.IsDir() {
		return CorpusIdentity{}, fmt.Errorf("corpus_dir must be an existing directory: %s", absolute)
	}
	type item struct {
		rel  string
		hash string
		size int64
	}
	items := make([]item, 0)
	var total int64
	err = filepath.WalkDir(absolute, func(current string, entry os.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		if len(items) >= maxCorpusFiles {
			return errors.New("corpus exceeds 10000 regular files")
		}
		if info.Size() < 0 || total > maxCorpusBytes-info.Size() {
			return errors.New("corpus exceeds 256 MiB")
		}
		digest, size, err := hashCorpusFileContext(ctx, current, maxCorpusBytes-total)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(absolute, current)
		if err != nil {
			return err
		}
		items = append(items, item{rel: filepath.ToSlash(rel), hash: digest, size: size})
		total += size
		return nil
	})
	if err != nil {
		return CorpusIdentity{}, err
	}
	sort.Slice(items, func(i, j int) bool { return items[i].rel < items[j].rel })
	aggregate := sha256.New()
	for _, item := range items {
		aggregate.Write([]byte(item.rel))
		aggregate.Write([]byte{0})
		aggregate.Write([]byte(item.hash))
		aggregate.Write([]byte{0})
	}
	return CorpusIdentity{
		Path: absolute, SHA256: hex.EncodeToString(aggregate.Sum(nil)),
		FileCount: len(items), TotalBytes: total,
	}, nil
}

func hashCorpusFileContext(ctx context.Context, path string, remaining int64) (digest string, size int64, err error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	before, err := file.Stat()
	if err != nil {
		return "", 0, errors.Join(err, file.Close())
	}
	if !before.Mode().IsRegular() {
		return "", 0, errors.Join(errors.New("corpus entry is not a regular file"), file.Close())
	}
	if before.Size() < 0 || before.Size() > remaining {
		return "", 0, errors.Join(errors.New("corpus exceeds 256 MiB"), file.Close())
	}

	hash := sha256.New()
	limited := &io.LimitedReader{R: corpusContextReader{ctx: ctx, reader: file}, N: remaining + 1}
	n, copyErr := io.Copy(hash, limited)
	after, statErr := file.Stat()
	closeErr := file.Close()
	if copyErr != nil || statErr != nil || closeErr != nil {
		return "", 0, errors.Join(copyErr, statErr, closeErr)
	}
	if n > remaining {
		return "", 0, errors.New("corpus exceeds 256 MiB")
	}
	current, err := os.Stat(path)
	if err != nil {
		return "", 0, fmt.Errorf("corpus entry changed during identity inspection: %w", err)
	}
	if !os.SameFile(before, after) || !os.SameFile(after, current) ||
		before.Size() != n || after.Size() != n || current.Size() != n ||
		!before.ModTime().Equal(after.ModTime()) || !after.ModTime().Equal(current.ModTime()) {
		return "", 0, errors.New("corpus entry changed during identity inspection")
	}
	return hex.EncodeToString(hash.Sum(nil)), n, nil
}

type corpusContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r corpusContextReader) Read(p []byte) (int, error) {
	select {
	case <-r.ctx.Done():
		return 0, r.ctx.Err()
	default:
		return r.reader.Read(p)
	}
}
