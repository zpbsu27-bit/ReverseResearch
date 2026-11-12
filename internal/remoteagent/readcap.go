package remoteagent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"

	"reverseresearch/internal/targetidentity"
)

const (
	MaxExcerptBytes            = 64 << 10
	MaxSnapshotEntries         = 4096
	MaxProcessEntries          = 2048
	MaxToolNames               = 64
	DefaultMaxExcerptFileBytes = int64(64 << 20)
	MaxExcerptFileBytes        = int64(1 << 30)
)

type ProcessInfo struct {
	PID       uint32 `json:"pid"`
	ParentPID uint32 `json:"parent_pid,omitempty"`
	Name      string `json:"name"`
}

type directoryEntry struct {
	Path        string `json:"path"`
	Kind        string `json:"kind"`
	Size        int64  `json:"size,omitempty"`
	ModifiedUTC string `json:"modified_utc,omitempty"`
}

type excerptResult struct {
	Path        string `json:"path"`
	SHA256      string `json:"sha256"`
	Size        int64  `json:"size"`
	ModifiedUTC string `json:"modified_utc"`
	Offset      int64  `json:"offset"`
	Bytes       int    `json:"bytes"`
	EOF         bool   `json:"eof"`
	DataBase64  string `json:"data_base64"`
}

func BuiltinReadOnlyCapabilities() map[string]CapabilityHandler {
	return map[string]CapabilityHandler{
		"artifact.inspect":        artifactInspectReadOnly,
		"artifact.hash":           artifactHashReadOnly,
		"artifact.metadata":       artifactMetadataReadOnly,
		"directory.snapshot":      directorySnapshotReadOnly,
		"tool.inventory":          toolInventoryReadOnly,
		"process.inventory":       processInventoryReadOnly,
		"environment.fingerprint": environmentFingerprintReadOnly,
		"file.read_excerpt":       fileReadExcerptReadOnly,
		"case.evidence.capture":   caseEvidenceCaptureReadOnly,
	}
}

func artifactInspectReadOnly(ctx context.Context, job JobRequest) (CapabilityResult, error) {
	if err := validateCapabilityParameters(job.Parameters); err != nil {
		return CapabilityResult{}, err
	}
	identity, err := targetidentity.InspectContext(ctx, job.Target)
	if err != nil {
		return CapabilityResult{}, err
	}
	return jsonCapability(identity)
}

func artifactHashReadOnly(ctx context.Context, job JobRequest) (CapabilityResult, error) {
	if err := validateCapabilityParameters(job.Parameters); err != nil {
		return CapabilityResult{}, err
	}
	identity, err := targetidentity.InspectContext(ctx, job.Target)
	if err != nil {
		return CapabilityResult{}, err
	}
	return jsonCapability(map[string]any{"sha256": identity.SHA256, "size": identity.Size})
}

func artifactMetadataReadOnly(_ context.Context, job JobRequest) (CapabilityResult, error) {
	if err := validateCapabilityParameters(job.Parameters); err != nil {
		return CapabilityResult{}, err
	}
	path, info, err := statTarget(job.Target)
	if err != nil {
		return CapabilityResult{}, err
	}
	kind := "other"
	if info.Mode().IsRegular() {
		kind = "file"
	} else if info.IsDir() {
		kind = "directory"
	}
	return jsonCapability(map[string]any{
		"path": path, "name": info.Name(), "kind": kind, "size": info.Size(),
		"mode": info.Mode().String(), "modified_utc": info.ModTime().UTC().Format(time.RFC3339Nano),
	})
}

var errSnapshotLimit = errors.New("directory snapshot entry limit reached")

func directorySnapshotReadOnly(ctx context.Context, job JobRequest) (CapabilityResult, error) {
	if err := validateCapabilityParameters(job.Parameters, "max_entries", "max_depth"); err != nil {
		return CapabilityResult{}, err
	}
	maxEntries, err := boundedInt(job.Parameters, "max_entries", 256, 1, MaxSnapshotEntries)
	if err != nil {
		return CapabilityResult{}, err
	}
	maxDepth, err := boundedInt(job.Parameters, "max_depth", 1, 0, 8)
	if err != nil {
		return CapabilityResult{}, err
	}
	root, info, err := statTarget(job.Target)
	if err != nil {
		return CapabilityResult{}, err
	}
	if !info.IsDir() {
		return CapabilityResult{}, errors.New("directory.snapshot target must be a directory")
	}
	entries := make([]directoryEntry, 0, min(maxEntries, 256))
	truncated := false
	walkErr := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if path == root {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		depth := 1 + strings.Count(filepath.ToSlash(rel), "/")
		if depth > maxDepth {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if len(entries) >= maxEntries {
			truncated = true
			return errSnapshotLimit
		}
		entryInfo, err := d.Info()
		if err != nil {
			return err
		}
		kind := "other"
		if d.IsDir() {
			kind = "directory"
		} else if entryInfo.Mode().IsRegular() {
			kind = "file"
		} else if entryInfo.Mode()&os.ModeSymlink != 0 {
			kind = "symlink"
		}
		entries = append(entries, directoryEntry{
			Path: filepath.ToSlash(rel), Kind: kind, Size: entryInfo.Size(),
			ModifiedUTC: entryInfo.ModTime().UTC().Format(time.RFC3339Nano),
		})
		return nil
	})
	if walkErr != nil && !errors.Is(walkErr, errSnapshotLimit) {
		return CapabilityResult{}, walkErr
	}
	return jsonCapability(map[string]any{
		"root": root, "max_depth": maxDepth, "max_entries": maxEntries,
		"truncated": truncated, "entries": entries,
	})
}

func toolInventoryReadOnly(ctx context.Context, job JobRequest) (CapabilityResult, error) {
	if err := validateCapabilityParameters(job.Parameters, "names"); err != nil {
		return CapabilityResult{}, err
	}
	names := []string{"adb", "frida", "gdb", "git", "go", "ghidraRun", "lldb", "objdump", "python", "python3", "radare2", "r2", "rizin", "rz-bin"}
	if raw := strings.TrimSpace(job.Parameters["names"]); raw != "" {
		names = nil
		seen := map[string]bool{}
		for _, part := range strings.Split(raw, ",") {
			name := strings.TrimSpace(part)
			if name == "" || seen[name] {
				continue
			}
			if len(names) >= MaxToolNames {
				return CapabilityResult{}, fmt.Errorf("names exceeds maximum of %d", MaxToolNames)
			}
			if strings.ContainsAny(name, "/\\") || strings.Contains(name, "..") {
				return CapabilityResult{}, fmt.Errorf("tool name %q must be a basename", name)
			}
			seen[name] = true
			names = append(names, name)
		}
		if len(names) == 0 {
			return CapabilityResult{}, errors.New("names did not contain any tool names")
		}
	}
	sort.Strings(names)
	type tool struct {
		Name      string `json:"name"`
		Available bool   `json:"available"`
		Path      string `json:"path,omitempty"`
	}
	out := make([]tool, 0, len(names))
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return CapabilityResult{}, err
		}
		path, err := exec.LookPath(name)
		if err != nil {
			out = append(out, tool{Name: name})
			continue
		}
		if abs, absErr := filepath.Abs(path); absErr == nil {
			path = abs
		}
		out = append(out, tool{Name: name, Available: true, Path: filepath.Clean(path)})
	}
	return jsonCapability(map[string]any{"target": job.Target, "tools": out})
}

func processInventoryReadOnly(ctx context.Context, job JobRequest) (CapabilityResult, error) {
	if err := validateCapabilityParameters(job.Parameters, "max_entries"); err != nil {
		return CapabilityResult{}, err
	}
	maxEntries, err := boundedInt(job.Parameters, "max_entries", 256, 1, MaxProcessEntries)
	if err != nil {
		return CapabilityResult{}, err
	}
	processes, truncated, err := platformProcessInventory(ctx, maxEntries)
	if err != nil {
		return CapabilityResult{}, err
	}
	sort.Slice(processes, func(i, j int) bool {
		if processes[i].PID != processes[j].PID {
			return processes[i].PID < processes[j].PID
		}
		return processes[i].Name < processes[j].Name
	})
	return jsonCapability(map[string]any{
		"target": job.Target, "max_entries": maxEntries, "truncated": truncated, "processes": processes,
	})
}

func environmentFingerprintReadOnly(ctx context.Context, job JobRequest) (CapabilityResult, error) {
	if err := validateCapabilityParameters(job.Parameters); err != nil {
		return CapabilityResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return CapabilityResult{}, err
	}
	host, err := os.Hostname()
	if err != nil {
		return CapabilityResult{}, err
	}
	version := ""
	if info, ok := debug.ReadBuildInfo(); ok {
		version = info.Main.Version
	}
	facts := map[string]any{
		"target": job.Target, "hostname": host, "goos": runtime.GOOS, "goarch": runtime.GOARCH,
		"cpu_count": runtime.NumCPU(), "go_version": runtime.Version(), "agent_build_version": version,
	}
	body, err := json.Marshal(facts)
	if err != nil {
		return CapabilityResult{}, err
	}
	sum := sha256.Sum256(body)
	facts["fingerprint_sha256"] = hex.EncodeToString(sum[:])
	return jsonCapability(facts)
}

func fileReadExcerptReadOnly(ctx context.Context, job JobRequest) (CapabilityResult, error) {
	if err := validateCapabilityParameters(job.Parameters, "offset", "max_bytes", "max_file_bytes"); err != nil {
		return CapabilityResult{}, err
	}
	offset, err := boundedInt64(job.Parameters, "offset", 0, 0, 1<<62)
	if err != nil {
		return CapabilityResult{}, err
	}
	maxBytes, err := boundedInt(job.Parameters, "max_bytes", 4096, 1, MaxExcerptBytes)
	if err != nil {
		return CapabilityResult{}, err
	}
	maxFileBytes, err := boundedInt64(job.Parameters, "max_file_bytes", DefaultMaxExcerptFileBytes, 1, MaxExcerptFileBytes)
	if err != nil {
		return CapabilityResult{}, err
	}
	result, _, err := readStableExcerptWithIdentity(ctx, job.Target, offset, maxBytes, maxFileBytes)
	if err != nil {
		return CapabilityResult{}, err
	}
	return jsonCapability(result)
}

func caseEvidenceCaptureReadOnly(ctx context.Context, job JobRequest) (CapabilityResult, error) {
	if err := validateCapabilityParameters(job.Parameters, "max_bytes", "max_file_bytes"); err != nil {
		return CapabilityResult{}, err
	}
	maxBytes, err := boundedInt(job.Parameters, "max_bytes", 4096, 1, 16<<10)
	if err != nil {
		return CapabilityResult{}, err
	}
	maxFileBytes, err := boundedInt64(job.Parameters, "max_file_bytes", DefaultMaxExcerptFileBytes, 1, MaxExcerptFileBytes)
	if err != nil {
		return CapabilityResult{}, err
	}
	excerpt, identity, err := readStableExcerptWithIdentity(ctx, job.Target, 0, maxBytes, maxFileBytes)
	if err != nil {
		return CapabilityResult{}, err
	}
	capture := map[string]any{
		"schema": "reverseresearch.remote-evidence-capture.v1",
		"target": job.Target, "captured_utc": time.Now().UTC().Format(time.RFC3339Nano),
		"identity": identity, "excerpt": excerpt,
	}
	body, err := json.Marshal(capture)
	if err != nil {
		return CapabilityResult{}, err
	}
	sum := sha256.Sum256(body)
	capture["capture_sha256"] = hex.EncodeToString(sum[:])
	return jsonCapability(capture)
}

func readStableExcerptWithIdentity(ctx context.Context, target string, offset int64, maxBytes int, maxFileBytes int64) (excerptResult, targetidentity.Identity, error) {
	if err := ctx.Err(); err != nil {
		return excerptResult{}, targetidentity.Identity{}, err
	}
	path, before, err := statTarget(target)
	if err != nil {
		return excerptResult{}, targetidentity.Identity{}, err
	}
	if !before.Mode().IsRegular() {
		return excerptResult{}, targetidentity.Identity{}, errors.New("file.read_excerpt target must be a regular file")
	}
	if before.Size() > maxFileBytes {
		return excerptResult{}, targetidentity.Identity{}, fmt.Errorf("target exceeds max_file_bytes: size=%d max=%d", before.Size(), maxFileBytes)
	}
	if offset > before.Size() {
		return excerptResult{}, targetidentity.Identity{}, fmt.Errorf("offset %d exceeds file size %d", offset, before.Size())
	}
	f, err := os.Open(path)
	if err != nil {
		return excerptResult{}, targetidentity.Identity{}, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return excerptResult{}, targetidentity.Identity{}, err
	}
	if !os.SameFile(before, opened) {
		return excerptResult{}, targetidentity.Identity{}, errors.New("target changed before bounded read")
	}

	buf := make([]byte, maxBytes)
	n, readErr := f.ReadAt(buf, offset)
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return excerptResult{}, targetidentity.Identity{}, readErr
	}
	buf = buf[:n]

	identity, err := targetidentity.InspectBoundedContext(ctx, path, maxFileBytes)
	if err != nil {
		return excerptResult{}, targetidentity.Identity{}, err
	}

	verify := make([]byte, n)
	if n > 0 {
		readN, verifyErr := f.ReadAt(verify, offset)
		if verifyErr != nil && !errors.Is(verifyErr, io.EOF) {
			return excerptResult{}, targetidentity.Identity{}, verifyErr
		}
		verify = verify[:readN]
	}
	afterOpen, err := f.Stat()
	if err != nil {
		return excerptResult{}, targetidentity.Identity{}, err
	}
	current, err := os.Stat(path)
	if err != nil {
		return excerptResult{}, targetidentity.Identity{}, err
	}
	if !os.SameFile(before, afterOpen) || !os.SameFile(afterOpen, current) ||
		before.Size() != afterOpen.Size() || afterOpen.Size() != current.Size() ||
		!before.ModTime().Equal(afterOpen.ModTime()) || !afterOpen.ModTime().Equal(current.ModTime()) ||
		identity.Size != before.Size() || identity.ModifiedUTC != before.ModTime().UTC().Format(time.RFC3339Nano) ||
		!bytes.Equal(buf, verify) {
		return excerptResult{}, targetidentity.Identity{}, errors.New("target changed during bounded read")
	}
	return excerptResult{
		Path: identity.Path, SHA256: identity.SHA256, Size: identity.Size, ModifiedUTC: identity.ModifiedUTC,
		Offset: offset, Bytes: n, EOF: offset+int64(n) >= identity.Size,
		DataBase64: base64.StdEncoding.EncodeToString(buf),
	}, identity, nil
}

func statTarget(target string) (string, os.FileInfo, error) {
	if strings.TrimSpace(target) == "" {
		return "", nil, errors.New("target is required")
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		return "", nil, err
	}
	abs = filepath.Clean(abs)
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", nil, err
	}
	return abs, info, nil
}

func validateCapabilityParameters(params map[string]string, allowed ...string) error {
	allow := map[string]bool{}
	for _, key := range allowed {
		allow[key] = true
	}
	for key := range params {
		key = strings.TrimSpace(key)
		if !allow[key] {
			return fmt.Errorf("parameter %q is not supported by this capability", key)
		}
	}
	return nil
}

func boundedInt(params map[string]string, key string, def, minValue, maxValue int) (int, error) {
	raw := strings.TrimSpace(params[key])
	if raw == "" {
		return def, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < minValue || value > maxValue {
		return 0, fmt.Errorf("%s must be an integer between %d and %d", key, minValue, maxValue)
	}
	return value, nil
}

func boundedInt64(params map[string]string, key string, def, minValue, maxValue int64) (int64, error) {
	raw := strings.TrimSpace(params[key])
	if raw == "" {
		return def, nil
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value < minValue || value > maxValue {
		return 0, fmt.Errorf("%s must be an integer between %d and %d", key, minValue, maxValue)
	}
	return value, nil
}

func jsonCapability(value any) (CapabilityResult, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return CapabilityResult{}, err
	}
	return CapabilityResult{State: "applied", Body: body}, nil
}
