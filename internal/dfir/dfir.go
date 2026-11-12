package dfir

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"reverseresearch/internal/targetidentity"
)

const (
	DefaultMaxTimelineBytes int64 = 128 << 20
	DefaultMaxEntries             = 200000
)

type ArtifactKind string

const (
	KindMemoryDump ArtifactKind = "memory-dump"
	KindCrashDump  ArtifactKind = "crash-dump"
	KindEVTX       ArtifactKind = "evtx"
	KindRegistry   ArtifactKind = "registry"
	KindMFT        ArtifactKind = "mft"
	KindUSN        ArtifactKind = "usn-journal"
	KindPrefetch   ArtifactKind = "prefetch"
	KindAmcache    ArtifactKind = "amcache"
	KindSRUM       ArtifactKind = "srum"
	KindPCAP       ArtifactKind = "pcap"
	KindDiskImage  ArtifactKind = "disk-image"
	KindTimeline   ArtifactKind = "timeline-json"
	KindUnknown    ArtifactKind = "unknown"
)

type Artifact struct {
	Identity         targetidentity.Identity `json:"identity"`
	Kind             ArtifactKind            `json:"kind"`
	ParserStatus     string                  `json:"parser_status"`
	RecommendedTools []string                `json:"recommended_tools,omitempty"`
	ReadOnly         bool                    `json:"read_only"`
}

type TimelineEntry struct {
	ID             string            `json:"id"`
	TimeUTC        string            `json:"time_utc"`
	Source         string            `json:"source"`
	Event          string            `json:"event"`
	Host           string            `json:"host,omitempty"`
	User           string            `json:"user,omitempty"`
	Process        string            `json:"process,omitempty"`
	PID            int64             `json:"pid,omitempty"`
	ParentPID      int64             `json:"parent_pid,omitempty"`
	ArtifactSHA256 string            `json:"artifact_sha256"`
	SourceLine     int               `json:"source_line"`
	Fields         map[string]string `json:"fields,omitempty"`
}

type Timeline struct {
	Source          Artifact        `json:"source"`
	Format          string          `json:"format"`
	Entries         []TimelineEntry `json:"entries"`
	Duplicates      int             `json:"duplicates"`
	Rejected        int             `json:"rejected"`
	CompletedUTC    string          `json:"completed_utc"`
	SourceUnchanged bool            `json:"source_unchanged"`
}

type ImportOptions struct {
	Format     string `json:"format,omitempty"`
	MaxBytes   int64  `json:"max_bytes,omitempty"`
	MaxEntries int    `json:"max_entries,omitempty"`
}

func Inspect(path string) (Artifact, error) {
	return InspectContext(context.Background(), path)
}

func InspectContext(ctx context.Context, path string) (Artifact, error) {
	return inspectContext(ctx, path, 0)
}

func inspectContext(ctx context.Context, path string, maxBytes int64) (Artifact, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var (
		identity targetidentity.Identity
		err      error
	)
	if maxBytes > 0 {
		identity, err = targetidentity.InspectBoundedContext(ctx, path, maxBytes)
	} else {
		identity, err = targetidentity.InspectContext(ctx, path)
	}
	if err != nil {
		return Artifact{}, err
	}
	kind := classify(path, identity)
	artifact := Artifact{Identity: identity, Kind: kind, ReadOnly: true}
	switch kind {
	case KindEVTX:
		artifact.ParserStatus = "adapter-required"
		artifact.RecommendedTools = []string{"hayabusa", "chainsaw"}
	case KindMemoryDump, KindCrashDump:
		artifact.ParserStatus = "adapter-required"
		artifact.RecommendedTools = []string{"volatility3", "memprocfs", "windbg"}
	case KindPCAP:
		artifact.ParserStatus = "adapter-required"
		artifact.RecommendedTools = []string{"tshark", "zeek"}
	case KindRegistry, KindMFT, KindUSN, KindPrefetch, KindAmcache, KindSRUM:
		artifact.ParserStatus = "adapter-required"
		artifact.RecommendedTools = []string{"kape", "zimmerman-tools"}
	case KindTimeline:
		artifact.ParserStatus = "native-jsonl"
	default:
		artifact.ParserStatus = "identify-only"
	}
	return artifact, nil
}

func ImportTimelineJSONL(path string, options ImportOptions) (Timeline, error) {
	return ImportTimelineJSONLContext(context.Background(), path, options)
}

func ImportTimelineJSONLContext(ctx context.Context, path string, options ImportOptions) (Timeline, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	options = normalizeImportOptions(options)
	before, err := inspectContext(ctx, path, options.MaxBytes)
	if err != nil {
		if errors.Is(err, targetidentity.ErrTargetTooLarge) {
			return Timeline{}, fmt.Errorf("timeline source exceeds max_bytes: %w", err)
		}
		return Timeline{}, err
	}
	format := strings.ToLower(strings.TrimSpace(options.Format))
	if format == "" {
		format = "generic-jsonl"
	}
	file, err := os.Open(before.Identity.Path)
	if err != nil {
		return Timeline{}, err
	}
	defer file.Close()

	result := Timeline{Source: before, Format: format, Entries: []TimelineEntry{}}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	seen := map[string]bool{}
	line := 0
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return Timeline{}, err
		}
		line++
		if len(result.Entries) >= options.MaxEntries {
			return Timeline{}, fmt.Errorf("timeline entry limit exceeded: %d", options.MaxEntries)
		}
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" {
			continue
		}
		var object map[string]any
		if err := json.Unmarshal([]byte(raw), &object); err != nil {
			result.Rejected++
			continue
		}
		entry, err := normalizeEntry(object, format, before.Identity.SHA256, line)
		if err != nil {
			result.Rejected++
			continue
		}
		if seen[entry.ID] {
			result.Duplicates++
			continue
		}
		seen[entry.ID] = true
		result.Entries = append(result.Entries, entry)
	}
	if err := scanner.Err(); err != nil {
		return Timeline{}, err
	}
	after, err := targetidentity.InspectBoundedContext(ctx, before.Identity.Path, options.MaxBytes)
	if err != nil {
		return Timeline{}, err
	}
	if after.ID != before.Identity.ID || after.Size != before.Identity.Size || after.ModifiedUTC != before.Identity.ModifiedUTC {
		return Timeline{}, errors.New("timeline source changed during import")
	}
	sort.SliceStable(result.Entries, func(i, j int) bool {
		if result.Entries[i].TimeUTC == result.Entries[j].TimeUTC {
			return result.Entries[i].ID < result.Entries[j].ID
		}
		return result.Entries[i].TimeUTC < result.Entries[j].TimeUTC
	})
	result.SourceUnchanged = true
	result.CompletedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	return result, nil
}

func normalizeImportOptions(options ImportOptions) ImportOptions {
	if options.MaxBytes <= 0 {
		options.MaxBytes = DefaultMaxTimelineBytes
	}
	if options.MaxBytes > 512<<20 {
		options.MaxBytes = 512 << 20
	}
	if options.MaxEntries <= 0 {
		options.MaxEntries = DefaultMaxEntries
	}
	if options.MaxEntries > 1000000 {
		options.MaxEntries = 1000000
	}
	return options
}

func classify(path string, identity targetidentity.Identity) ArtifactKind {
	name := strings.ToLower(filepath.Base(path))
	ext := strings.ToLower(filepath.Ext(name))
	switch {
	case ext == ".evtx":
		return KindEVTX
	case ext == ".pcap" || ext == ".pcapng" || ext == ".cap":
		return KindPCAP
	case ext == ".dmp" || ext == ".mdmp":
		return KindCrashDump
	case ext == ".raw" || ext == ".mem" || strings.Contains(name, "memory"):
		return KindMemoryDump
	case ext == ".e01" || ext == ".dd" || ext == ".img":
		return KindDiskImage
	case ext == ".jsonl" || ext == ".ndjson":
		return KindTimeline
	case name == "$mft" || ext == ".mft":
		return KindMFT
	case strings.Contains(name, "$usnjrnl") || strings.Contains(name, "usn"):
		return KindUSN
	case ext == ".pf":
		return KindPrefetch
	case strings.Contains(name, "amcache"):
		return KindAmcache
	case strings.Contains(name, "srum"):
		return KindSRUM
	case ext == ".dat" || ext == ".hve" || name == "system" || name == "software" || name == "sam" || name == "security" || name == "ntuser.dat":
		return KindRegistry
	default:
		_ = identity
		return KindUnknown
	}
}

func normalizeEntry(object map[string]any, format, artifactSHA string, line int) (TimelineEntry, error) {
	timeValue := firstString(object, "@timestamp", "timestamp", "Timestamp", "datetime", "DateTime", "TimeCreated", "time")
	parsed, err := parseTime(timeValue)
	if err != nil {
		return TimelineEntry{}, err
	}
	event := firstString(object, "event", "Event", "message", "Message", "title", "Title", "EventID")
	if event == "" {
		event = format
	}
	fields := flattenStrings(object)
	entry := TimelineEntry{
		TimeUTC: parsed.UTC().Format(time.RFC3339Nano), Source: format, Event: event,
		Host:           firstString(object, "host", "Host", "computer", "Computer", "ComputerName"),
		User:           firstString(object, "user", "User", "username", "UserName", "SubjectUserName"),
		Process:        firstString(object, "process", "Process", "Image", "ProcessName"),
		PID:            firstInt64(object, "pid", "PID", "ProcessId", "ProcessID"),
		ParentPID:      firstInt64(object, "ppid", "PPID", "ParentProcessId", "ParentProcessID"),
		ArtifactSHA256: artifactSHA, SourceLine: line, Fields: fields,
	}
	entry.ID = timelineID(entry)
	return entry, nil
}

func parseTime(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, errors.New("timeline entry has no timestamp")
	}
	layouts := []string{
		time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05.999999999Z07:00",
		"2006-01-02 15:04:05.999999999", "2006-01-02 15:04:05",
	}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed, nil
		}
	}
	return time.Time{}, fmt.Errorf("unsupported timestamp %q", value)
}

func timelineID(entry TimelineEntry) string {
	h := sha256.New()
	for _, value := range []string{
		entry.TimeUTC, entry.Source, entry.Event, entry.Host, entry.User, entry.Process,
		strconv.FormatInt(entry.PID, 10), strconv.FormatInt(entry.ParentPID, 10), entry.ArtifactSHA256,
	} {
		h.Write([]byte(value))
		h.Write([]byte{0})
	}
	keys := make([]string, 0, len(entry.Fields))
	for key := range entry.Fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		h.Write([]byte(key))
		h.Write([]byte{0})
		h.Write([]byte(entry.Fields[key]))
		h.Write([]byte{0})
	}
	return "timeline:" + hex.EncodeToString(h.Sum(nil))
}

func firstString(object map[string]any, keys ...string) string {
	for _, key := range keys {
		value, ok := object[key]
		if !ok || value == nil {
			continue
		}
		switch typed := value.(type) {
		case string:
			if strings.TrimSpace(typed) != "" {
				return strings.TrimSpace(typed)
			}
		case float64:
			return strconv.FormatFloat(typed, 'f', -1, 64)
		case json.Number:
			return typed.String()
		}
	}
	return ""
}

func firstInt64(object map[string]any, keys ...string) int64 {
	for _, key := range keys {
		value, ok := object[key]
		if !ok || value == nil {
			continue
		}
		switch typed := value.(type) {
		case float64:
			return int64(typed)
		case string:
			if parsed, err := strconv.ParseInt(strings.TrimSpace(typed), 10, 64); err == nil {
				return parsed
			}
		case json.Number:
			if parsed, err := typed.Int64(); err == nil {
				return parsed
			}
		}
	}
	return 0
}

func flattenStrings(object map[string]any) map[string]string {
	result := map[string]string{}
	for key, value := range object {
		switch typed := value.(type) {
		case string:
			result[key] = typed
		case float64:
			result[key] = strconv.FormatFloat(typed, 'f', -1, 64)
		case bool:
			result[key] = strconv.FormatBool(typed)
		case json.Number:
			result[key] = typed.String()
		}
	}
	return result
}
