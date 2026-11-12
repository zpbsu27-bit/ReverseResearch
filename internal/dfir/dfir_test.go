package dfir

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestInspectClassifiesForensicArtifactsWithoutMutation(t *testing.T) {
	root := t.TempDir()
	cases := map[string]ArtifactKind{
		"events.evtx":    KindEVTX,
		"capture.pcapng": KindPCAP,
		"memory.raw":     KindMemoryDump,
		"disk.E01":       KindDiskImage,
		"NTUSER.DAT":     KindRegistry,
	}
	for name, want := range cases {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := Inspect(path)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got.Kind != want || !got.ReadOnly || got.Identity.SHA256 == "" {
			t.Fatalf("%s artifact=%+v want kind=%s", name, got, want)
		}
	}
}

func TestImportTimelineJSONLSortsDedupesAndPreservesProvenance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hayabusa.jsonl")
	body := "" +
		"{\"Timestamp\":\"2026-10-02T10:00:02Z\",\"Computer\":\"host-a\",\"User\":\"alice\",\"Image\":\"cmd.exe\",\"ProcessId\":42,\"EventID\":\"1\"}\n" +
		"{\"Timestamp\":\"2026-10-02T10:00:01Z\",\"Computer\":\"host-a\",\"User\":\"alice\",\"Image\":\"parent.exe\",\"ProcessId\":10,\"EventID\":\"1\"}\n" +
		"{\"Timestamp\":\"2026-10-02T10:00:01Z\",\"Computer\":\"host-a\",\"User\":\"alice\",\"Image\":\"parent.exe\",\"ProcessId\":10,\"EventID\":\"1\"}\n" +
		"{\"bad\":true}\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ImportTimelineJSONL(path, ImportOptions{Format: "hayabusa-jsonl"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Entries) != 2 || got.Duplicates != 1 || got.Rejected != 1 || !got.SourceUnchanged {
		t.Fatalf("timeline=%+v", got)
	}
	if got.Entries[0].PID != 10 || got.Entries[1].PID != 42 {
		t.Fatalf("timeline not sorted: %+v", got.Entries)
	}
	for _, entry := range got.Entries {
		if entry.ArtifactSHA256 != got.Source.Identity.SHA256 || entry.SourceLine == 0 || entry.ID == "" {
			t.Fatalf("entry provenance incomplete: %+v", entry)
		}
	}
}

func TestImportTimelineJSONLRejectsEntryLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	body := "{\"timestamp\":\"2026-10-02T10:00:00Z\",\"event\":\"a\"}\n" +
		"{\"timestamp\":\"2026-10-02T10:00:01Z\",\"event\":\"b\"}\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ImportTimelineJSONL(path, ImportOptions{MaxEntries: 1}); err == nil {
		t.Fatal("expected entry limit failure")
	}
}

func TestInspectContextHonorsCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "memory.raw")
	if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := InspectContext(ctx, path); !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v want context.Canceled", err)
	}
}

func TestImportTimelineJSONLContextHonorsCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	if err := os.WriteFile(path, []byte("{\"timestamp\":\"2026-10-02T10:00:00Z\",\"event\":\"a\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ImportTimelineJSONLContext(ctx, path, ImportOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v want context.Canceled", err)
	}
}
