package collaboration

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"reverseresearch/internal/recordio"
)

func TestCollaborationHistoryArchivesOverflowWithoutLoss(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := store.Init("case_archive", "alice")
	if err != nil {
		t.Fatal(err)
	}

	extra := collaborationHistoryInlineLimit + 32
	_, err = store.mutateAction(
		"case_archive",
		workspace.Revision,
		HistoryEvent{Action: "bulk.finalize", Actor: "alice"},
		func(w *Workspace) error {
			base := time.Now().UTC().Add(-time.Hour)
			for i := 0; i < extra; i++ {
				w.History = append(w.History, HistoryEvent{
					ID:         fmt.Sprintf("seed_%04d", i),
					Action:     "seed",
					Actor:      "alice",
					CreatedUTC: base.Add(time.Duration(i) * time.Millisecond).Format(time.RFC3339Nano),
				})
			}
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	hot, err := store.Get("case_archive")
	if err != nil {
		t.Fatal(err)
	}
	if len(hot.History) != collaborationHistoryInlineLimit {
		t.Fatalf("hot history len=%d want=%d", len(hot.History), collaborationHistoryInlineLimit)
	}

	full, err := store.History("case_archive")
	if err != nil {
		t.Fatal(err)
	}
	wantTotal := extra + 2
	if len(full) != wantTotal {
		t.Fatalf("full history len=%d want=%d", len(full), wantTotal)
	}

	var archived int
	err = filepath.WalkDir(store.historyArchiveDir("case_archive"), func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
			archived++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := archived, wantTotal-collaborationHistoryInlineLimit; got != want {
		t.Fatalf("archive entries=%d want=%d", got, want)
	}
}

func TestArchivedHistoryEventIsImmutableShardedAndIdempotent(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	event := HistoryEvent{
		ID: "history_fixed", Action: "review.request", Actor: "alice",
		CreatedUTC: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := store.writeArchivedHistoryEvent("case", event); err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(store.historyArchivePath("case", event.ID)) == store.historyArchiveDir("case") {
		t.Fatal("history archive was not sharded")
	}
	if err := store.writeArchivedHistoryEvent("case", event); err != nil {
		t.Fatalf("idempotent rewrite failed: %v", err)
	}
	changed := event
	changed.Action = "review.decision"
	if err := store.writeArchivedHistoryEvent("case", changed); err == nil {
		t.Fatal("changed event with the same id replaced immutable archive")
	}
}

func TestArchivedHistoryReadsAndMigratesLegacyFlatEvent(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	event := HistoryEvent{
		ID: "history_legacy", Action: "legacy", Actor: "alice",
		CreatedUTC: time.Now().UTC().Format(time.RFC3339Nano),
	}
	body, err := json.MarshalIndent(event, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	body = append(body, '\n')
	legacy := store.legacyHistoryArchivePath("case", event.ID)
	if err := recordio.WriteFile(legacy, body, 0o600); err != nil {
		t.Fatal(err)
	}
	events, err := store.readArchivedHistory("case")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].ID != event.ID {
		t.Fatalf("legacy events=%+v", events)
	}
	if err := store.writeArchivedHistoryEvent("case", event); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(store.historyArchivePath("case", event.ID)); err != nil {
		t.Fatalf("sharded history missing: %v", err)
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatalf("legacy history was not removed: %v", err)
	}
}

func TestCollaborationRejectsUnsafeStorageIDs(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Init("../escape", "alice"); err == nil {
		t.Fatal("unsafe case id was accepted")
	}
	event := HistoryEvent{ID: "../escape", Action: "x", CreatedUTC: time.Now().UTC().Format(time.RFC3339Nano)}
	if err := store.writeArchivedHistoryEvent("case", event); err == nil {
		t.Fatal("unsafe history id was accepted")
	}
}
