package casebook

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"reverseresearch/internal/recordio"
)

func TestCaseRecentIndexListsNewestAndRebuildsCorruptCache(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var created []Case
	for _, title := range []string{"one", "two", "three"} {
		value, err := store.Create(CreateRequest{Title: title})
		if err != nil {
			t.Fatal(err)
		}
		created = append(created, value)
		time.Sleep(2 * time.Millisecond)
	}
	recent, err := store.List(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(recent) != 2 || recent[0].ID != created[2].ID || recent[1].ID != created[1].ID {
		t.Fatalf("recent=%+v created=%+v", recent, created)
	}

	if err := os.WriteFile(store.indexPath(), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	recent, err = store.List(3)
	if err != nil {
		t.Fatal(err)
	}
	if len(recent) != 3 || recent[0].ID != created[2].ID {
		t.Fatalf("rebuilt recent=%+v", recent)
	}
}

func TestCaseRecentDirtyMarkerRepairsCommittedCanonicalState(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	value, err := store.Create(CreateRequest{Title: "before"})
	if err != nil {
		t.Fatal(err)
	}

	value.Title = "after"
	value.UpdatedUTC = time.Now().UTC().Add(time.Second).Format(time.RFC3339Nano)
	if err := store.markCaseIndexDirty(value); err != nil {
		t.Fatal(err)
	}
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	body = append(body, '\n')
	if err := recordio.WriteFile(store.casePath(value.ID), body, 0o600); err != nil {
		t.Fatal(err)
	}

	recent, err := store.List(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(recent) != 1 || recent[0].ID != value.ID || recent[0].Title != "after" {
		t.Fatalf("recent=%+v", recent)
	}
	if _, err := os.Stat(store.indexDirtyPath(value.ID)); !os.IsNotExist(err) {
		t.Fatalf("committed dirty marker was not cleared: %v", err)
	}
}

func TestCaseDirtyMarkerClearCannotEraseNewerWriter(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	value, err := store.Create(CreateRequest{Title: "marker-owner"})
	if err != nil {
		t.Fatal(err)
	}
	older := value
	older.UpdatedUTC = time.Now().UTC().Add(time.Second).Format(time.RFC3339Nano)
	newer := value
	newer.UpdatedUTC = time.Now().UTC().Add(2 * time.Second).Format(time.RFC3339Nano)

	if err := store.markCaseIndexDirty(older); err != nil {
		t.Fatal(err)
	}
	if err := store.markCaseIndexDirty(newer); err != nil {
		t.Fatal(err)
	}
	if err := store.clearCaseIndexDirty(value.ID, older.UpdatedUTC); err != nil {
		t.Fatal(err)
	}
	body, err := recordio.ReadFileLimit(store.indexDirtyPath(value.ID), caseDirtyMaxBytes)
	if err != nil {
		t.Fatalf("older writer cleared newer marker: %v", err)
	}
	var marker caseDirtyMarker
	if err := json.Unmarshal(body, &marker); err != nil {
		t.Fatal(err)
	}
	if marker.UpdatedUTC != newer.UpdatedUTC {
		t.Fatalf("marker=%+v want newer=%s", marker, newer.UpdatedUTC)
	}
	if err := store.clearCaseIndexDirty(value.ID, newer.UpdatedUTC); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(store.indexDirtyPath(value.ID)); !os.IsNotExist(err) {
		t.Fatalf("newer writer did not clear its marker: %v", err)
	}
}

func TestCaseRecentIndexRejectsOversizedCache(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	index := caseIndex{Version: caseIndexVersion, Entries: make([]caseIndexEntry, caseRecentLimit+1)}
	if err := store.writeCaseIndex(index); err == nil {
		t.Fatal("oversized recent index was accepted")
	}
}
