package knowledge

import (
	"testing"
)

func TestAddAndSearchNotes(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	note, err := store.Add(AddRequest{
		Title: "Ghidra Unicode path recovery",
		Body:  "Use an ASCII content-addressed project name and reclaim dead database IDs.",
		Route: "native-static",
		Tags:  []string{"ghidra", "unicode", "database"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if note.ID == "" {
		t.Fatal("empty note id")
	}

	results, err := store.Search("unicode database", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].ID != note.ID {
		t.Fatalf("results=%+v", results)
	}

	none, err := store.Search("completely unrelated", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(none) != 0 {
		t.Fatalf("unexpected=%+v", none)
	}
}

func TestSearchRanksMultiTermMatchesFirst(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = store.Add(AddRequest{Title: "Ghidra path", Body: "unicode support", Tags: []string{"ghidra"}})
	best, _ := store.Add(AddRequest{Title: "Ghidra Unicode Database", Body: "path database recovery", Tags: []string{"ghidra", "unicode", "database"}})
	results, err := store.Search("ghidra unicode database", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) < 2 || results[0].ID != best.ID {
		t.Fatalf("ranking=%+v", results)
	}
}
