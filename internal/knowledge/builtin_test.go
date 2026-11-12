package knowledge

import (
	"errors"
	"strings"
	"testing"
)

func TestBuiltinCorpusIsReadOnlySearchableAndRevisionPinned(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	builtins, err := builtinNotes()
	if err != nil {
		t.Fatal(err)
	}
	if len(builtins) != 11 {
		t.Fatalf("builtin count=%d want=11", len(builtins))
	}
	for _, note := range builtins {
		if note.Origin != OriginBuiltin || note.Source == nil || note.Source.EvidenceStatus != "reviewed" ||
			len(note.Revision) != 64 || note.Domain == "" || len(note.Architectures) == 0 || len(note.Tools) == 0 {
			t.Fatalf("invalid builtin=%+v", note)
		}
	}

	results, err := store.SearchFiltered(SearchRequest{
		Query:         "guarded mutation",
		Domain:        "native-dynamic",
		Architectures: []string{"x86"},
		Tools:         []string{"x32dbg"},
		Origin:        OriginBuiltin,
		Limit:         10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].ID != "builtin_x32_process_guard" || results[0].Origin != OriginBuiltin {
		t.Fatalf("results=%+v", results)
	}
	part, err := store.Read(ReadRequest{
		ID: results[0].ID, Revision: results[0].Revision, StartLine: 1, MaxLines: 1,
	})
	if err != nil || !strings.Contains(part.Text, "Before a typed x32dbg mutation") {
		t.Fatalf("read=%+v err=%v", part, err)
	}
	if _, err := store.Read(ReadRequest{ID: results[0].ID, Revision: strings.Repeat("0", 64)}); !errors.Is(err, ErrRevisionChanged) {
		t.Fatalf("stale builtin revision accepted: %v", err)
	}
}

func TestStructuredKnowledgeFiltersDoNotPromoteUnspecifiedLegacyMetadata(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	local, err := store.Add(AddRequest{
		Title: "local ghidra note", Body: "unicode path recovery", Tags: []string{"ghidra"},
	})
	if err != nil {
		t.Fatal(err)
	}
	filtered, err := store.SearchFiltered(SearchRequest{
		Query:         "unicode",
		Domain:        "static-analysis",
		Architectures: []string{"x86-64"},
		Tools:         []string{"ghidra"},
		Origin:        OriginJournal,
		Limit:         10,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, result := range filtered {
		if result.ID == local.ID {
			t.Fatalf("unstructured local note leaked through structured filters: %+v", result)
		}
	}

	structured, err := store.Add(AddRequest{
		Title: "structured ghidra note", Body: "unicode path recovery",
		Domain: "static-analysis", Architectures: []string{"x86-64"}, Tools: []string{"ghidra"},
	})
	if err != nil {
		t.Fatal(err)
	}
	filtered, err = store.SearchFiltered(SearchRequest{
		Query: "unicode", Domain: "static-analysis", Architectures: []string{"x86-64"},
		Tools: []string{"ghidra"}, Origin: OriginJournal, Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, result := range filtered {
		found = found || result.ID == structured.ID
	}
	if !found {
		t.Fatalf("structured local note not found: %+v", filtered)
	}
}

func TestArchitectureAliasesNormalizeForFilters(t *testing.T) {
	values, err := normalizeScopeValues("architecture", []string{"x64", "amd64", "x86_64", "i686", "aarch64"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"arm64", "x86", "x86-64"}
	if len(values) != len(want) {
		t.Fatalf("values=%v want=%v", values, want)
	}
	for i := range want {
		if values[i] != want[i] {
			t.Fatalf("values=%v want=%v", values, want)
		}
	}
}

func TestSearchFiltersCanSelectBuiltinWithoutTextQuery(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	results, err := store.SearchFiltered(SearchRequest{
		Domain: "static-analysis", Tools: []string{"ghidra"}, Origin: OriginBuiltin, Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].ID != "builtin_ghidra_project_currentness" {
		t.Fatalf("results=%+v", results)
	}
}
