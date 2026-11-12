package main

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"reverseresearch/internal/knowledge"
)

func TestCLIJournalRevisionRead(t *testing.T) {
	root := t.TempDir()
	var note knowledge.Note
	if err := json.Unmarshal(recordCLI(t, root, "journal", "add", "--title", "sourced note", "--body", "first\nsecond\nthird", "--source", "local:research", "--license", "unspecified", "--source-revision", "fixture-v1", "--engine", "ghidra", "--target-version", "test-only"), &note); err != nil {
		t.Fatal(err)
	}
	var excerpt knowledge.Excerpt
	if err := json.Unmarshal(recordCLI(t, root, "journal", "read", note.ID, "--revision", note.Revision, "--start-line", "2", "--max-lines", "1"), &excerpt); err != nil {
		t.Fatal(err)
	}
	if excerpt.Text != "second" || excerpt.NextLine != 3 || excerpt.Source.Reference != "local:research" || excerpt.Source.UpstreamRevision != "fixture-v1" {
		t.Fatalf("excerpt=%+v", excerpt)
	}
	var stdout, stderr bytes.Buffer
	if err := runCLI(context.Background(), root, []string{"journal", "read", note.ID}, &stdout, &stderr); err == nil {
		t.Fatal("CLI allowed a read without revision")
	}
}

func TestCLIJournalOperationRetry(t *testing.T) {
	root := t.TempDir()
	args := []string{"journal", "add", "--operation-id", "cli-note-1", "--title", "immutable", "--body", "observed source bytes"}
	var first, repeated knowledge.Note
	if err := json.Unmarshal(recordCLI(t, root, args...), &first); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(recordCLI(t, root, args...), &repeated); err != nil {
		t.Fatal(err)
	}
	if first.ID != repeated.ID || first.Revision != repeated.Revision {
		t.Fatal("CLI retry duplicated the note")
	}
	args[len(args)-1] = "conflicting bytes"
	var stdout, stderr bytes.Buffer
	if err := runCLI(context.Background(), root, args, &stdout, &stderr); err == nil {
		t.Fatal("CLI accepted conflicting operation reuse")
	}
}
