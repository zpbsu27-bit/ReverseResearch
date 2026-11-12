package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"reverseresearch/internal/casebook"
	"reverseresearch/internal/knowledge"
)

func recordCLI(t *testing.T, root string, args ...string) []byte {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if err := runCLI(context.Background(), root, args, &stdout, &stderr); err != nil {
		t.Fatalf("%v: %v; stderr=%s", args, err, stderr.String())
	}
	return stdout.Bytes()
}

func TestCLIRecordInspection(t *testing.T) {
	root := t.TempDir()
	var c casebook.Case
	if err := json.Unmarshal(recordCLI(t, root, "case", "create", "--title", "persisted case"), &c); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "source.bin")
	if err := os.WriteFile(source, []byte("ABC"), 0o600); err != nil {
		t.Fatal(err)
	}
	recordCLI(t, root, "case", "evidence", c.ID, "--summary", "bound bytes", "--source", source)
	var listed []casebook.Case
	if err := json.Unmarshal(recordCLI(t, root, "case", "list", "--limit", "1"), &listed); err != nil || len(listed) != 1 || listed[0].ID != c.ID {
		t.Fatalf("list=%+v err=%v", listed, err)
	}
	var verified casebook.Verification
	if err := json.Unmarshal(recordCLI(t, root, "case", "verify", c.ID), &verified); err != nil || !verified.Valid || len(verified.CaseSHA256) != 64 {
		t.Fatalf("verify=%+v err=%v", verified, err)
	}
	before, err := os.ReadFile(filepath.Join(root, "state", "research", "cases", c.ID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("XYZ"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := runCLI(context.Background(), root, []string{"case", "verify", c.ID}, &stdout, &stderr); err == nil {
		t.Fatal("source drift must produce a non-success exit status")
	}
	if err := json.Unmarshal(stdout.Bytes(), &verified); err != nil || verified.Valid || len(verified.Issues) != 1 || verified.Issues[0].Code != "source_changed" {
		t.Fatalf("failed audit must still produce structured JSON: %+v %v", verified, err)
	}
	after, err := os.ReadFile(filepath.Join(root, "state", "research", "cases", c.ID+".json"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("verification rewrote the case: %v", err)
	}
}

func TestCLIJournalShow(t *testing.T) {
	root := t.TempDir()
	var added, got knowledge.Note
	if err := json.Unmarshal(recordCLI(t, root, "journal", "add", "--title", "saved observation", "--body", "not executable instructions"), &added); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(recordCLI(t, root, "journal", "show", added.ID), &got); err != nil || got.ID != added.ID || got.Body != added.Body {
		t.Fatalf("persisted note=%+v err=%v", got, err)
	}
}

func TestCLIRecordInspectionRejectsBadArguments(t *testing.T) {
	for _, args := range [][]string{
		{"case", "list", "extra"},
		{"case", "list", "--limit", "0"},
		{"case", "list", "--limit", "101"},
		{"case", "verify"},
		{"case", "verify", "../outside"},
		{"journal", "show"},
		{"journal", "show", "../outside"},
	} {
		var stdout, stderr bytes.Buffer
		if err := runCLI(context.Background(), t.TempDir(), args, &stdout, &stderr); err == nil {
			t.Errorf("invalid arguments accepted: %v", args)
		}
	}
}
