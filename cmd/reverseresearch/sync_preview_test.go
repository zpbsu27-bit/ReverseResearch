package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"reverseresearch/internal/migration"
)

func TestCLISemanticSyncPreviewIsNonDestructive(t *testing.T) {
	root := t.TempDir()
	request := migration.SyncPreviewRequest{
		Migration: migration.Result{Entries: []migration.Entry{{
			Label: "unit-update", Status: migration.StatusMapped, OldRVA: 0x1000, NewRVA: 0x2000,
		}}},
		Source: migration.SemanticSnapshot{Functions: []migration.FunctionSemantic{{
			RVA: 0x1000, Name: "UpdateUnit", NameOrigin: migration.NameOriginUser,
			Comments: []migration.SemanticComment{{Kind: "plate", Text: "source note"}},
		}}},
		Target: migration.SemanticSnapshot{Functions: []migration.FunctionSemantic{{
			RVA: 0x2000, Name: "ManualUpdateUnit", NameOrigin: migration.NameOriginUser,
			Comments: []migration.SemanticComment{{Kind: "plate", Text: "target note"}},
		}}},
	}
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	requestPath := filepath.Join(root, "sync-preview.json")
	if err := os.WriteFile(requestPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := runCLI(context.Background(), root, []string{"sync", "preview", "--json-file", requestPath}, &stdout, &stderr); err != nil {
		t.Fatalf("sync preview err=%v stderr=%s", err, stderr.String())
	}
	var result migration.SyncPreview
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Validation != "preview-only" || result.RuntimeVerified || result.WritesPerformed {
		t.Fatalf("result=%+v", result)
	}
	if result.Preserved != 1 || result.Conflicts != 1 || result.Suggested != 0 {
		t.Fatalf("result=%+v", result)
	}
}
