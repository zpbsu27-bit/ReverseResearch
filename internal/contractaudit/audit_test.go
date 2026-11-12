package contractaudit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCurrentOnlineSnapshotMatchesBackendCatalogs(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	report, err := Audit(filepath.Join(root, "testdata", "online-rr-rt-contract-20261001.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !report.Match {
		body, _ := json.MarshalIndent(report, "", "  ")
		t.Fatalf("online/local backend contract drift:\n%s", body)
	}
	if report.SnapshotToolCount != 124 || report.LocalBaseToolCount != 124 ||
		report.RRToolCount != 124 || report.RTToolCount != 124 || !report.RRRTNormalizedEqual {
		t.Fatalf("report=%+v", report)
	}
}

func TestFindDefaultSnapshotWalksAncestorDirectories(t *testing.T) {
	root := t.TempDir()
	snapshotDir := filepath.Join(root, "testdata")
	if err := os.MkdirAll(snapshotDir, 0o700); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(snapshotDir, DefaultSnapshotName)
	if err := os.WriteFile(want, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(root, ".tmp", "record-closeout", "smoke-fixture")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	got, err := FindDefaultSnapshot(nested)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Clean(got) != filepath.Clean(want) {
		t.Fatalf("snapshot=%q want=%q", got, want)
	}
}

func TestSchemaTypeNormalizesNullableArray(t *testing.T) {
	schema := map[string]any{
		"anyOf": []any{
			map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			map[string]any{"type": "null"},
		},
	}
	if got := schemaType(schema); got != "array" {
		t.Fatalf("schemaType=%q want array", got)
	}
}

func TestAuditReportsDescriptionDrift(t *testing.T) {
	local, err := LocalBaseContract()
	if err != nil {
		t.Fatal(err)
	}
	snapshot := Snapshot{
		SchemaVersion:       1,
		ObservedDateUTC:     "fixture",
		Source:              "fixture",
		RRToolCount:         len(local),
		RTToolCount:         len(local),
		RRRTNormalizedEqual: true,
		Tools:               append([]Tool(nil), local...),
	}
	snapshot.Tools[0].Description += " drift"

	root := t.TempDir()
	path := filepath.Join(root, "snapshot.json")
	body, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := Audit(path)
	if err != nil {
		t.Fatal(err)
	}
	if report.Match || len(report.ParameterDiffs) != 1 ||
		report.ParameterDiffs[0].Name != snapshot.Tools[0].Name ||
		report.ParameterDiffs[0].SnapshotDescription == report.ParameterDiffs[0].LocalDescription {
		t.Fatalf("report=%+v", report)
	}
}

func TestAuditReportsParameterDrift(t *testing.T) {
	local, err := LocalBaseContract()
	if err != nil {
		t.Fatal(err)
	}
	if len(local) == 0 {
		t.Fatal("local base contract is empty")
	}
	snapshot := Snapshot{
		SchemaVersion:       1,
		ObservedDateUTC:     "fixture",
		Source:              "fixture",
		RRToolCount:         len(local),
		RTToolCount:         len(local),
		RRRTNormalizedEqual: true,
		Tools:               append([]Tool(nil), local...),
	}
	for i := range snapshot.Tools {
		snapshot.Tools[i].Params = append([]Parameter(nil), snapshot.Tools[i].Params...)
	}
	target := -1
	for i := range snapshot.Tools {
		if len(snapshot.Tools[i].Params) > 0 {
			target = i
			break
		}
	}
	if target < 0 {
		t.Fatal("no tool with parameters")
	}
	snapshot.Tools[target].Params[0].Required = !snapshot.Tools[target].Params[0].Required

	root := t.TempDir()
	path := filepath.Join(root, "snapshot.json")
	body, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := Audit(path)
	if err != nil {
		t.Fatal(err)
	}
	if report.Match || len(report.ParameterDiffs) != 1 ||
		report.ParameterDiffs[0].Name != snapshot.Tools[target].Name {
		t.Fatalf("report=%+v", report)
	}
}
