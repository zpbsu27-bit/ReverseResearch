package knowledgepack

import (
	"path/filepath"
	"testing"

	"reverseresearch/internal/knowledge"
)

func TestKnowledgePacksLoadAndBindReviewedBuiltinNotes(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	store, err := knowledge.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	registry, err := Load(filepath.Join(root, "config", "knowledge-packs.json"), store)
	if err != nil {
		t.Fatal(err)
	}
	packs := registry.List()
	if len(packs) != 6 {
		t.Fatalf("packs=%d want=6", len(packs))
	}
	blue := registry.ForRoute("blue-detection")
	if len(blue) != 4 {
		t.Fatalf("blue-detection packs=%+v", blue)
	}
	detection, err := registry.Get("detection-engineering")
	if err != nil {
		t.Fatal(err)
	}
	if len(detection.Standards) != 3 || len(detection.NoteIDs) != 1 {
		t.Fatalf("detection pack=%+v", detection)
	}
}

func TestP1RoutesResolveReviewedKnowledgePacks(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	store, err := knowledge.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	registry, err := Load(filepath.Join(root, "config", "knowledge-packs.json"), store)
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range []string{"linux-native", "vuln-research", "dfir-forensics", "traffic-protocol", "source-code-audit", "supply-chain"} {
		packs := registry.ForRoute(route)
		if len(packs) == 0 {
			t.Fatalf("route %s has no knowledge packs", route)
		}
		for _, pack := range packs {
			if pack.TrustStatus != "reviewed" || len(pack.NoteIDs) == 0 {
				t.Fatalf("route %s pack=%+v", route, pack)
			}
		}
	}
}
