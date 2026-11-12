package capability

import (
	"testing"

	"reverseresearch/internal/provision"
	"reverseresearch/internal/router"
	"reverseresearch/internal/toolindex"
)

func TestEvaluateRouteReadiness(t *testing.T) {
	routes := []router.Route{{
		ID:          "pwn-exploit",
		Description: "pwn",
		Tools:       []string{"gdb", "pwntools", "qemu"},
	}}
	index := toolindex.Index{Tools: []toolindex.Tool{
		{Name: "gdb", Available: true, Path: "C:/gdb.exe", Source: "path"},
		{Name: "pwntools", Available: false, Source: "missing"},
		{Name: "qemu", Available: false, Source: "missing"},
	}}
	manifest := provision.Manifest{
		Version: 1,
		Recipes: []provision.Recipe{{Tool: "pwntools", Provider: "pip", Package: "pwntools"}},
	}
	evaluator := New(routes, index, manifest)
	status, err := evaluator.Route("pwn-exploit")
	if err != nil {
		t.Fatal(err)
	}
	if !status.Runnable || status.FullReady {
		t.Fatalf("status=%+v", status)
	}
	if status.Available != 1 || status.Installable != 1 || status.NoRecipe != 1 {
		t.Fatalf("status=%+v", status)
	}
	if status.CoveragePercent != 33 {
		t.Fatalf("coverage=%d", status.CoveragePercent)
	}
}

func TestAllIsStableByRouteID(t *testing.T) {
	routes := []router.Route{
		{ID: "z", Tools: []string{"x"}},
		{ID: "a", Tools: []string{"x"}},
	}
	evaluator := New(routes, toolindex.Index{}, provision.Manifest{Version: 1})
	all := evaluator.All()
	if len(all) != 2 || all[0].RouteID != "a" || all[1].RouteID != "z" {
		t.Fatalf("all=%+v", all)
	}
}
