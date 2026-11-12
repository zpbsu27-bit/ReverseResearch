package provision

import (
	"os"
	"path/filepath"
	"testing"

	"reverseresearch/internal/toolindex"
)

func TestPlannerClassifiesAvailableMissingAndUnknownRecipe(t *testing.T) {
	root := t.TempDir()
	manifestPath := filepath.Join(root, "recipes.json")
	body := []byte(`{
	  "version": 1,
	  "recipes": [
	    {"tool":"frida","provider":"pip","package":"frida-tools","scope":"user"},
	    {"tool":"wireshark","provider":"manual","package":"Wireshark","scope":"machine"}
	  ]
	}`)
	if err := os.WriteFile(manifestPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, err := LoadManifest(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	planner := NewPlanner(manifest, toolindex.Index{
		Tools: []toolindex.Tool{
			{Name: "frida", Available: false, Source: "missing"},
			{Name: "wireshark", Available: true, Path: "C:/Wireshark.exe", Source: "path"},
			{Name: "nmap", Available: false, Source: "missing"},
		},
	})
	plan, err := planner.Plan([]string{"frida", "wireshark", "nmap"})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Items) != 3 {
		t.Fatalf("plan=%+v", plan)
	}
	if plan.Items[0].Status != StatusInstallable {
		t.Fatalf("frida=%+v", plan.Items[0])
	}
	if plan.Items[1].Status != StatusAvailable {
		t.Fatalf("wireshark=%+v", plan.Items[1])
	}
	if plan.Items[2].Status != StatusNoRecipe {
		t.Fatalf("nmap=%+v", plan.Items[2])
	}
}

func TestManifestRejectsDuplicateRecipes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "recipes.json")
	if err := os.WriteFile(path, []byte(`{
	  "version":1,
	  "recipes":[
	    {"tool":"x","provider":"manual","package":"x"},
	    {"tool":"x","provider":"manual","package":"x2"}
	  ]
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadManifest(path); err == nil {
		t.Fatal("expected duplicate recipe failure")
	}
}

func TestProjectToolRecipesV2AreComplete(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "config", "tool-recipes.json"))
	manifest, err := LoadManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Version != 2 {
		t.Fatalf("manifest version=%d want=2", manifest.Version)
	}
	for _, recipe := range manifest.Recipes {
		if recipe.CanonicalSource == "" || recipe.License == "" || recipe.Redistribution == "" || recipe.InstallScope == "" ||
			len(recipe.ExpectedExecutables) == 0 || len(recipe.PostInstallSmoke) == 0 ||
			len(recipe.SupportedPlatforms) == 0 || len(recipe.SupportedArchitectures) == 0 {
			t.Fatalf("incomplete v2 recipe: %+v", recipe)
		}
		if recipe.Commercial && recipe.Redistributable {
			t.Fatalf("commercial recipe must be installed-only/non-redistributable: %+v", recipe)
		}
	}
}

func TestToolRecipeV2RejectsIncompleteAndCommercialRedistribution(t *testing.T) {
	path := filepath.Join(t.TempDir(), "recipes.json")
	if err := os.WriteFile(path, []byte(`{
	  "version":2,
	  "recipes":[{
	    "tool":"x","provider":"manual","package":"x",
	    "canonical_source":"vendor","license":"unknown","redistribution":"review",
	    "install_scope":"user","expected_executables":["x.exe"],
	    "post_install_smoke":["x --version"],"supported_platforms":["windows"],
	    "supported_architectures":["x86-64"]
	  }]
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadManifest(path); err != nil {
		t.Fatalf("complete v2 recipe rejected: %v", err)
	}

	if err := os.WriteFile(path, []byte(`{
	  "version":2,
	  "recipes":[{
	    "tool":"x","provider":"installed-only","package":"x",
	    "canonical_source":"vendor","license":"proprietary","redistribution":"prohibited",
	    "install_scope":"user","expected_executables":["x.exe"],
	    "post_install_smoke":["identity present"],"supported_platforms":["windows"],
	    "supported_architectures":["x86-64"],"commercial":true,"redistributable":true
	  }]
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadManifest(path); err == nil {
		t.Fatal("commercial redistributable v2 recipe was accepted")
	}
}

func TestP2RouteToolsHaveRecipes(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "config", "tool-recipes.json"))
	manifest, err := LoadManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	required := []string{
		"atomic-red-team", "aws", "az", "binwalk", "bloodhound", "caldera", "certipy", "curl",
		"frida", "gcloud", "ghidra", "impacket", "kube-bench", "kubectl", "kubescape", "lldb",
		"masscan", "misp", "netexec", "nmap", "opencti", "osquery", "prowler", "qemu", "scoutsuite",
		"sharphound", "sigma", "sqlmap", "steampipe", "taxii", "trivy", "zeek",
	}
	for _, name := range required {
		recipe, ok := manifest.byTool[name]
		if !ok {
			t.Fatalf("P2 route tool has no Tool Recipe v2: %s", name)
		}
		if recipe.CanonicalSource == "" || recipe.License == "" || recipe.InstallScope == "" || len(recipe.PostInstallSmoke) == 0 {
			t.Fatalf("P2 recipe incomplete: %+v", recipe)
		}
	}
}
