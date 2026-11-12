package cloudinventory

import (
	"os"
	"path/filepath"
	"testing"
)

func TestImportKubernetesInventory(t *testing.T) {
	p := filepath.Join(t.TempDir(), "k8s.json")
	body := `{"provider":"kubernetes","scope_id":"lab","resources":[{"id":"ns/a","type":"Namespace","name":"a"},{"id":"pod/a","type":"Pod","name":"p"}],"relationships":[{"from":"ns/a","to":"pod/a","kind":"contains"}]}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := Import(p, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !r.ReadOnly || r.Graph.SHA256 == "" || len(r.Graph.Edges) != 1 {
		t.Fatalf("report=%+v", r)
	}
}
