package attackgraph

import "testing"

func TestBuildAndShortestPath(t *testing.T) {
	g, err := Build(Input{SourceKind: "bloodhound-export", Nodes: []Node{
		{ID: "u", Kind: "identity"}, {ID: "g", Kind: "group"}, {ID: "h", Kind: "host"},
	}, Edges: []Edge{{From: "u", To: "g", Kind: "member-of"}, {From: "g", To: "h", Kind: "admin-of"}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(g.SHA256) != 64 {
		t.Fatalf("sha=%q", g.SHA256)
	}
	p, err := ShortestPath(g, "u", "h", 4)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Found || len(p.Edges) != 2 {
		t.Fatalf("path=%+v", p)
	}
}
func TestRejectsSecretBearingProperties(t *testing.T) {
	_, err := Build(Input{Nodes: []Node{{ID: "u", Kind: "identity", Properties: map[string]string{"password": "x"}}}})
	if err == nil {
		t.Fatal("plaintext secret property accepted")
	}
}
