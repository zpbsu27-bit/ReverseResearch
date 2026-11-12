package attackgraph

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

var allowedNodeKinds = map[string]bool{
	"host": true, "identity": true, "group": true, "service": true, "application": true,
	"cloud-principal": true, "role": true, "trust": true, "credential-reference": true,
	"vulnerability": true, "session": true, "data-asset": true, "resource": true,
	"namespace": true, "workload": true, "certificate-template": true, "container-image": true,
}

var allowedEdgeKinds = map[string]bool{
	"authenticates-to": true, "admin-of": true, "member-of": true, "trusts": true,
	"can-assume": true, "exposes": true, "reachable-from": true, "vulnerable-to": true,
	"runs-on": true, "owns": true, "bound-to": true, "contains": true, "can-access": true,
}

type Node struct {
	ID         string            `json:"id"`
	Kind       string            `json:"kind"`
	Name       string            `json:"name,omitempty"`
	Properties map[string]string `json:"properties,omitempty"`
}

type Edge struct {
	From        string            `json:"from"`
	To          string            `json:"to"`
	Kind        string            `json:"kind"`
	EvidenceIDs []string          `json:"evidence_ids,omitempty"`
	Properties  map[string]string `json:"properties,omitempty"`
}

type Input struct {
	SourceKind string `json:"source_kind,omitempty"`
	Nodes      []Node `json:"nodes"`
	Edges      []Edge `json:"edges"`
}

type Graph struct {
	Version    int    `json:"version"`
	SourceKind string `json:"source_kind,omitempty"`
	Nodes      []Node `json:"nodes"`
	Edges      []Edge `json:"edges"`
	SHA256     string `json:"sha256"`
}

type PathResult struct {
	Found bool   `json:"found"`
	Nodes []Node `json:"nodes,omitempty"`
	Edges []Edge `json:"edges,omitempty"`
}

func Build(input Input) (Graph, error) {
	if len(input.Nodes) == 0 {
		return Graph{}, errors.New("attack graph requires at least one node")
	}
	if len(input.Nodes) > 100000 || len(input.Edges) > 500000 {
		return Graph{}, errors.New("attack graph exceeds bounded limits")
	}
	nodes := append([]Node(nil), input.Nodes...)
	edges := append([]Edge(nil), input.Edges...)
	ids := map[string]bool{}
	for i := range nodes {
		nodes[i].ID = strings.TrimSpace(nodes[i].ID)
		nodes[i].Kind = strings.ToLower(strings.TrimSpace(nodes[i].Kind))
		nodes[i].Name = strings.TrimSpace(nodes[i].Name)
		if nodes[i].ID == "" || !allowedNodeKinds[nodes[i].Kind] {
			return Graph{}, fmt.Errorf("invalid node %d id/kind", i)
		}
		if ids[nodes[i].ID] {
			return Graph{}, fmt.Errorf("duplicate node id %q", nodes[i].ID)
		}
		if err := validateProperties(nodes[i].Properties); err != nil {
			return Graph{}, fmt.Errorf("node %s: %w", nodes[i].ID, err)
		}
		ids[nodes[i].ID] = true
	}
	for i := range edges {
		edges[i].From = strings.TrimSpace(edges[i].From)
		edges[i].To = strings.TrimSpace(edges[i].To)
		edges[i].Kind = strings.ToLower(strings.TrimSpace(edges[i].Kind))
		if !ids[edges[i].From] || !ids[edges[i].To] {
			return Graph{}, fmt.Errorf("edge %d references missing endpoint", i)
		}
		if !allowedEdgeKinds[edges[i].Kind] {
			return Graph{}, fmt.Errorf("edge %d has invalid kind %q", i, edges[i].Kind)
		}
		if err := validateProperties(edges[i].Properties); err != nil {
			return Graph{}, fmt.Errorf("edge %d: %w", i, err)
		}
		edges[i].EvidenceIDs = uniqueSorted(edges[i].EvidenceIDs)
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].From != edges[j].From {
			return edges[i].From < edges[j].From
		}
		if edges[i].To != edges[j].To {
			return edges[i].To < edges[j].To
		}
		return edges[i].Kind < edges[j].Kind
	})
	g := Graph{Version: 1, SourceKind: strings.TrimSpace(input.SourceKind), Nodes: nodes, Edges: edges}
	body, _ := json.Marshal(struct {
		Version    int    `json:"version"`
		SourceKind string `json:"source_kind,omitempty"`
		Nodes      []Node `json:"nodes"`
		Edges      []Edge `json:"edges"`
	}{g.Version, g.SourceKind, g.Nodes, g.Edges})
	sum := sha256.Sum256(body)
	g.SHA256 = hex.EncodeToString(sum[:])
	return g, nil
}

func ShortestPath(g Graph, from, to string, maxDepth int) (PathResult, error) {
	from = strings.TrimSpace(from)
	to = strings.TrimSpace(to)
	if maxDepth <= 0 {
		maxDepth = 12
	}
	if maxDepth > 64 {
		maxDepth = 64
	}
	nodeByID := map[string]Node{}
	for _, n := range g.Nodes {
		nodeByID[n.ID] = n
	}
	if _, ok := nodeByID[from]; !ok {
		return PathResult{}, fmt.Errorf("source node %q not found", from)
	}
	if _, ok := nodeByID[to]; !ok {
		return PathResult{}, fmt.Errorf("target node %q not found", to)
	}
	type step struct {
		node  string
		depth int
	}
	q := []step{{from, 0}}
	seen := map[string]bool{from: true}
	prevNode := map[string]string{}
	prevEdge := map[string]Edge{}
	adj := map[string][]Edge{}
	for _, e := range g.Edges {
		adj[e.From] = append(adj[e.From], e)
	}
	for len(q) > 0 {
		cur := q[0]
		q = q[1:]
		if cur.node == to {
			break
		}
		if cur.depth >= maxDepth {
			continue
		}
		for _, e := range adj[cur.node] {
			if seen[e.To] {
				continue
			}
			seen[e.To] = true
			prevNode[e.To] = cur.node
			prevEdge[e.To] = e
			q = append(q, step{e.To, cur.depth + 1})
		}
	}
	if !seen[to] {
		return PathResult{Found: false}, nil
	}
	ids := []string{to}
	es := []Edge{}
	for ids[len(ids)-1] != from {
		n := ids[len(ids)-1]
		es = append(es, prevEdge[n])
		ids = append(ids, prevNode[n])
	}
	reverseStrings(ids)
	reverseEdges(es)
	out := PathResult{Found: true}
	for _, id := range ids {
		out.Nodes = append(out.Nodes, nodeByID[id])
	}
	out.Edges = es
	return out, nil
}

func validateProperties(p map[string]string) error {
	for k := range p {
		l := strings.ToLower(strings.TrimSpace(k))
		if strings.Contains(l, "password") || strings.Contains(l, "secret") || strings.Contains(l, "token") || strings.Contains(l, "private_key") || strings.Contains(l, "private-key") {
			return fmt.Errorf("secret-bearing property %q is not allowed; store an opaque credential reference", k)
		}
	}
	return nil
}
func uniqueSorted(in []string) []string {
	m := map[string]bool{}
	out := []string{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v != "" && !m[v] {
			m[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}
func reverseStrings(x []string) {
	for i, j := 0, len(x)-1; i < j; i, j = i+1, j-1 {
		x[i], x[j] = x[j], x[i]
	}
}
func reverseEdges(x []Edge) {
	for i, j := 0, len(x)-1; i < j; i, j = i+1, j-1 {
		x[i], x[j] = x[j], x[i]
	}
}
