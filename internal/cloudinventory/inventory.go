package cloudinventory

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"reverseresearch/internal/attackgraph"
	"reverseresearch/internal/targetidentity"
)

const DefaultMaxBytes int64 = 64 << 20

type Resource struct {
	ID         string            `json:"id"`
	Type       string            `json:"type"`
	Name       string            `json:"name,omitempty"`
	Region     string            `json:"region,omitempty"`
	Public     bool              `json:"public,omitempty"`
	Properties map[string]string `json:"properties,omitempty"`
}
type Relationship struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"`
}
type Document struct {
	Provider      string         `json:"provider"`
	ScopeID       string         `json:"scope_id"`
	Resources     []Resource     `json:"resources"`
	Relationships []Relationship `json:"relationships,omitempty"`
}
type Report struct {
	Source    targetidentity.Identity `json:"source"`
	Provider  string                  `json:"provider"`
	ScopeID   string                  `json:"scope_id"`
	Resources []Resource              `json:"resources"`
	Graph     attackgraph.Graph       `json:"graph"`
	ReadOnly  bool                    `json:"read_only"`
}

func Import(path string, maxBytes int64) (Report, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	if maxBytes > 256<<20 {
		maxBytes = 256 << 20
	}
	src, err := targetidentity.InspectBounded(path, maxBytes)
	if err != nil {
		return Report{}, err
	}
	if src.Size > maxBytes {
		return Report{}, fmt.Errorf("cloud inventory exceeds max_bytes: %d", maxBytes)
	}
	body, err := os.ReadFile(src.Path)
	if err != nil {
		return Report{}, err
	}
	var d Document
	if err := json.Unmarshal(body, &d); err != nil {
		return Report{}, fmt.Errorf("decode cloud inventory: %w", err)
	}
	d.Provider = strings.ToLower(strings.TrimSpace(d.Provider))
	d.ScopeID = strings.TrimSpace(d.ScopeID)
	switch d.Provider {
	case "aws", "azure", "gcp", "kubernetes":
	default:
		return Report{}, errors.New("provider must be aws, azure, gcp, or kubernetes")
	}
	if d.ScopeID == "" || len(d.Resources) == 0 {
		return Report{}, errors.New("scope_id and resources are required")
	}
	if len(d.Resources) > 100000 || len(d.Relationships) > 500000 {
		return Report{}, errors.New("inventory exceeds bounded limits")
	}
	nodes := make([]attackgraph.Node, 0, len(d.Resources))
	seen := map[string]bool{}
	for i := range d.Resources {
		r := &d.Resources[i]
		r.ID = strings.TrimSpace(r.ID)
		r.Type = strings.TrimSpace(r.Type)
		r.Name = strings.TrimSpace(r.Name)
		r.Region = strings.TrimSpace(r.Region)
		if r.ID == "" || r.Type == "" {
			return Report{}, fmt.Errorf("resource %d id/type required", i)
		}
		if seen[r.ID] {
			return Report{}, fmt.Errorf("duplicate resource id %q", r.ID)
		}
		seen[r.ID] = true
		kind := "resource"
		lt := strings.ToLower(r.Type)
		if d.Provider == "kubernetes" {
			switch {
			case strings.Contains(lt, "namespace"):
				kind = "namespace"
			case strings.Contains(lt, "pod") || strings.Contains(lt, "deployment") || strings.Contains(lt, "statefulset") || strings.Contains(lt, "daemonset"):
				kind = "workload"
			case strings.Contains(lt, "image"):
				kind = "container-image"
			case strings.Contains(lt, "service"):
				kind = "service"
			}
		} else if strings.Contains(lt, "role") || strings.Contains(lt, "principal") || strings.Contains(lt, "identity") {
			kind = "cloud-principal"
		}
		props := map[string]string{"provider": d.Provider, "resource_type": r.Type}
		if r.Region != "" {
			props["region"] = r.Region
		}
		if r.Public {
			props["public"] = "true"
		}
		for k, v := range r.Properties {
			props[k] = v
		}
		nodes = append(nodes, attackgraph.Node{ID: r.ID, Kind: kind, Name: r.Name, Properties: props})
	}
	edges := make([]attackgraph.Edge, 0, len(d.Relationships))
	for i, e := range d.Relationships {
		e.From = strings.TrimSpace(e.From)
		e.To = strings.TrimSpace(e.To)
		e.Kind = strings.ToLower(strings.TrimSpace(e.Kind))
		if !seen[e.From] || !seen[e.To] {
			return Report{}, fmt.Errorf("relationship %d has missing endpoint", i)
		}
		edges = append(edges, attackgraph.Edge{From: e.From, To: e.To, Kind: e.Kind})
	}
	g, err := attackgraph.Build(attackgraph.Input{SourceKind: d.Provider + "-inventory", Nodes: nodes, Edges: edges})
	if err != nil {
		return Report{}, err
	}
	sort.Slice(d.Resources, func(i, j int) bool { return d.Resources[i].ID < d.Resources[j].ID })
	after, err := targetidentity.InspectBounded(src.Path, maxBytes)
	if err != nil {
		return Report{}, err
	}
	if after.ID != src.ID || after.Size != src.Size || after.ModifiedUTC != src.ModifiedUTC {
		return Report{}, errors.New("inventory changed during import")
	}
	return Report{Source: src, Provider: d.Provider, ScopeID: d.ScopeID, Resources: d.Resources, Graph: g, ReadOnly: true}, nil
}
