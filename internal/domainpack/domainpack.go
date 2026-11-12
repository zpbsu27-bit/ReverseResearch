package domainpack

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"reverseresearch/internal/playbook"
	"reverseresearch/internal/router"
)

type SkillContract struct {
	Path        string `json:"path"`
	Role        string `json:"role"`
	OwnsRouting bool   `json:"owns_routing"`
}

type Pack struct {
	ID             string        `json:"id"`
	Domain         string        `json:"domain"`
	Routes         []string      `json:"routes"`
	Skill          SkillContract `json:"skill"`
	Playbooks      []string      `json:"playbooks"`
	Tools          []string      `json:"tools,omitempty"`
	Capabilities   []string      `json:"capabilities"`
	KnowledgePacks []string      `json:"knowledge_packs,omitempty"`
	Schemas        []string      `json:"schemas,omitempty"`
	Fixtures       []string      `json:"fixtures,omitempty"`
	Tests          []string      `json:"tests,omitempty"`
	Source         string        `json:"source"`
	License        string        `json:"license"`
	TrustStatus    string        `json:"trust_status"`
	ReviewedAt     string        `json:"reviewed_at,omitempty"`
}

type Config struct {
	Version int    `json:"version"`
	Packs   []Pack `json:"packs"`
}

type Registry struct {
	packs   map[string]Pack
	byRoute map[string]string
	order   []string
}

func Load(root, path string) (*Registry, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read domain packs: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(body, &cfg); err != nil {
		return nil, fmt.Errorf("decode domain packs: %w", err)
	}
	if cfg.Version <= 0 || len(cfg.Packs) == 0 {
		return nil, errors.New("domain pack version and packs are required")
	}
	routes, err := router.Load(filepath.Join(root, "config", "routes.json"))
	if err != nil {
		return nil, err
	}
	playbooks, err := playbook.Load(root, filepath.Join(root, "config", "playbooks.json"))
	if err != nil {
		return nil, err
	}
	routeByID := map[string]router.Route{}
	for _, route := range routes.Routes() {
		routeByID[route.ID] = route
	}
	registry := &Registry{packs: map[string]Pack{}, byRoute: map[string]string{}, order: []string{}}
	for _, pack := range cfg.Packs {
		pack.ID = strings.TrimSpace(pack.ID)
		pack.Domain = strings.TrimSpace(pack.Domain)
		pack.Skill.Path = filepath.ToSlash(filepath.Clean(filepath.FromSlash(strings.TrimSpace(pack.Skill.Path))))
		pack.Skill.Role = strings.TrimSpace(pack.Skill.Role)
		pack.Source = strings.TrimSpace(pack.Source)
		pack.License = strings.TrimSpace(pack.License)
		pack.TrustStatus = strings.ToLower(strings.TrimSpace(pack.TrustStatus))
		pack.ReviewedAt = strings.TrimSpace(pack.ReviewedAt)
		if pack.ID == "" || pack.Domain == "" || len(pack.Routes) == 0 || len(pack.Playbooks) == 0 || len(pack.Capabilities) == 0 || pack.Source == "" || pack.License == "" || pack.TrustStatus == "" {
			return nil, errors.New("domain pack id, domain, routes, playbooks, capabilities, source, license, and trust_status are required")
		}
		switch pack.TrustStatus {
		case "reviewed", "builtin", "external-reviewed":
		default:
			return nil, fmt.Errorf("domain pack %s has unsupported trust_status %q", pack.ID, pack.TrustStatus)
		}
		if _, exists := registry.packs[pack.ID]; exists {
			return nil, fmt.Errorf("duplicate domain pack id %q", pack.ID)
		}
		if pack.Skill.Role != "specialist" || pack.Skill.OwnsRouting {
			return nil, fmt.Errorf("domain pack %s skill must be specialist with owns_routing=false", pack.ID)
		}
		if err := validateSkill(root, pack.Skill.Path); err != nil {
			return nil, fmt.Errorf("domain pack %s skill: %w", pack.ID, err)
		}
		for _, routeID := range clean(pack.Routes) {
			route, ok := routeByID[routeID]
			if !ok {
				return nil, fmt.Errorf("domain pack %s references unknown route %q", pack.ID, routeID)
			}
			if route.Domain != pack.Domain {
				return nil, fmt.Errorf("domain pack %s domain %q does not match route %s domain %q", pack.ID, pack.Domain, routeID, route.Domain)
			}
			if owner, exists := registry.byRoute[routeID]; exists {
				return nil, fmt.Errorf("route %q belongs to both domain packs %s and %s", routeID, owner, pack.ID)
			}
			registry.byRoute[routeID] = pack.ID
		}
		for _, playbookID := range clean(pack.Playbooks) {
			if _, err := playbooks.Get(playbookID); err != nil {
				return nil, fmt.Errorf("domain pack %s playbook: %w", pack.ID, err)
			}
		}
		for _, relative := range pack.Schemas {
			if err := validateProjectFile(root, relative); err != nil {
				return nil, fmt.Errorf("domain pack %s schema %q: %w", pack.ID, relative, err)
			}
		}
		for _, relative := range append(append([]string{}, pack.Fixtures...), pack.Tests...) {
			if err := validateRelativePath(relative); err != nil {
				return nil, fmt.Errorf("domain pack %s development path %q: %w", pack.ID, relative, err)
			}
		}
		pack.Routes = clean(pack.Routes)
		pack.Playbooks = clean(pack.Playbooks)
		pack.Tools = clean(pack.Tools)
		pack.Capabilities = clean(pack.Capabilities)
		pack.KnowledgePacks = clean(pack.KnowledgePacks)
		registry.packs[pack.ID] = pack
		registry.order = append(registry.order, pack.ID)
	}
	return registry, nil
}

func (r *Registry) Get(id string) (Pack, error) {
	value, ok := r.packs[strings.TrimSpace(id)]
	if !ok {
		return Pack{}, fmt.Errorf("unknown domain pack %q", id)
	}
	return value, nil
}

func (r *Registry) ForRoute(routeID string) (Pack, bool) {
	id, ok := r.byRoute[strings.TrimSpace(routeID)]
	if !ok {
		return Pack{}, false
	}
	return r.packs[id], true
}

func (r *Registry) List() []Pack {
	result := make([]Pack, 0, len(r.order))
	for _, id := range r.order {
		result = append(result, r.packs[id])
	}
	return result
}

func validateSkill(root, relative string) error {
	if err := validateProjectFile(root, relative); err != nil {
		return err
	}
	body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
	if err != nil {
		return err
	}
	text := strings.ReplaceAll(string(body), "\r\n", "\n")
	if !strings.HasPrefix(text, "---\n") || !strings.Contains(text, "\nname: ") || !strings.Contains(text, "\ndescription: ") {
		return errors.New("SKILL.md requires YAML frontmatter with name and description")
	}
	return nil
}

func validateProjectFile(root, relative string) error {
	if err := validateRelativePath(relative); err != nil {
		return err
	}
	relative = strings.TrimSpace(relative)
	native := filepath.FromSlash(relative)
	full, err := filepath.Abs(filepath.Join(root, native))
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(root, full)
	if err != nil {
		return err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New("path escapes project root")
	}
	info, err := os.Stat(full)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return errors.New("path must reference a file")
	}
	return nil
}

func clean(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}

func validateRelativePath(relative string) error {
	relative = strings.TrimSpace(relative)
	if relative == "" {
		return errors.New("path is empty")
	}
	native := filepath.FromSlash(relative)
	if filepath.IsAbs(native) {
		return errors.New("path must be relative")
	}
	cleaned := filepath.Clean(native)
	if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return errors.New("path escapes project root")
	}
	return nil
}
