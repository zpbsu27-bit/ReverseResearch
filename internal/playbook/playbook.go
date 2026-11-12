package playbook

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"reverseresearch/internal/router"
)

type Gate struct {
	ID            string `json:"id"`
	Title         string `json:"title"`
	PassCriterion string `json:"pass_criterion"`
}

type Playbook struct {
	ID               string   `json:"id"`
	Platform         string   `json:"platform"`
	Routes           []string `json:"routes"`
	SkillPath        string   `json:"skill_path"`
	ReferencePath    string   `json:"reference_path"`
	Summary          string   `json:"summary"`
	Gates            []Gate   `json:"gates"`
	SymptomReference string   `json:"symptom_reference,omitempty"`
	Done             []string `json:"done"`
}

type Config struct {
	Version   int        `json:"version"`
	Playbooks []Playbook `json:"playbooks"`
}

type Registry struct {
	root    string
	byID    map[string]Playbook
	byRoute map[string]Playbook
	order   []string
}

func Load(root, path string) (*Registry, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("playbook root is required")
	}
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve playbook root: %w", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read playbooks: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(body, &cfg); err != nil {
		return nil, fmt.Errorf("decode playbooks: %w", err)
	}
	if cfg.Version <= 0 {
		return nil, errors.New("playbooks version must be positive")
	}
	if len(cfg.Playbooks) == 0 {
		return nil, errors.New("playbooks must not be empty")
	}
	routeEngine, err := router.Load(filepath.Join(absoluteRoot, "config", "routes.json"))
	if err != nil {
		return nil, fmt.Errorf("load canonical routes: %w", err)
	}
	validRoutes := make(map[string]bool, len(routeEngine.Routes()))
	for _, route := range routeEngine.Routes() {
		validRoutes[route.ID] = true
	}

	registry := &Registry{
		root: absoluteRoot, byID: make(map[string]Playbook, len(cfg.Playbooks)),
		byRoute: map[string]Playbook{}, order: make([]string, 0, len(cfg.Playbooks)),
	}
	for _, value := range cfg.Playbooks {
		value.ID = strings.TrimSpace(value.ID)
		value.Platform = strings.TrimSpace(value.Platform)
		value.SkillPath = cleanProtocolPath(value.SkillPath)
		value.ReferencePath = cleanProtocolPath(value.ReferencePath)
		value.Summary = strings.TrimSpace(value.Summary)
		value.SymptomReference = cleanProtocolPath(value.SymptomReference)
		if value.ID == "" || value.Platform == "" || value.SkillPath == "." || value.ReferencePath == "." || value.Summary == "" {
			return nil, errors.New("playbook id, platform, skill_path, reference_path, and summary are required")
		}
		if _, exists := registry.byID[value.ID]; exists {
			return nil, fmt.Errorf("duplicate playbook id %q", value.ID)
		}
		if len(value.Routes) == 0 || len(value.Gates) == 0 || len(value.Done) == 0 {
			return nil, fmt.Errorf("playbook %s requires routes, gates, and done criteria", value.ID)
		}
		if err := validateRelativeFile(absoluteRoot, value.SkillPath); err != nil {
			return nil, fmt.Errorf("playbook %s skill_path: %w", value.ID, err)
		}
		if err := validateRelativeFile(absoluteRoot, value.ReferencePath); err != nil {
			return nil, fmt.Errorf("playbook %s reference_path: %w", value.ID, err)
		}
		if value.SymptomReference != "." && value.SymptomReference != "" {
			if err := validateRelativeFile(absoluteRoot, value.SymptomReference); err != nil {
				return nil, fmt.Errorf("playbook %s symptom_reference: %w", value.ID, err)
			}
		}
		gateIDs := map[string]bool{}
		for i := range value.Gates {
			value.Gates[i].ID = strings.TrimSpace(value.Gates[i].ID)
			value.Gates[i].Title = strings.TrimSpace(value.Gates[i].Title)
			value.Gates[i].PassCriterion = strings.TrimSpace(value.Gates[i].PassCriterion)
			if value.Gates[i].ID == "" || value.Gates[i].Title == "" || value.Gates[i].PassCriterion == "" {
				return nil, fmt.Errorf("playbook %s has incomplete gate", value.ID)
			}
			if gateIDs[value.Gates[i].ID] {
				return nil, fmt.Errorf("playbook %s has duplicate gate %q", value.ID, value.Gates[i].ID)
			}
			gateIDs[value.Gates[i].ID] = true
		}
		seenRoutes := map[string]bool{}
		routes := value.Routes[:0]
		for _, routeID := range value.Routes {
			routeID = strings.TrimSpace(routeID)
			if routeID == "" || seenRoutes[routeID] {
				continue
			}
			if !validRoutes[routeID] {
				return nil, fmt.Errorf("playbook %s references unknown canonical route %q", value.ID, routeID)
			}
			if existing, exists := registry.byRoute[routeID]; exists {
				return nil, fmt.Errorf("route %q belongs to both %s and %s", routeID, existing.ID, value.ID)
			}
			seenRoutes[routeID] = true
			routes = append(routes, routeID)
		}
		if len(routes) == 0 {
			return nil, fmt.Errorf("playbook %s has no valid routes", value.ID)
		}
		value.Routes = routes
		for _, done := range value.Done {
			if strings.TrimSpace(done) == "" {
				return nil, fmt.Errorf("playbook %s has empty done criterion", value.ID)
			}
		}
		registry.byID[value.ID] = value
		registry.order = append(registry.order, value.ID)
		for _, routeID := range value.Routes {
			registry.byRoute[routeID] = value
		}
	}
	return registry, nil
}

func (r *Registry) Get(id string) (Playbook, error) {
	value, ok := r.byID[strings.TrimSpace(id)]
	if !ok {
		return Playbook{}, fmt.Errorf("unknown playbook %q", id)
	}
	return value, nil
}

func (r *Registry) ForRoute(routeID string) (Playbook, bool) {
	value, ok := r.byRoute[strings.TrimSpace(routeID)]
	return value, ok
}

func (r *Registry) List() []Playbook {
	result := make([]Playbook, 0, len(r.order))
	for _, id := range r.order {
		result = append(result, r.byID[id])
	}
	return result
}

func cleanProtocolPath(value string) string {
	return filepath.ToSlash(filepath.Clean(filepath.FromSlash(strings.TrimSpace(value))))
}

func validateRelativeFile(root, relative string) error {
	native := filepath.FromSlash(relative)
	if filepath.IsAbs(native) {
		return errors.New("path must be relative to project root")
	}
	full := filepath.Join(root, native)
	resolved, err := filepath.Abs(full)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(root, resolved)
	if err != nil {
		return err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New("path escapes project root")
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return errors.New("path must reference a file")
	}
	return nil
}
