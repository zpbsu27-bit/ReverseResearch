package knowledgepack

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"reverseresearch/internal/knowledge"
)

type Standard struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Version         string `json:"version,omitempty"`
	CanonicalSource string `json:"canonical_source"`
	Purpose         string `json:"purpose"`
}

type Pack struct {
	ID          string     `json:"id"`
	Title       string     `json:"title"`
	Domains     []string   `json:"domains"`
	Routes      []string   `json:"routes,omitempty"`
	Standards   []Standard `json:"standards"`
	NoteIDs     []string   `json:"note_ids"`
	Source      string     `json:"source"`
	License     string     `json:"license"`
	TrustStatus string     `json:"trust_status"`
	ReviewedAt  string     `json:"reviewed_at"`
}

type manifest struct {
	Version int    `json:"version"`
	Packs   []Pack `json:"packs"`
}

type Registry struct {
	version int
	packs   map[string]Pack
	ordered []Pack
}

func Load(path string, store *knowledge.Store) (*Registry, error) {
	if store == nil {
		return nil, errors.New("knowledge store is required")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read knowledge pack manifest: %w", err)
	}
	var input manifest
	if err := json.Unmarshal(body, &input); err != nil {
		return nil, fmt.Errorf("decode knowledge pack manifest: %w", err)
	}
	if input.Version <= 0 {
		return nil, errors.New("knowledge pack manifest version must be positive")
	}
	registry := &Registry{version: input.Version, packs: map[string]Pack{}}
	for index, pack := range input.Packs {
		pack.ID = strings.ToLower(strings.TrimSpace(pack.ID))
		pack.Title = strings.TrimSpace(pack.Title)
		pack.Source = strings.TrimSpace(pack.Source)
		pack.License = strings.TrimSpace(pack.License)
		pack.TrustStatus = strings.ToLower(strings.TrimSpace(pack.TrustStatus))
		pack.ReviewedAt = strings.TrimSpace(pack.ReviewedAt)
		pack.Domains = clean(pack.Domains)
		pack.Routes = clean(pack.Routes)
		pack.NoteIDs = clean(pack.NoteIDs)
		if pack.ID == "" || pack.Title == "" || len(pack.Domains) == 0 || len(pack.Standards) == 0 || len(pack.NoteIDs) == 0 ||
			pack.Source == "" || pack.License == "" || pack.TrustStatus == "" || pack.ReviewedAt == "" {
			return nil, fmt.Errorf("knowledge pack %d is incomplete", index)
		}
		switch pack.TrustStatus {
		case "builtin", "reviewed", "external-reviewed":
		default:
			return nil, fmt.Errorf("knowledge pack %s has unsupported trust_status %q", pack.ID, pack.TrustStatus)
		}
		if _, exists := registry.packs[pack.ID]; exists {
			return nil, fmt.Errorf("duplicate knowledge pack %q", pack.ID)
		}
		standardIDs := map[string]bool{}
		for standardIndex := range pack.Standards {
			standard := &pack.Standards[standardIndex]
			standard.ID = strings.ToLower(strings.TrimSpace(standard.ID))
			standard.Name = strings.TrimSpace(standard.Name)
			standard.Version = strings.TrimSpace(standard.Version)
			standard.CanonicalSource = strings.TrimSpace(standard.CanonicalSource)
			standard.Purpose = strings.TrimSpace(standard.Purpose)
			if standard.ID == "" || standard.Name == "" || standard.CanonicalSource == "" || standard.Purpose == "" {
				return nil, fmt.Errorf("knowledge pack %s standard %d is incomplete", pack.ID, standardIndex)
			}
			if standardIDs[standard.ID] {
				return nil, fmt.Errorf("knowledge pack %s has duplicate standard %q", pack.ID, standard.ID)
			}
			standardIDs[standard.ID] = true
		}
		for _, noteID := range pack.NoteIDs {
			note, err := store.Get(noteID)
			if err != nil {
				return nil, fmt.Errorf("knowledge pack %s note %s: %w", pack.ID, noteID, err)
			}
			if note.Origin != knowledge.OriginBuiltin || note.Source == nil || !strings.EqualFold(note.Source.EvidenceStatus, "reviewed") {
				return nil, fmt.Errorf("knowledge pack %s note %s is not reviewed builtin knowledge", pack.ID, noteID)
			}
		}
		registry.packs[pack.ID] = pack
		registry.ordered = append(registry.ordered, pack)
	}
	sort.Slice(registry.ordered, func(i, j int) bool { return registry.ordered[i].ID < registry.ordered[j].ID })
	return registry, nil
}

func (r *Registry) Get(id string) (Pack, error) {
	id = strings.ToLower(strings.TrimSpace(id))
	value, ok := r.packs[id]
	if !ok {
		return Pack{}, fmt.Errorf("knowledge pack %q not found", id)
	}
	return value, nil
}

func (r *Registry) List() []Pack {
	return append([]Pack(nil), r.ordered...)
}

func (r *Registry) ForRoute(route string) []Pack {
	route = strings.ToLower(strings.TrimSpace(route))
	result := make([]Pack, 0)
	for _, pack := range r.ordered {
		for _, candidate := range pack.Routes {
			if candidate == route {
				result = append(result, pack)
				break
			}
		}
	}
	return result
}

func clean(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}
