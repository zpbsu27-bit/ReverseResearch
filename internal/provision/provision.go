package provision

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"reverseresearch/internal/toolindex"
)

type Status string

const (
	StatusAvailable   Status = "available"
	StatusInstallable Status = "installable"
	StatusNoRecipe    Status = "no_recipe"
)

type Recipe struct {
	Tool                   string   `json:"tool"`
	Aliases                []string `json:"aliases,omitempty"`
	Provider               string   `json:"provider"`
	Package                string   `json:"package"`
	Version                string   `json:"version,omitempty"`
	VersionConstraint      string   `json:"version_constraint,omitempty"`
	CanonicalSource        string   `json:"canonical_source,omitempty"`
	Checksum               string   `json:"checksum,omitempty"`
	SignatureVerification  string   `json:"signature_verification,omitempty"`
	License                string   `json:"license,omitempty"`
	Redistribution         string   `json:"redistribution,omitempty"`
	Scope                  string   `json:"scope,omitempty"`
	InstallScope           string   `json:"install_scope,omitempty"`
	ExpectedExecutables    []string `json:"expected_executables,omitempty"`
	PostInstallSmoke       []string `json:"post_install_smoke,omitempty"`
	UpgradePath            string   `json:"upgrade_path,omitempty"`
	UninstallPath          string   `json:"uninstall_path,omitempty"`
	SupportedPlatforms     []string `json:"supported_platforms,omitempty"`
	SupportedArchitectures []string `json:"supported_architectures,omitempty"`
	Commercial             bool     `json:"commercial,omitempty"`
	Redistributable        bool     `json:"redistributable,omitempty"`
	Notes                  string   `json:"notes,omitempty"`
}

type Manifest struct {
	Version int      `json:"version"`
	Recipes []Recipe `json:"recipes"`
	byTool  map[string]Recipe
}

type PlanItem struct {
	Tool   string  `json:"tool"`
	Status Status  `json:"status"`
	Path   string  `json:"path,omitempty"`
	Source string  `json:"source,omitempty"`
	Recipe *Recipe `json:"recipe,omitempty"`
}

type Plan struct {
	Items       []PlanItem `json:"items"`
	Installable int        `json:"installable"`
	Available   int        `json:"available"`
	NoRecipe    int        `json:"no_recipe"`
}

type Planner struct {
	manifest Manifest
	index    toolindex.Index
}

func LoadManifest(path string) (Manifest, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("read tool recipes: %w", err)
	}
	var manifest Manifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode tool recipes: %w", err)
	}
	if manifest.Version <= 0 {
		return Manifest{}, errors.New("tool recipe manifest version must be positive")
	}
	manifest.byTool = make(map[string]Recipe, len(manifest.Recipes))
	for index, recipe := range manifest.Recipes {
		recipe.Tool = strings.ToLower(strings.TrimSpace(recipe.Tool))
		recipe.Provider = strings.ToLower(strings.TrimSpace(recipe.Provider))
		recipe.Package = strings.TrimSpace(recipe.Package)
		recipe.Version = strings.TrimSpace(recipe.Version)
		recipe.VersionConstraint = strings.TrimSpace(recipe.VersionConstraint)
		recipe.CanonicalSource = strings.TrimSpace(recipe.CanonicalSource)
		recipe.Checksum = strings.TrimSpace(recipe.Checksum)
		recipe.SignatureVerification = strings.TrimSpace(recipe.SignatureVerification)
		recipe.License = strings.TrimSpace(recipe.License)
		recipe.Redistribution = strings.TrimSpace(recipe.Redistribution)
		recipe.Scope = strings.TrimSpace(recipe.Scope)
		recipe.InstallScope = strings.TrimSpace(recipe.InstallScope)
		if recipe.InstallScope == "" {
			recipe.InstallScope = recipe.Scope
		}
		if recipe.Scope == "" {
			recipe.Scope = recipe.InstallScope
		}
		recipe.Aliases = normalizeRecipeList(recipe.Aliases)
		recipe.ExpectedExecutables = normalizeRecipeList(recipe.ExpectedExecutables)
		recipe.PostInstallSmoke = normalizeRecipeList(recipe.PostInstallSmoke)
		recipe.SupportedPlatforms = normalizeRecipeList(recipe.SupportedPlatforms)
		recipe.SupportedArchitectures = normalizeRecipeList(recipe.SupportedArchitectures)
		if recipe.Tool == "" || recipe.Provider == "" || recipe.Package == "" {
			return Manifest{}, fmt.Errorf("recipe %d requires tool, provider, and package", index)
		}
		if manifest.Version >= 2 {
			if recipe.CanonicalSource == "" || recipe.License == "" || recipe.Redistribution == "" || recipe.InstallScope == "" ||
				len(recipe.ExpectedExecutables) == 0 || len(recipe.PostInstallSmoke) == 0 ||
				len(recipe.SupportedPlatforms) == 0 || len(recipe.SupportedArchitectures) == 0 {
				return Manifest{}, fmt.Errorf("recipe %s is incomplete for Tool Recipe v2", recipe.Tool)
			}
			if recipe.Commercial && recipe.Redistributable {
				return Manifest{}, fmt.Errorf("commercial recipe %s cannot be marked redistributable", recipe.Tool)
			}
		}
		if !validProvider(recipe.Provider) {
			return Manifest{}, fmt.Errorf("recipe %s has unsupported provider %q", recipe.Tool, recipe.Provider)
		}
		if _, exists := manifest.byTool[recipe.Tool]; exists {
			return Manifest{}, fmt.Errorf("duplicate tool recipe %q", recipe.Tool)
		}
		manifest.Recipes[index] = recipe
		manifest.byTool[recipe.Tool] = recipe
	}
	sort.Slice(manifest.Recipes, func(i, j int) bool {
		return manifest.Recipes[i].Tool < manifest.Recipes[j].Tool
	})
	return manifest, nil
}

func NewPlanner(manifest Manifest, index toolindex.Index) *Planner {
	if manifest.byTool == nil {
		manifest.byTool = make(map[string]Recipe, len(manifest.Recipes))
		for _, recipe := range manifest.Recipes {
			manifest.byTool[strings.ToLower(recipe.Tool)] = recipe
		}
	}
	return &Planner{manifest: manifest, index: index}
}

func (p *Planner) Plan(names []string) (Plan, error) {
	if len(names) == 0 {
		return Plan{}, errors.New("at least one tool is required")
	}
	result := Plan{Items: make([]PlanItem, 0, len(names))}
	for _, rawName := range names {
		name := strings.ToLower(strings.TrimSpace(rawName))
		if name == "" {
			return Plan{}, errors.New("tool name must not be empty")
		}
		if tool, ok := p.index.ByName(name); ok && tool.Available {
			result.Items = append(result.Items, PlanItem{
				Tool: name, Status: StatusAvailable, Path: tool.Path, Source: tool.Source,
			})
			result.Available++
			continue
		}
		recipe, ok := p.manifest.byTool[name]
		if !ok {
			result.Items = append(result.Items, PlanItem{Tool: name, Status: StatusNoRecipe})
			result.NoRecipe++
			continue
		}
		recipeCopy := recipe
		result.Items = append(result.Items, PlanItem{
			Tool: name, Status: StatusInstallable, Recipe: &recipeCopy,
		})
		result.Installable++
	}
	return result, nil
}

func validProvider(provider string) bool {
	switch provider {
	case "manual", "pip", "pipx", "winget", "choco", "url", "project", "installed-only":
		return true
	default:
		return false
	}
}

func normalizeRecipeList(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}
