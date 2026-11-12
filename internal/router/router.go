package router

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
)

type Route struct {
	ID          string   `json:"id"`
	Priority    int      `json:"priority"`
	Description string   `json:"description"`
	Keywords    []string `json:"keywords"`
	Tools       []string `json:"tools,omitempty"`
	BuiltIn     bool     `json:"built_in,omitempty"`
	Domain      string   `json:"domain,omitempty"`
	Intents     []string `json:"intents,omitempty"`
	Platforms   []string `json:"platforms,omitempty"`
	Artifacts   []string `json:"artifacts,omitempty"`
	EffectClass string   `json:"effect_class,omitempty"`
}

type Config struct {
	Version  int     `json:"version"`
	Fallback string  `json:"fallback"`
	Routes   []Route `json:"routes"`
}

type Candidate struct {
	ID              string   `json:"id"`
	Score           int      `json:"score"`
	MatchedKeywords []string `json:"matched_keywords"`
}

type Result struct {
	Route           Route          `json:"route"`
	Score           int            `json:"score"`
	MatchedKeywords []string       `json:"matched_keywords"`
	Candidates      []Candidate    `json:"candidates,omitempty"`
	Classification  Classification `json:"classification"`
}

type Classification struct {
	Domain      string   `json:"domain,omitempty"`
	Intents     []string `json:"intents,omitempty"`
	Platforms   []string `json:"platforms,omitempty"`
	Artifacts   []string `json:"artifacts,omitempty"`
	EffectClass string   `json:"effect_class,omitempty"`
}

type Engine struct {
	config Config
	byID   map[string]Route
}

func Load(path string) (*Engine, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read routes: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(body, &cfg); err != nil {
		return nil, fmt.Errorf("decode routes: %w", err)
	}
	if cfg.Version <= 0 {
		return nil, errors.New("routes version must be positive")
	}
	if len(cfg.Routes) == 0 {
		return nil, errors.New("routes must not be empty")
	}
	engine := &Engine{config: cfg, byID: make(map[string]Route, len(cfg.Routes))}
	for _, route := range cfg.Routes {
		route.ID = strings.TrimSpace(route.ID)
		if route.ID == "" {
			return nil, errors.New("route id must not be empty")
		}
		if _, exists := engine.byID[route.ID]; exists {
			return nil, fmt.Errorf("duplicate route id %q", route.ID)
		}
		if len(route.Keywords) == 0 && route.ID != cfg.Fallback {
			return nil, fmt.Errorf("route %s has no keywords", route.ID)
		}
		if cfg.Version >= 4 {
			if strings.TrimSpace(route.Domain) == "" {
				return nil, fmt.Errorf("route %s has no domain in v4 config", route.ID)
			}
			if len(route.Intents) == 0 {
				return nil, fmt.Errorf("route %s has no intents in v4 config", route.ID)
			}
			if strings.TrimSpace(route.EffectClass) == "" {
				return nil, fmt.Errorf("route %s has no effect_class in v4 config", route.ID)
			}
		}
		engine.byID[route.ID] = route
	}
	if _, ok := engine.byID[cfg.Fallback]; !ok {
		return nil, fmt.Errorf("fallback route %q not found", cfg.Fallback)
	}
	return engine, nil
}

func (e *Engine) Routes() []Route {
	result := make([]Route, len(e.config.Routes))
	copy(result, e.config.Routes)
	return result
}

func (e *Engine) Route(text string) Result {
	normalized := strings.ToLower(strings.TrimSpace(text))
	candidates := make([]Candidate, 0, len(e.config.Routes))
	for _, route := range e.config.Routes {
		var matched []string
		score := 0
		seenKeywords := map[string]bool{}
		for _, keyword := range route.Keywords {
			k := strings.ToLower(strings.TrimSpace(keyword))
			if k == "" || seenKeywords[k] {
				continue
			}
			seenKeywords[k] = true
			if !keywordMatches(normalized, k) {
				continue
			}
			matched = append(matched, keyword)
			score += 100 + len([]rune(k))
		}
		if score > 0 {
			candidates = append(candidates, Candidate{
				ID:              route.ID,
				Score:           score,
				MatchedKeywords: matched,
			})
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].Score != candidates[j].Score {
			return candidates[i].Score > candidates[j].Score
		}
		left := e.byID[candidates[i].ID]
		right := e.byID[candidates[j].ID]
		if left.Priority != right.Priority {
			return left.Priority > right.Priority
		}
		return left.ID < right.ID
	})
	if len(candidates) == 0 {
		fallback := e.byID[e.config.Fallback]
		return Result{Route: fallback, Classification: classificationFor(fallback)}
	}
	best := candidates[0]
	return Result{
		Route:           e.byID[best.ID],
		Score:           best.Score,
		MatchedKeywords: append([]string(nil), best.MatchedKeywords...),
		Candidates:      candidates,
		Classification:  classificationFor(e.byID[best.ID]),
	}
}

func classificationFor(route Route) Classification {
	return Classification{Domain: route.Domain, Intents: append([]string(nil), route.Intents...), Platforms: append([]string(nil), route.Platforms...), Artifacts: append([]string(nil), route.Artifacts...), EffectClass: route.EffectClass}
}
