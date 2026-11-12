package capability

import (
	"fmt"
	"sort"

	"reverseresearch/internal/provision"
	"reverseresearch/internal/router"
	"reverseresearch/internal/toolindex"
)

type ToolStatus struct {
	Name   string            `json:"name"`
	Status provision.Status  `json:"status"`
	Path   string            `json:"path,omitempty"`
	Source string            `json:"source,omitempty"`
	Recipe *provision.Recipe `json:"recipe,omitempty"`
}

type Status struct {
	RouteID         string       `json:"route_id"`
	Description     string       `json:"description,omitempty"`
	Tools           []ToolStatus `json:"tools,omitempty"`
	Available       int          `json:"available"`
	Installable     int          `json:"installable"`
	NoRecipe        int          `json:"no_recipe"`
	CoveragePercent int          `json:"coverage_percent"`
	Runnable        bool         `json:"runnable"`
	FullReady       bool         `json:"full_ready"`
}

type Evaluator struct {
	routes   map[string]router.Route
	order    []string
	index    toolindex.Index
	manifest provision.Manifest
}

func New(routes []router.Route, index toolindex.Index, manifest provision.Manifest) *Evaluator {
	byID := make(map[string]router.Route, len(routes))
	order := make([]string, 0, len(routes))
	for _, route := range routes {
		byID[route.ID] = route
		order = append(order, route.ID)
	}
	sort.Strings(order)
	return &Evaluator{
		routes:   byID,
		order:    order,
		index:    index,
		manifest: manifest,
	}
}

func (e *Evaluator) Route(routeID string) (Status, error) {
	route, ok := e.routes[routeID]
	if !ok {
		return Status{}, fmt.Errorf("unknown capability route %q", routeID)
	}
	status := Status{
		RouteID:     route.ID,
		Description: route.Description,
	}
	if len(route.Tools) == 0 {
		if route.BuiltIn {
			status.Runnable, status.FullReady, status.CoveragePercent = true, true, 100
		}
		return status, nil
	}

	plan, err := provision.NewPlanner(e.manifest, e.index).Plan(route.Tools)
	if err != nil {
		return Status{}, err
	}
	status.Tools = make([]ToolStatus, 0, len(plan.Items))
	for _, item := range plan.Items {
		status.Tools = append(status.Tools, ToolStatus{
			Name:   item.Tool,
			Status: item.Status,
			Path:   item.Path,
			Source: item.Source,
			Recipe: item.Recipe,
		})
		switch item.Status {
		case provision.StatusAvailable:
			status.Available++
		case provision.StatusInstallable:
			status.Installable++
		case provision.StatusNoRecipe:
			status.NoRecipe++
		}
	}
	status.CoveragePercent = status.Available * 100 / len(route.Tools)
	status.Runnable = status.Available > 0
	status.FullReady = status.Available == len(route.Tools)
	return status, nil
}

func (e *Evaluator) All() []Status {
	result := make([]Status, 0, len(e.order))
	for _, routeID := range e.order {
		status, err := e.Route(routeID)
		if err != nil {
			continue
		}
		result = append(result, status)
	}
	return result
}
