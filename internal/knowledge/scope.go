package knowledge

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const (
	OriginAll     = "all"
	OriginJournal = "journal"
	OriginBuiltin = "builtin"
)

var scopeTokenPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:+-]{0,63}$`)

type SearchRequest struct {
	Query         string   `json:"query,omitempty"`
	Limit         int      `json:"limit,omitempty"`
	Domain        string   `json:"domain,omitempty"`
	Architectures []string `json:"architectures,omitempty"`
	Tools         []string `json:"tools,omitempty"`
	Route         string   `json:"route,omitempty"`
	Origin        string   `json:"origin,omitempty"`
}

func normalizeScope(domain string, architectures, tools []string) (string, []string, []string, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain != "" && !scopeTokenPattern.MatchString(domain) {
		return "", nil, nil, fmt.Errorf("invalid knowledge domain %q", domain)
	}
	architectures, err := normalizeScopeValues("architecture", architectures)
	if err != nil {
		return "", nil, nil, err
	}
	tools, err = normalizeScopeValues("tool", tools)
	if err != nil {
		return "", nil, nil, err
	}
	return domain, architectures, tools, nil
}

func normalizeScopeValues(kind string, values []string) ([]string, error) {
	if len(values) > 32 {
		return nil, fmt.Errorf("knowledge %s filter exceeds 32 values", kind)
	}
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if kind == "architecture" {
			value = normalizeArchitectureAlias(value)
		}
		if value == "" {
			continue
		}
		if !scopeTokenPattern.MatchString(value) {
			return nil, fmt.Errorf("invalid knowledge %s %q", kind, value)
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result, nil
}

func normalizeArchitectureAlias(value string) string {
	switch value {
	case "x64", "amd64", "x86_64":
		return "x86-64"
	case "i386", "i486", "i586", "i686":
		return "x86"
	case "aarch64":
		return "arm64"
	default:
		return value
	}
}

func normalizeOrigin(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return OriginAll, nil
	}
	switch value {
	case OriginAll, OriginJournal, OriginBuiltin:
		return value, nil
	default:
		return "", fmt.Errorf("invalid knowledge origin %q; expected all, journal, or builtin", value)
	}
}

func normalizeSearchRequest(request SearchRequest) (SearchRequest, error) {
	request.Query = strings.TrimSpace(request.Query)
	request.Route = strings.ToLower(strings.TrimSpace(request.Route))
	if request.Route != "" && !scopeTokenPattern.MatchString(request.Route) {
		return SearchRequest{}, fmt.Errorf("invalid knowledge route %q", request.Route)
	}
	var err error
	request.Domain, request.Architectures, request.Tools, err = normalizeScope(
		request.Domain, request.Architectures, request.Tools,
	)
	if err != nil {
		return SearchRequest{}, err
	}
	request.Origin, err = normalizeOrigin(request.Origin)
	if err != nil {
		return SearchRequest{}, err
	}
	if request.Limit <= 0 {
		request.Limit = 20
	}
	if request.Limit > 100 {
		request.Limit = 100
	}
	if request.Limit < 1 {
		return SearchRequest{}, errors.New("knowledge search limit must be positive")
	}
	if request.Query == "" && request.Domain == "" && len(request.Architectures) == 0 &&
		len(request.Tools) == 0 && request.Route == "" && request.Origin == OriginAll {
		return SearchRequest{}, errors.New("knowledge search requires a query or at least one filter")
	}
	return request, nil
}

func containsAny(haystack, needles []string) bool {
	if len(needles) == 0 {
		return true
	}
	set := make(map[string]struct{}, len(haystack))
	for _, value := range haystack {
		set[strings.ToLower(value)] = struct{}{}
	}
	for _, value := range needles {
		if _, ok := set[value]; ok {
			return true
		}
	}
	return false
}
