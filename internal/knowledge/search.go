package knowledge

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func (s *Store) SearchFiltered(request SearchRequest) ([]SearchResult, error) {
	request, err := normalizeSearchRequest(request)
	if err != nil {
		return nil, err
	}
	terms := uniqueTerms(request.Query)
	results := make([]SearchResult, 0)

	entries, err := os.ReadDir(filepath.Join(s.root, "notes"))
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		note, err := s.Get(strings.TrimSuffix(entry.Name(), ".json"))
		if err != nil {
			return nil, err
		}
		if result, ok := matchKnowledge(note, request, terms); ok {
			results = append(results, result)
		}
	}

	builtins, err := builtinNotes()
	if err != nil {
		return nil, err
	}
	for _, note := range builtins {
		if result, ok := matchKnowledge(note, request, terms); ok {
			results = append(results, result)
		}
	}

	sort.SliceStable(results, func(i, j int) bool {
		if results[i].Score != results[j].Score {
			return results[i].Score > results[j].Score
		}
		left, _ := time.Parse(time.RFC3339Nano, results[i].CreatedUTC)
		right, _ := time.Parse(time.RFC3339Nano, results[j].CreatedUTC)
		if !left.Equal(right) {
			return left.After(right)
		}
		return results[i].ID < results[j].ID
	})
	if len(results) > request.Limit {
		results = results[:request.Limit]
	}
	return results, nil
}

func matchKnowledge(note Note, request SearchRequest, terms []string) (SearchResult, bool) {
	if request.Origin != OriginAll && note.Origin != request.Origin {
		return SearchResult{}, false
	}
	if request.Domain != "" && note.Domain != request.Domain {
		return SearchResult{}, false
	}
	if request.Route != "" && strings.ToLower(note.Route) != request.Route {
		return SearchResult{}, false
	}
	if !containsAny(note.Architectures, request.Architectures) {
		return SearchResult{}, false
	}
	if !containsAny(note.Tools, request.Tools) {
		return SearchResult{}, false
	}

	haystack := strings.ToLower(strings.Join([]string{
		note.Title,
		note.Body,
		note.Route,
		note.Origin,
		note.Domain,
		strings.Join(note.Architectures, " "),
		strings.Join(note.Tools, " "),
		strings.Join(note.Tags, " "),
	}, " "))
	score := 1
	for _, term := range terms {
		if !strings.Contains(haystack, term) {
			continue
		}
		score += 100
		score += strings.Count(haystack, term)
	}
	if len(terms) > 0 && score == 1 {
		return SearchResult{}, false
	}
	return SearchResult{Note: note, Score: score}, true
}
