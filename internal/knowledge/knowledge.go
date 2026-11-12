package knowledge

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type AddRequest struct {
	OperationID   string   `json:"operation_id,omitempty"`
	Title         string   `json:"title"`
	Body          string   `json:"body"`
	Route         string   `json:"route,omitempty"`
	Tags          []string `json:"tags,omitempty"`
	Domain        string   `json:"domain,omitempty"`
	Architectures []string `json:"architectures,omitempty"`
	Tools         []string `json:"tools,omitempty"`
	Source        *Source  `json:"source,omitempty"`
}

type Note struct {
	ID            string   `json:"id"`
	Title         string   `json:"title"`
	Body          string   `json:"body"`
	Route         string   `json:"route,omitempty"`
	Tags          []string `json:"tags,omitempty"`
	Origin        string   `json:"origin,omitempty"`
	Domain        string   `json:"domain,omitempty"`
	Architectures []string `json:"architectures,omitempty"`
	Tools         []string `json:"tools,omitempty"`
	CreatedUTC    string   `json:"created_utc"`
	Source        *Source  `json:"source,omitempty"`
	Revision      string   `json:"revision,omitempty"`
	OperationID   string   `json:"operation_id,omitempty"`
	RequestSHA256 string   `json:"request_sha256,omitempty"`
}

type SearchResult struct {
	Note
	Score int `json:"score"`
}

type Store struct {
	root string
}

func New(root string) (*Store, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("knowledge store root is required")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve knowledge root: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(absolute, "notes"), 0o700); err != nil {
		return nil, fmt.Errorf("create knowledge store: %w", err)
	}
	return &Store{root: absolute}, nil
}

func (s *Store) Add(request AddRequest) (Note, error) {
	title := strings.TrimSpace(request.Title)
	body := strings.TrimSpace(request.Body)
	if title == "" || body == "" {
		return Note{}, errors.New("knowledge title and body are required")
	}
	if len(body) > 1<<20 {
		return Note{}, errors.New("knowledge body exceeds 1 MiB")
	}
	domain, architectures, tools, err := normalizeScope(request.Domain, request.Architectures, request.Tools)
	if err != nil {
		return Note{}, err
	}
	note := Note{
		Title:         title,
		Body:          body,
		Route:         strings.ToLower(strings.TrimSpace(request.Route)),
		Tags:          normalizeTags(request.Tags),
		Origin:        OriginJournal,
		Domain:        domain,
		Architectures: architectures,
		Tools:         tools,
		CreatedUTC:    time.Now().UTC().Format(time.RFC3339Nano),
	}
	note.Source, err = normalizeSource(request.Source, note.CreatedUTC)
	if err != nil {
		return Note{}, err
	}
	if request.OperationID != "" {
		if !noteOperationPattern.MatchString(request.OperationID) {
			return Note{}, errors.New("knowledge operation_id must be 1..128 ASCII letters, digits, dot, underscore or hyphen")
		}
		intent := AddRequest{
			Title: note.Title, Body: note.Body, Route: note.Route, Tags: note.Tags,
			Domain: note.Domain, Architectures: note.Architectures, Tools: note.Tools,
		}
		if request.Source != nil {
			intent.Source = note.Source
		}
		body, err := json.Marshal(intent)
		if err != nil {
			return Note{}, err
		}
		note.ID = "note_" + contentRevision([]byte("journal:add:"+request.OperationID))
		note.OperationID = request.OperationID
		note.RequestSHA256 = contentRevision(body)
	} else {
		note.ID, err = newNoteID()
		if err != nil {
			return Note{}, err
		}
	}
	payload, err := json.MarshalIndent(note, "", "  ")
	if err != nil {
		return Note{}, err
	}
	payload = append(payload, '\n')
	if len(payload) > maxNoteRecordBytes {
		return Note{}, errors.New("encoded knowledge record exceeds 4 MiB")
	}
	if err := writeNote(filepath.Join(s.root, "notes", note.ID+".json"), payload); err != nil {
		if request.OperationID != "" && errors.Is(err, ErrNoteExists) {
			existing, readErr := s.Get(note.ID)
			if readErr != nil {
				return Note{}, readErr
			}
			if existing.OperationID != note.OperationID || existing.RequestSHA256 != note.RequestSHA256 {
				return Note{}, ErrOperationConflict
			}
			// The binding cannot make externally changed note content satisfy a
			// historical request merely because its digest field was left intact.
			existingIntent := AddRequest{Title: existing.Title, Body: existing.Body,
				Route: existing.Route, Tags: existing.Tags, Domain: existing.Domain,
				Architectures: existing.Architectures, Tools: existing.Tools}
			if request.Source != nil {
				existingIntent.Source = existing.Source
			} else {
				defaultSource, sourceErr := normalizeSource(nil, existing.CreatedUTC)
				if sourceErr != nil || *defaultSource != *existing.Source {
					return Note{}, ErrOperationConflict
				}
			}
			currentIntent, marshalErr := json.Marshal(existingIntent)
			if marshalErr != nil {
				return Note{}, marshalErr
			}
			if contentRevision(currentIntent) != existing.RequestSHA256 {
				return Note{}, ErrOperationConflict
			}
			return existing, nil
		}
		return Note{}, err
	}
	note.Revision = contentRevision(payload)
	return note, nil
}

func (s *Store) Search(query string, limit int) ([]SearchResult, error) {
	// Preserve the pre-builtin API contract: legacy Search only searches the
	// mutable journal. Call SearchFiltered to opt into builtin knowledge.
	return s.SearchFiltered(SearchRequest{Query: query, Limit: limit, Origin: OriginJournal})
}

func normalizeTags(tags []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(tags))
	for _, tag := range tags {
		tag = strings.ToLower(strings.TrimSpace(tag))
		if tag == "" {
			continue
		}
		if _, ok := seen[tag]; ok {
			continue
		}
		seen[tag] = struct{}{}
		result = append(result, tag)
	}
	sort.Strings(result)
	return result
}

func uniqueTerms(query string) []string {
	seen := map[string]struct{}{}
	var terms []string
	for _, term := range strings.Fields(strings.ToLower(strings.TrimSpace(query))) {
		if _, ok := seen[term]; ok {
			continue
		}
		seen[term] = struct{}{}
		terms = append(terms, term)
	}
	return terms
}

func newNoteID() (string, error) {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "note_" + hex.EncodeToString(raw[:]), nil
}
