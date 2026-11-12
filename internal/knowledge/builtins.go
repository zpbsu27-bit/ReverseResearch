package knowledge

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"time"
)

//go:embed builtins/*.json
var builtinFS embed.FS

var builtinIDPattern = regexp.MustCompile(`^builtin_[a-z0-9_-]{1,96}$`)

func builtinNotes() ([]Note, error) {
	entries, err := fs.ReadDir(builtinFS, "builtins")
	if err != nil {
		return nil, fmt.Errorf("read builtin knowledge: %w", err)
	}
	result := make([]Note, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		note, err := getBuiltin(id)
		if err != nil {
			return nil, err
		}
		result = append(result, note)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func getBuiltin(id string) (Note, error) {
	if !builtinIDPattern.MatchString(id) {
		return Note{}, fmt.Errorf("invalid builtin knowledge ID %q", id)
	}
	body, err := builtinFS.ReadFile("builtins/" + id + ".json")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Note{}, fmt.Errorf("builtin knowledge %q not found", id)
		}
		return Note{}, err
	}
	if len(body) > maxNoteRecordBytes {
		return Note{}, errors.New("builtin knowledge record exceeds 4 MiB")
	}
	var note Note
	if err := json.Unmarshal(body, &note); err != nil {
		return Note{}, fmt.Errorf("decode builtin knowledge %s: %w", id, err)
	}
	if note.ID != id || note.Origin != OriginBuiltin {
		return Note{}, errors.New("builtin knowledge identity/origin mismatch")
	}
	if strings.TrimSpace(note.Title) == "" || strings.TrimSpace(note.Body) == "" {
		return Note{}, errors.New("builtin knowledge title and body are required")
	}
	if _, err := time.Parse(time.RFC3339Nano, note.CreatedUTC); err != nil {
		return Note{}, fmt.Errorf("builtin knowledge creation time: %w", err)
	}
	if note.Source == nil {
		return Note{}, errors.New("builtin knowledge requires explicit provenance")
	}
	note.Source, err = normalizeSource(note.Source, note.CreatedUTC)
	if err != nil {
		return Note{}, err
	}
	if !strings.EqualFold(note.Source.EvidenceStatus, "reviewed") {
		return Note{}, errors.New("builtin knowledge must be explicitly reviewed")
	}
	note.Domain, note.Architectures, note.Tools, err = normalizeScope(
		note.Domain, note.Architectures, note.Tools,
	)
	if err != nil {
		return Note{}, err
	}
	note.Tags = normalizeTags(note.Tags)
	note.Route = strings.ToLower(strings.TrimSpace(note.Route))
	note.Revision = contentRevision(body)
	return note, nil
}
