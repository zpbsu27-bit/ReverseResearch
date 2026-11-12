package knowledge

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"reverseresearch/internal/recordio"
)

var (
	noteIDPattern        = regexp.MustCompile(`^note_[a-z0-9_-]{1,96}$`)
	noteOperationPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	ErrNoteExists        = errors.New("knowledge note already exists; previous note retained")
	ErrOperationConflict = errors.New("knowledge operation_id is already bound to a different request")
)

func (s *Store) Get(id string) (result Note, err error) {
	if builtinIDPattern.MatchString(id) {
		return getBuiltin(id)
	}
	if !noteIDPattern.MatchString(id) {
		return Note{}, fmt.Errorf("invalid knowledge note ID %q", id)
	}
	path := filepath.Join(s.root, "notes", id+".json")
	release, err := recordio.Acquire(noteLockPath(path), 10*time.Second)
	if err != nil {
		return Note{}, err
	}
	defer func() { err = errors.Join(err, release()) }()
	info, err := os.Lstat(path)
	if err != nil {
		return Note{}, err
	}
	if !info.Mode().IsRegular() {
		return Note{}, errors.New("knowledge record must be a regular file")
	}
	if info.Size() > maxNoteRecordBytes {
		return Note{}, errors.New("knowledge record exceeds 4 MiB")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return Note{}, err
	}
	if len(body) > maxNoteRecordBytes {
		return Note{}, errors.New("knowledge record exceeds 4 MiB")
	}
	var note Note
	if err := json.Unmarshal(body, &note); err != nil {
		return Note{}, fmt.Errorf("decode knowledge note %s: %w", id, err)
	}
	if note.ID != id {
		return Note{}, errors.New("knowledge note identity mismatch")
	}
	if note.OperationID != "" {
		digest, digestErr := hex.DecodeString(note.RequestSHA256)
		if !noteOperationPattern.MatchString(note.OperationID) ||
			note.ID != "note_"+contentRevision([]byte("journal:add:"+note.OperationID)) ||
			digestErr != nil || len(digest) != 32 {
			return Note{}, errors.New("invalid knowledge operation binding")
		}
	} else if note.RequestSHA256 != "" {
		return Note{}, errors.New("knowledge request digest requires an operation binding")
	}
	if strings.TrimSpace(note.Title) == "" || strings.TrimSpace(note.Body) == "" {
		return Note{}, errors.New("knowledge note title and body are required")
	}
	if _, err := time.Parse(time.RFC3339Nano, note.CreatedUTC); err != nil {
		return Note{}, fmt.Errorf("knowledge note creation time: %w", err)
	}
	if note.Origin != "" && !strings.EqualFold(note.Origin, OriginJournal) {
		return Note{}, errors.New("state knowledge note cannot claim builtin origin")
	}
	note.Origin = OriginJournal
	note.Route = strings.ToLower(strings.TrimSpace(note.Route))
	note.Tags = normalizeTags(note.Tags)
	note.Domain, note.Architectures, note.Tools, err = normalizeScope(
		note.Domain, note.Architectures, note.Tools,
	)
	if err != nil {
		return Note{}, err
	}
	legacy := note.Source == nil
	note.Source, err = normalizeSource(note.Source, note.CreatedUTC)
	if err != nil {
		return Note{}, err
	}
	if legacy {
		note.Source.Reference = "legacy:unspecified"
	}
	note.Revision = contentRevision(body)
	return note, nil
}

func noteLockPath(path string) string {
	return filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".lock")
}

// Notes are immutable. Even a random ID collision must not overwrite knowledge.
func writeNote(path string, body []byte) (err error) {
	release, err := recordio.Acquire(noteLockPath(path), 10*time.Second)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, release()) }()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return ErrNoteExists
		}
		return err
	}
	return recordio.WriteFile(path, body, 0o600)
}
