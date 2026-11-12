package knowledge

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const maxNoteRecordBytes = 4 << 20

var ErrRevisionChanged = errors.New("knowledge revision changed; search or show the current note before reading")

// Source is author-supplied provenance, not executable policy or proof of a
// runtime result. An unspecified license is not permission to redistribute.
type Source struct {
	Reference        string `json:"reference"`
	License          string `json:"license"`
	UpstreamRevision string `json:"upstream_revision"`
	Engine           string `json:"engine"`
	Version          string `json:"version"`
	EvidenceStatus   string `json:"evidence_status"`
}

type ReadRequest struct {
	ID        string `json:"id"`
	Revision  string `json:"revision"`
	StartLine int    `json:"start_line,omitempty"`
	MaxLines  int    `json:"max_lines,omitempty"`
}

type Excerpt struct {
	ID         string  `json:"id"`
	Revision   string  `json:"revision"`
	Title      string  `json:"title"`
	Source     *Source `json:"source"`
	StartLine  int     `json:"start_line"`
	EndLine    int     `json:"end_line"`
	TotalLines int     `json:"total_lines"`
	NextLine   int     `json:"next_line,omitempty"`
	Text       string  `json:"text"`
}

// Read accepts a note ID, never an arbitrary filesystem path. Revisions are the
// SHA-256 of the exact persisted JSON bytes returned by Get/Search/Add.
func (s *Store) Read(request ReadRequest) (Excerpt, error) {
	digest, err := hex.DecodeString(request.Revision)
	if err != nil || len(digest) != sha256.Size {
		return Excerpt{}, errors.New("a SHA-256 knowledge revision is required")
	}
	if request.StartLine == 0 {
		request.StartLine = 1
	}
	if request.MaxLines == 0 {
		request.MaxLines = 80
	}
	if request.StartLine < 1 || request.MaxLines < 1 || request.MaxLines > 200 {
		return Excerpt{}, errors.New("start line must be positive and max lines must be between 1 and 200")
	}
	note, err := s.Get(request.ID)
	if err != nil {
		return Excerpt{}, err
	}
	if !strings.EqualFold(request.Revision, note.Revision) {
		return Excerpt{}, ErrRevisionChanged
	}
	lines := strings.Split(note.Body, "\n")
	if request.StartLine > len(lines) {
		return Excerpt{}, fmt.Errorf("start line exceeds the note's %d lines", len(lines))
	}
	end := request.StartLine - 1 + request.MaxLines
	if end > len(lines) {
		end = len(lines)
	}
	text := strings.Join(lines[request.StartLine-1:end], "\n")
	if len(text) > 32<<10 {
		return Excerpt{}, errors.New("requested excerpt exceeds 32 KiB; use fewer or shorter lines")
	}
	result := Excerpt{
		ID: note.ID, Revision: note.Revision, Title: note.Title, Source: note.Source,
		StartLine: request.StartLine, EndLine: end, TotalLines: len(lines), Text: text,
	}
	if end < len(lines) {
		result.NextLine = end + 1
	}
	return result, nil
}

func contentRevision(body []byte) string {
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}

func normalizeSource(source *Source, createdUTC string) (*Source, error) {
	if source == nil {
		return &Source{Reference: "local:journal", License: "unspecified", UpstreamRevision: createdUTC, Engine: "unspecified", Version: "unspecified", EvidenceStatus: "unverified"}, nil
	}
	value := *source
	value.Reference = strings.TrimSpace(value.Reference)
	value.License = strings.TrimSpace(value.License)
	value.UpstreamRevision = strings.TrimSpace(value.UpstreamRevision)
	value.Engine = strings.TrimSpace(value.Engine)
	value.Version = strings.TrimSpace(value.Version)
	value.EvidenceStatus = strings.TrimSpace(value.EvidenceStatus)
	if value.Reference == "" || value.License == "" || value.UpstreamRevision == "" {
		return nil, errors.New("explicit knowledge source requires reference, license and upstream revision/date")
	}
	if value.Engine == "" {
		value.Engine = "unspecified"
	}
	if value.Version == "" {
		value.Version = "unspecified"
	}
	if value.EvidenceStatus == "" {
		value.EvidenceStatus = "unverified"
	}
	return &value, nil
}
