package collaboration

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"reverseresearch/internal/recordio"
)

const (
	collaborationHistoryInlineLimit      = 256
	collaborationHistoryEventMaxBytes    = int64(256 << 10)
	collaborationHistoryShardMaxFiles    = 64
	collaborationHistoryShardMaxBytes    = int64(256 << 10)
	collaborationHistoryHydrateMaxEvents = collaborationHistoryShardMaxFiles * 256
	collaborationHistoryHydrateMaxBytes  = collaborationHistoryShardMaxBytes * 256
)

var collaborationStorageIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,160}$`)

func validateCollaborationStorageID(kind, value string) error {
	value = strings.TrimSpace(value)
	if !collaborationStorageIDPattern.MatchString(value) || strings.Contains(value, "..") {
		return fmt.Errorf("invalid collaboration %s %q", kind, value)
	}
	return nil
}

func collaborationHistoryShard(eventID string) string {
	sum := sha256.Sum256([]byte(eventID))
	return fmt.Sprintf("%02x", sum[0])
}

func (s *Store) historyArchiveDir(caseID string) string {
	return filepath.Join(s.root, "history", caseID)
}

func (s *Store) historyArchivePath(caseID, eventID string) string {
	return filepath.Join(s.historyArchiveDir(caseID), collaborationHistoryShard(eventID), eventID+".json")
}

func (s *Store) legacyHistoryArchivePath(caseID, eventID string) string {
	return filepath.Join(s.historyArchiveDir(caseID), eventID+".json")
}

// archiveHistoryOverflow keeps the mutable workspace record bounded while
// preserving every older history event as an immutable per-event record.
// Archive writes happen before the main workspace record is replaced, so a
// crash can at worst leave a duplicate archived event; History de-duplicates it.
func (s *Store) archiveHistoryOverflow(caseID string, workspace *Workspace) error {
	if err := validateCollaborationStorageID("case_id", caseID); err != nil {
		return err
	}
	if workspace == nil || len(workspace.History) <= collaborationHistoryInlineLimit {
		return nil
	}
	overflow := append([]HistoryEvent(nil), workspace.History[:len(workspace.History)-collaborationHistoryInlineLimit]...)
	for _, event := range overflow {
		if err := s.writeArchivedHistoryEvent(caseID, event); err != nil {
			return err
		}
	}
	workspace.History = append([]HistoryEvent(nil), workspace.History[len(workspace.History)-collaborationHistoryInlineLimit:]...)
	return nil
}

func (s *Store) writeArchivedHistoryEvent(caseID string, event HistoryEvent) error {
	if err := validateCollaborationStorageID("case_id", caseID); err != nil {
		return err
	}
	if err := validateCollaborationStorageID("history event id", event.ID); err != nil {
		return err
	}
	body, err := json.MarshalIndent(event, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if int64(len(body)) > collaborationHistoryEventMaxBytes {
		return fmt.Errorf("collaboration history event exceeds size limit: %d > %d", len(body), collaborationHistoryEventMaxBytes)
	}

	path := s.historyArchivePath(caseID, event.ID)
	legacy := s.legacyHistoryArchivePath(caseID, event.ID)
	existing, err := readCollaborationArchiveWithLegacy(path, legacy)
	if err == nil {
		if !bytes.Equal(existing, body) {
			return fmt.Errorf("archived collaboration history event %q changed", event.ID)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	if err := recordio.WriteFileShardQuota(
		path, body, 0o600,
		collaborationHistoryShardMaxFiles,
		collaborationHistoryShardMaxBytes,
	); err != nil {
		return fmt.Errorf("archive collaboration history within shard quota: %w", err)
	}
	_ = os.Remove(legacy)
	return nil
}

func readCollaborationArchiveWithLegacy(path, legacy string) ([]byte, error) {
	body, err := recordio.ReadFileLimit(path, collaborationHistoryEventMaxBytes)
	if errors.Is(err, os.ErrNotExist) && legacy != path {
		return recordio.ReadFileLimit(legacy, collaborationHistoryEventMaxBytes)
	}
	return body, err
}

func (s *Store) readArchivedHistory(caseID string) ([]HistoryEvent, error) {
	if err := validateCollaborationStorageID("case_id", caseID); err != nil {
		return nil, err
	}
	root := s.historyArchiveDir(caseID)
	if _, err := os.Stat(root); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	out := make([]HistoryEvent, 0, 256)
	seen := map[string]struct{}{}
	var totalBytes int64
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			return nil
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		if err := validateCollaborationStorageID("history event id", id); err != nil {
			return err
		}
		// Prefer a sharded copy over a legacy flat copy if both exist.
		if filepath.Dir(path) == root {
			if _, err := os.Stat(s.historyArchivePath(caseID, id)); err == nil {
				return nil
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		if _, duplicate := seen[id]; duplicate {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Size() < 0 || totalBytes > collaborationHistoryHydrateMaxBytes-info.Size() {
			return fmt.Errorf("collaboration history exceeds hydration byte limit: %d", collaborationHistoryHydrateMaxBytes)
		}
		totalBytes += info.Size()
		if len(out) >= collaborationHistoryHydrateMaxEvents {
			return fmt.Errorf("collaboration history exceeds hydration event limit: %d", collaborationHistoryHydrateMaxEvents)
		}
		body, err := recordio.ReadFileLimit(path, collaborationHistoryEventMaxBytes)
		if err != nil {
			return err
		}
		var event HistoryEvent
		if err := json.Unmarshal(body, &event); err != nil {
			return fmt.Errorf("decode archived collaboration history %s: %w", path, err)
		}
		if event.ID != id {
			return fmt.Errorf("archived collaboration history identity mismatch: %s", path)
		}
		seen[id] = struct{}{}
		out = append(out, event)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedUTC != out[j].CreatedUTC {
			return out[i].CreatedUTC < out[j].CreatedUTC
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}
