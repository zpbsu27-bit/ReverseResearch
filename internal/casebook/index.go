package casebook

import (
	"container/heap"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"reverseresearch/internal/recordio"
)

const (
	caseIndexVersion  = 2
	caseRecentLimit   = 256
	caseDirtyStaleAge = 5 * time.Minute
	caseDirtyMaxBytes = int64(4096)
)

type caseIndexEntry struct {
	ID         string `json:"id"`
	UpdatedUTC string `json:"updated_utc"`
}

type caseIndex struct {
	Version    int              `json:"version"`
	Entries    []caseIndexEntry `json:"entries"`
	WrittenUTC string           `json:"written_utc"`
}

type caseDirtyMarker struct {
	ID         string `json:"id"`
	UpdatedUTC string `json:"updated_utc"`
}

type caseRecentCandidate struct {
	entry caseIndexEntry
	at    time.Time
}

type caseRecentHeap []caseRecentCandidate

func (h caseRecentHeap) Len() int { return len(h) }
func (h caseRecentHeap) Less(i, j int) bool {
	if !h[i].at.Equal(h[j].at) {
		return h[i].at.Before(h[j].at)
	}
	return h[i].entry.ID < h[j].entry.ID
}
func (h caseRecentHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *caseRecentHeap) Push(value any) {
	*h = append(*h, value.(caseRecentCandidate))
}
func (h *caseRecentHeap) Pop() any {
	old := *h
	last := old[len(old)-1]
	*h = old[:len(old)-1]
	return last
}

func (s *Store) indexPath() string {
	return filepath.Join(s.root, ".case-recent.json")
}

func (s *Store) indexLockPath() string {
	return filepath.Join(s.root, ".case-recent.lock")
}

func (s *Store) indexDirtyDir() string {
	return filepath.Join(s.root, ".case-recent-dirty")
}

func (s *Store) indexDirtyPath(id string) string {
	return filepath.Join(s.indexDirtyDir(), id+".json")
}

func (s *Store) indexDirtyLockPath(id string) string {
	return filepath.Join(s.indexDirtyDir(), "."+id+".lock")
}

func (s *Store) markCaseIndexDirty(value Case) (err error) {
	if err := validateID(value.ID); err != nil {
		return err
	}
	if _, err := time.Parse(time.RFC3339Nano, value.UpdatedUTC); err != nil {
		return fmt.Errorf("case %s has invalid update time: %w", value.ID, err)
	}
	if err := os.MkdirAll(s.indexDirtyDir(), 0o700); err != nil {
		return err
	}
	release, err := recordio.Acquire(s.indexDirtyLockPath(value.ID), 2*time.Second)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, release()) }()

	body, err := json.Marshal(caseDirtyMarker{ID: value.ID, UpdatedUTC: value.UpdatedUTC})
	if err != nil {
		return err
	}
	body = append(body, '\n')
	return recordio.WriteFile(s.indexDirtyPath(value.ID), body, 0o600)
}

func (s *Store) clearCaseIndexDirty(id, updatedUTC string) (err error) {
	if err := validateID(id); err != nil {
		return err
	}
	release, err := recordio.Acquire(s.indexDirtyLockPath(id), 2*time.Second)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, release()) }()

	path := s.indexDirtyPath(id)
	body, err := recordio.ReadFileLimit(path, caseDirtyMaxBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var marker caseDirtyMarker
	if err := json.Unmarshal(body, &marker); err != nil {
		return fmt.Errorf("decode case recent dirty marker %s: %w", id, err)
	}
	if marker.ID != id {
		return fmt.Errorf("case recent dirty marker identity mismatch: %s", id)
	}
	// Only the writer that published this exact case revision may clear the
	// recovery fence. A newer writer may already have replaced the marker.
	if marker.UpdatedUTC != updatedUTC {
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (s *Store) updateCaseIndex(value Case) (err error) {
	release, err := recordio.Acquire(s.indexLockPath(), 2*time.Second)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, release()) }()

	index, err := s.readCaseIndex()
	if err != nil {
		index, err = s.rebuildCaseIndexUnlocked()
	}
	if err != nil {
		return err
	}

	found := false
	for i := range index.Entries {
		if index.Entries[i].ID == value.ID {
			index.Entries[i].UpdatedUTC = value.UpdatedUTC
			found = true
			break
		}
	}
	if !found {
		index.Entries = append(index.Entries, caseIndexEntry{ID: value.ID, UpdatedUTC: value.UpdatedUTC})
	}
	sortCaseIndex(index.Entries)
	if len(index.Entries) > caseRecentLimit {
		index.Entries = append([]caseIndexEntry(nil), index.Entries[:caseRecentLimit]...)
	}
	if err := s.writeCaseIndex(index); err != nil {
		return err
	}
	return s.clearCaseIndexDirty(value.ID, value.UpdatedUTC)
}

func (s *Store) currentCaseIndex() (index caseIndex, err error) {
	release, err := recordio.Acquire(s.indexLockPath(), 2*time.Second)
	if err != nil {
		return caseIndex{}, err
	}
	defer func() { err = errors.Join(err, release()) }()

	index, indexErr := s.readCaseIndex()
	committedDirty, err := s.committedCaseIndexDirtyUnlocked()
	if err != nil {
		return caseIndex{}, err
	}
	if indexErr == nil && len(index.Entries) <= caseRecentLimit && len(committedDirty) == 0 {
		return index, nil
	}

	index, err = s.rebuildCaseIndexUnlocked()
	if err != nil {
		return caseIndex{}, err
	}
	for _, marker := range committedDirty {
		if err := s.clearCaseIndexDirty(marker.ID, marker.UpdatedUTC); err != nil {
			return caseIndex{}, err
		}
	}
	return index, nil
}

// committedCaseIndexDirtyUnlocked returns only markers whose canonical Case
// already reflects the target update. Fresh markers that precede the canonical
// publish are intentionally left in place so a concurrent writer cannot lose
// its crash-recovery fence.
func (s *Store) committedCaseIndexDirtyUnlocked() ([]caseDirtyMarker, error) {
	entries, err := os.ReadDir(s.indexDirtyDir())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	committed := make([]caseDirtyMarker, 0, len(entries))
	now := time.Now()
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(s.indexDirtyDir(), entry.Name())
		body, err := recordio.ReadFileLimit(path, caseDirtyMaxBytes)
		if err != nil {
			return nil, err
		}
		var marker caseDirtyMarker
		if err := json.Unmarshal(body, &marker); err != nil {
			return nil, fmt.Errorf("decode case recent dirty marker %s: %w", entry.Name(), err)
		}
		if err := validateID(marker.ID); err != nil || entry.Name() != marker.ID+".json" {
			return nil, fmt.Errorf("invalid case recent dirty marker %q", entry.Name())
		}
		target, err := time.Parse(time.RFC3339Nano, marker.UpdatedUTC)
		if err != nil {
			return nil, fmt.Errorf("invalid case recent dirty marker time for %s: %w", marker.ID, err)
		}
		current, currentErr := s.readCaseIndexHeader(s.casePath(marker.ID))
		if currentErr == nil {
			at, parseErr := time.Parse(time.RFC3339Nano, current.UpdatedUTC)
			if parseErr != nil {
				return nil, parseErr
			}
			if !at.Before(target) {
				committed = append(committed, marker)
				continue
			}
		} else if !errors.Is(currentErr, os.ErrNotExist) {
			return nil, currentErr
		}
		info, statErr := entry.Info()
		if statErr != nil {
			return nil, statErr
		}
		if now.Sub(info.ModTime()) > caseDirtyStaleAge {
			if err := s.clearCaseIndexDirty(marker.ID, marker.UpdatedUTC); err != nil {
				return nil, err
			}
		}
	}
	return committed, nil
}

func (s *Store) rebuildCaseIndexUnlocked() (caseIndex, error) {
	recent := &caseRecentHeap{}
	heap.Init(recent)
	err := filepath.WalkDir(filepath.Join(s.root, "cases"), func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			if errors.Is(walkErr, os.ErrNotExist) {
				return nil
			}
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			return nil
		}
		// A single damaged or concurrently removed case must not fail the whole
		// rebuild: a failed rebuild leaves the cache unusable for every list call.
		header, err := s.readCaseIndexHeader(path)
		if err != nil {
			return nil
		}
		if err := validateID(header.ID); err != nil {
			return nil
		}
		at, err := time.Parse(time.RFC3339Nano, header.UpdatedUTC)
		if err != nil {
			return nil
		}
		candidate := caseRecentCandidate{
			entry: caseIndexEntry{ID: header.ID, UpdatedUTC: header.UpdatedUTC},
			at:    at,
		}
		if recent.Len() < caseRecentLimit {
			heap.Push(recent, candidate)
		} else {
			oldest := (*recent)[0]
			if at.After(oldest.at) || (at.Equal(oldest.at) && header.ID > oldest.entry.ID) {
				heap.Pop(recent)
				heap.Push(recent, candidate)
			}
		}
		return nil
	})
	if err != nil {
		return caseIndex{}, err
	}
	index := caseIndex{Version: caseIndexVersion, Entries: make([]caseIndexEntry, 0, recent.Len())}
	for recent.Len() > 0 {
		index.Entries = append(index.Entries, heap.Pop(recent).(caseRecentCandidate).entry)
	}
	sortCaseIndex(index.Entries)
	if err := s.writeCaseIndex(index); err != nil {
		return caseIndex{}, err
	}
	return index, nil
}

// invalidateCaseIndex rebuilds the recent cache from authoritative records.
// Read paths call it when a cached entry no longer resolves, so one removed
// case cannot shorten every later list forever.
func (s *Store) invalidateCaseIndex() (err error) {
	release, err := recordio.Acquire(s.indexLockPath(), 2*time.Second)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, release()) }()
	_, err = s.rebuildCaseIndexUnlocked()
	return err
}

func (s *Store) readCaseIndexHeader(path string) (caseIndexEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return caseIndexEntry{}, err
	}
	defer file.Close()
	var header struct {
		ID         string `json:"id"`
		UpdatedUTC string `json:"updated_utc"`
	}
	if err := json.NewDecoder(io.LimitReader(file, MaxCaseRecordBytes)).Decode(&header); err != nil {
		return caseIndexEntry{}, fmt.Errorf("decode case header %s: %w", path, err)
	}
	return caseIndexEntry{ID: header.ID, UpdatedUTC: header.UpdatedUTC}, nil
}

func (s *Store) readCaseIndex() (caseIndex, error) {
	file, err := os.Open(s.indexPath())
	if err != nil {
		return caseIndex{}, err
	}
	defer file.Close()
	var index caseIndex
	if err := json.NewDecoder(io.LimitReader(file, 1<<20)).Decode(&index); err != nil {
		return caseIndex{}, err
	}
	if index.Version != caseIndexVersion {
		return caseIndex{}, errors.New("unsupported case recent index version")
	}
	return index, nil
}

func (s *Store) writeCaseIndex(index caseIndex) error {
	if len(index.Entries) > caseRecentLimit {
		return fmt.Errorf("case recent index exceeds entry limit: %d > %d", len(index.Entries), caseRecentLimit)
	}
	index.Version = caseIndexVersion
	index.WrittenUTC = time.Now().UTC().Format(time.RFC3339Nano)
	return recordio.WriteStream(s.indexPath(), 0o600, func(writer io.Writer) error {
		return json.NewEncoder(writer).Encode(index)
	})
}

func sortCaseIndex(entries []caseIndexEntry) {
	sort.Slice(entries, func(i, j int) bool {
		left, _ := time.Parse(time.RFC3339Nano, entries[i].UpdatedUTC)
		right, _ := time.Parse(time.RFC3339Nano, entries[j].UpdatedUTC)
		if !left.Equal(right) {
			return left.After(right)
		}
		return entries[i].ID < entries[j].ID
	})
}
