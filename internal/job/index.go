package job

import (
	"container/heap"
	"context"
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
	jobIndexVersion = 2
	jobRecentLimit  = 1024
)

type jobIndexEntry struct {
	ID         string `json:"id"`
	PlannedUTC string `json:"planned_utc"`
}

type jobIndex struct {
	Version    int             `json:"version"`
	Entries    []jobIndexEntry `json:"entries"`
	WrittenUTC string          `json:"written_utc"`
}

type jobRecentCandidate struct {
	entry jobIndexEntry
	at    time.Time
}

type jobRecentHeap []jobRecentCandidate

func (h jobRecentHeap) Len() int { return len(h) }
func (h jobRecentHeap) Less(i, j int) bool {
	if !h[i].at.Equal(h[j].at) {
		return h[i].at.Before(h[j].at)
	}
	return h[i].entry.ID < h[j].entry.ID
}
func (h jobRecentHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *jobRecentHeap) Push(value any) {
	*h = append(*h, value.(jobRecentCandidate))
}
func (h *jobRecentHeap) Pop() any {
	old := *h
	last := old[len(old)-1]
	*h = old[:len(old)-1]
	return last
}

func (s *Store) jobIndexPath() string {
	return filepath.Join(s.root, ".job-recent.json")
}

func (s *Store) jobIndexLockPath() string {
	return filepath.Join(s.root, ".job-recent.lock")
}

func (s *Store) jobIndexDirtyPath() string {
	return filepath.Join(s.root, ".job-recent.dirty")
}

// saveNew commits the authoritative per-job records while maintaining only a
// bounded recent cache. The dirty marker makes a crash between those steps
// self-healing without making every normal write O(total historical jobs).
func (s *Store) saveNewContext(ctx context.Context, value Job) (err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	release, err := recordio.AcquireContext(ctx, s.jobIndexLockPath(), 2*time.Second)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, release()) }()

	index, err := s.currentJobIndexUnlocked()
	if err != nil {
		return err
	}
	if err := s.markJobIndexDirtyUnlocked(); err != nil {
		return err
	}
	if err := s.saveContext(ctx, value); err != nil {
		return err
	}

	found := false
	for i := range index.Entries {
		if index.Entries[i].ID == value.ID {
			index.Entries[i].PlannedUTC = value.PlannedUTC
			found = true
			break
		}
	}
	if !found {
		index.Entries = append(index.Entries, jobIndexEntry{ID: value.ID, PlannedUTC: value.PlannedUTC})
	}
	sortJobIndex(index.Entries)
	if len(index.Entries) > jobRecentLimit {
		index.Entries = append([]jobIndexEntry(nil), index.Entries[len(index.Entries)-jobRecentLimit:]...)
	}
	if writeErr := s.writeJobIndexUnlocked(index); writeErr == nil {
		_ = os.Remove(s.jobIndexDirtyPath())
	}
	return nil
}

// ListRecent returns at most the newest limit jobs while preserving chronological
// order within the returned window. A zero/negative limit means the whole bounded
// recent cache, never the complete historical store.
func (s *Store) ListRecent(limit int) ([]Job, error) {
	if limit <= 0 || limit > jobRecentLimit {
		limit = jobRecentLimit
	}
	index, err := s.currentJobIndex()
	if err != nil {
		return nil, err
	}
	entries := index.Entries
	if len(entries) > limit {
		entries = entries[len(entries)-limit:]
	}
	out := make([]Job, 0, len(entries))
	for _, entry := range entries {
		value, err := s.Get(entry.ID)
		if err != nil {
			// One removed or unreadable record must not take the whole recent
			// view down permanently: the index is refenced so the next rebuild
			// drops the dangling entry.
			if errors.Is(err, os.ErrNotExist) {
				_ = s.markJobIndexDirty()
			}
			continue
		}
		out = append(out, value)
	}
	return out, nil
}

// markJobIndexDirty refences the recent cache from a read path that does not
// already hold the index lock.
func (s *Store) markJobIndexDirty() (err error) {
	release, err := recordio.Acquire(s.jobIndexLockPath(), 2*time.Second)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, release()) }()
	return s.markJobIndexDirtyUnlocked()
}

// List is intentionally the explicit full-history operation. It scans
// authoritative records because returning all jobs is inherently O(N); normal
// dashboards and status paths use ListRecent instead.
func (s *Store) List() ([]Job, error) {
	entries, err := s.scanAllJobHeaders()
	if err != nil {
		return nil, err
	}
	out := make([]Job, 0, len(entries))
	for _, entry := range entries {
		value, err := s.Get(entry.ID)
		if err != nil {
			// A record removed while the directory was being listed is a normal
			// race; damaged records still fail loudly on this explicit path.
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, err
		}
		out = append(out, value)
	}
	return out, nil
}

func (s *Store) currentJobIndex() (index jobIndex, err error) {
	release, err := recordio.Acquire(s.jobIndexLockPath(), 2*time.Second)
	if err != nil {
		return jobIndex{}, err
	}
	defer func() { err = errors.Join(err, release()) }()
	return s.currentJobIndexUnlocked()
}

func (s *Store) currentJobIndexUnlocked() (jobIndex, error) {
	if _, err := os.Stat(s.jobIndexDirtyPath()); err == nil {
		return s.rebuildJobIndexUnlocked()
	} else if !errors.Is(err, os.ErrNotExist) {
		return jobIndex{}, err
	}

	index, err := s.readJobIndexUnlocked()
	if err == nil {
		if len(index.Entries) > jobRecentLimit {
			return s.rebuildJobIndexUnlocked()
		}
		return index, nil
	}
	return s.rebuildJobIndexUnlocked()
}

func (s *Store) rebuildJobIndexUnlocked() (jobIndex, error) {
	candidates := &jobRecentHeap{}
	heap.Init(candidates)
	seen := map[string]time.Time{}
	err := walkJobRecords(filepath.Join(s.root, "jobs"), func(header jobIndexEntry, at time.Time) {
		if existing, ok := seen[header.ID]; ok && !at.After(existing) {
			return
		}
		seen[header.ID] = at
		rebuildRecentJobHeap(candidates, header, at)
	})
	if err != nil {
		return jobIndex{}, err
	}

	index := jobIndex{Version: jobIndexVersion, Entries: make([]jobIndexEntry, 0, candidates.Len())}
	for candidates.Len() > 0 {
		index.Entries = append(index.Entries, heap.Pop(candidates).(jobRecentCandidate).entry)
	}
	sortJobIndex(index.Entries)
	if err := s.writeJobIndexUnlocked(index); err != nil {
		return jobIndex{}, err
	}
	_ = os.Remove(s.jobIndexDirtyPath())
	return index, nil
}

func rebuildRecentJobHeap(h *jobRecentHeap, entry jobIndexEntry, at time.Time) {
	candidate := jobRecentCandidate{entry: entry, at: at}
	if h.Len() < jobRecentLimit {
		heap.Push(h, candidate)
		return
	}
	oldest := (*h)[0]
	if at.After(oldest.at) || (at.Equal(oldest.at) && entry.ID > oldest.entry.ID) {
		heap.Pop(h)
		heap.Push(h, candidate)
	}
}

func (s *Store) scanAllJobHeaders() ([]jobIndexEntry, error) {
	byID := map[string]jobRecentCandidate{}
	err := walkJobRecords(filepath.Join(s.root, "jobs"), func(header jobIndexEntry, at time.Time) {
		if existing, ok := byID[header.ID]; !ok || at.After(existing.at) {
			byID[header.ID] = jobRecentCandidate{entry: header, at: at}
		}
	})
	if err != nil {
		return nil, err
	}
	entries := make([]jobIndexEntry, 0, len(byID))
	for _, candidate := range byID {
		entries = append(entries, candidate.entry)
	}
	sortJobIndex(entries)
	return entries, nil
}

func readJobHeader(path string) (jobIndexEntry, time.Time, error) {
	file, err := os.Open(path)
	if err != nil {
		return jobIndexEntry{}, time.Time{}, err
	}
	var header struct {
		ID         string `json:"job_id"`
		PlannedUTC string `json:"planned_at"`
	}
	decodeErr := json.NewDecoder(file).Decode(&header)
	closeErr := file.Close()
	if decodeErr != nil {
		return jobIndexEntry{}, time.Time{}, fmt.Errorf("decode job %s for index: %w", path, decodeErr)
	}
	if closeErr != nil {
		return jobIndexEntry{}, time.Time{}, closeErr
	}
	if strings.TrimSpace(header.ID) == "" {
		return jobIndexEntry{}, time.Time{}, fmt.Errorf("job %s has empty identity while rebuilding index", path)
	}
	at, err := time.Parse(time.RFC3339Nano, header.PlannedUTC)
	if err != nil {
		return jobIndexEntry{}, time.Time{}, fmt.Errorf("job %s has invalid planned time: %w", header.ID, err)
	}
	return jobIndexEntry{ID: header.ID, PlannedUTC: header.PlannedUTC}, at, nil
}

// readJobHeaderBestEffort reports a header only when it parses. One damaged or
// concurrently removed record must not make the whole recent index unusable,
// because a failed rebuild would leave the dirty fence set and fail every read.
func readJobHeaderBestEffort(path string) (jobIndexEntry, time.Time, bool) {
	header, at, err := readJobHeader(path)
	if err != nil {
		return jobIndexEntry{}, time.Time{}, false
	}
	return header, at, true
}

func walkJobRecords(root string, visit func(jobIndexEntry, time.Time)) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			if errors.Is(walkErr, os.ErrNotExist) {
				return nil
			}
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			return nil
		}
		if header, at, ok := readJobHeaderBestEffort(path); ok {
			visit(header, at)
		}
		return nil
	})
}

func (s *Store) markJobIndexDirtyUnlocked() error {
	body := []byte(time.Now().UTC().Format(time.RFC3339Nano) + "\n")
	return recordio.WriteFile(s.jobIndexDirtyPath(), body, 0o600)
}

func (s *Store) readJobIndexUnlocked() (jobIndex, error) {
	file, err := os.Open(s.jobIndexPath())
	if err != nil {
		return jobIndex{}, err
	}
	defer file.Close()
	var index jobIndex
	if err := json.NewDecoder(file).Decode(&index); err != nil {
		return jobIndex{}, err
	}
	if index.Version != jobIndexVersion {
		return jobIndex{}, errors.New("unsupported job recent index version")
	}
	return index, nil
}

func (s *Store) writeJobIndexUnlocked(index jobIndex) error {
	index.Version = jobIndexVersion
	index.WrittenUTC = time.Now().UTC().Format(time.RFC3339Nano)
	return recordio.WriteStream(s.jobIndexPath(), 0o600, func(writer io.Writer) error {
		return json.NewEncoder(writer).Encode(index)
	})
}

func sortJobIndex(entries []jobIndexEntry) {
	sort.Slice(entries, func(i, j int) bool {
		left, _ := time.Parse(time.RFC3339Nano, entries[i].PlannedUTC)
		right, _ := time.Parse(time.RFC3339Nano, entries[j].PlannedUTC)
		if !left.Equal(right) {
			return left.Before(right)
		}
		return entries[i].ID < entries[j].ID
	})
}
