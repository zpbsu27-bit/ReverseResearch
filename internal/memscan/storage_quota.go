package memscan

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const (
	MaxStoredScans     = 1024
	MaxStoredScanBytes = int64(4 << 30)
)

func (m *Manager) ensureNewScanCapacity() error {
	count, bytes, err := m.scanStorageUsage()
	if err != nil {
		return err
	}
	if count >= MaxStoredScans {
		return fmt.Errorf("memory scan storage quota reached: %d records >= %d; archive or remove old scan state before starting another scan", count, MaxStoredScans)
	}
	if bytes > MaxStoredScanBytes-MaxPersistedScanBytes {
		return fmt.Errorf("memory scan storage quota reached: %d bytes leaves insufficient space under %d-byte quota", bytes, MaxStoredScanBytes)
	}
	return nil
}

func (m *Manager) scanStorageUsage() (int, int64, error) {
	// A scan can exist at the sharded path, at the legacy path, or (briefly
	// during a migration) at both. Count it once and charge the larger copy so
	// the record count and the byte total can never disagree.
	bytesByID := map[string]int64{}
	consume := func(path string, info fs.FileInfo) {
		id := strings.TrimSuffix(filepath.Base(path), ".json")
		if !validScanID(id) || info.Size() < 0 {
			return
		}
		if info.Size() > bytesByID[id] {
			bytesByID[id] = info.Size()
		}
	}
	dataRoot := filepath.Join(m.dir, "data")
	if _, err := os.Stat(dataRoot); err == nil {
		err = filepath.Walk(dataRoot, func(path string, info fs.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if info.Mode().IsRegular() && filepath.Ext(info.Name()) == ".json" {
				consume(path, info)
			}
			return nil
		})
		if err != nil {
			return 0, 0, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return 0, 0, err
	}
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		return 0, 0, err
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return 0, 0, err
		}
		consume(filepath.Join(m.dir, entry.Name()), info)
	}
	var totalBytes int64
	for _, size := range bytesByID {
		totalBytes += size
	}
	return len(bytesByID), totalBytes, nil
}
