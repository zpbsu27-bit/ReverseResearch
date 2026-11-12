package pointermap

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const (
	MaxStoredMaps     = 1024
	MaxStoredMapBytes = int64(4 << 30)
)

func (m *Manager) ensureNewMapCapacity() error {
	count, bytes, err := m.mapStorageUsage()
	if err != nil {
		return err
	}
	if count >= MaxStoredMaps {
		return fmt.Errorf("pointer map storage quota reached: %d records >= %d; archive or remove old map state before building another map", count, MaxStoredMaps)
	}
	if bytes > MaxStoredMapBytes-MaxPersistedMapBytes {
		return fmt.Errorf("pointer map storage quota reached: %d bytes leaves insufficient space under %d-byte quota", bytes, MaxStoredMapBytes)
	}
	return nil
}

func (m *Manager) mapStorageUsage() (int, int64, error) {
	// A map can exist at the sharded path, at the legacy path, or at both while a
	// migration is incomplete. Count it once and charge the larger copy so the
	// record count and the byte total cannot disagree.
	bytesByID := map[string]int64{}
	consume := func(path string, info fs.FileInfo) {
		id := strings.TrimSuffix(filepath.Base(path), ".json")
		if !validMapID(id) || info.Size() < 0 {
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
