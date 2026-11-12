package remoteagent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"reverseresearch/internal/recordio"
)

const operationStatsCacheVersion = 1

type operationStatsCache struct {
	Version    int            `json:"version"`
	Stats      OperationStats `json:"stats"`
	WrittenUTC string         `json:"written_utc"`
}

func (l *OperationLedger) statsPath() string {
	return filepath.Join(l.root, ".operation-stats.json")
}

func (l *OperationLedger) statsLockPath() string {
	return filepath.Join(l.root, ".operation-stats.lock")
}

func (l *OperationLedger) statsDirtyPath() string {
	return filepath.Join(l.root, ".operation-stats.dirty")
}

func (l *OperationLedger) markStatsDirtyUnlocked() error {
	body := []byte(time.Now().UTC().Format(time.RFC3339Nano) + "\n")
	return recordio.WriteFile(l.statsDirtyPath(), body, 0o600)
}

func (l *OperationLedger) finishStatsCacheBestEffortUnlocked(stats OperationStats) {
	if err := l.writeStatsCacheUnlocked(stats); err != nil {
		return
	}
	_ = os.Remove(l.statsDirtyPath())
}

func (l *OperationLedger) currentStatsUnlocked() (OperationStats, error) {
	if _, err := os.Stat(l.statsDirtyPath()); err == nil {
		return l.rebuildStatsUnlocked()
	} else if !errors.Is(err, os.ErrNotExist) {
		return OperationStats{}, err
	}

	body, err := recordio.ReadFileLimit(l.statsPath(), MaxOperationStatsCacheBytes)
	if err == nil {
		var cache operationStatsCache
		if decodeErr := json.Unmarshal(body, &cache); decodeErr == nil &&
			cache.Version == operationStatsCacheVersion &&
			validOperationStats(cache.Stats) {
			return cache.Stats, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return OperationStats{}, err
	}
	return l.rebuildStatsUnlocked()
}

func (l *OperationLedger) rebuildStatsUnlocked() (OperationStats, error) {
	var stats OperationStats
	seen := map[string]bool{}
	// One unreadable or unknown-state receipt must never block every remote
	// operation: it is counted as unreadable and skipped instead of aborting the
	// rebuild. Sharded records are walked first, so a leftover legacy copy of the
	// same operation id cannot inflate Total.
	consume := func(path string, verifyKey bool) {
		body, err := recordio.ReadFileLimit(path, MaxOperationReceiptBytes)
		if err != nil {
			stats.Unreadable++
			return
		}
		var receipt OperationReceipt
		if err := json.Unmarshal(body, &receipt); err != nil {
			stats.Unreadable++
			return
		}
		if receipt.Version != 1 || !safeOperationID.MatchString(receipt.OperationID) {
			stats.Unreadable++
			return
		}
		if verifyKey && filepath.Base(path) != operationFileKey(receipt.OperationID)+".json" {
			stats.Unreadable++
			return
		}
		if seen[receipt.OperationID] {
			return
		}
		seen[receipt.OperationID] = true
		stats.Total++
		if receipt.State == "running" {
			stats.Running++
			return
		}
		if !incrementOperationState(&stats, receipt.State) {
			stats.Total--
			stats.Unreadable++
		}
	}

	receiptsRoot := filepath.Join(l.root, "receipts")
	if _, err := os.Stat(receiptsRoot); err == nil {
		if err := filepath.WalkDir(receiptsRoot, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				stats.Unreadable++
				return nil
			}
			if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
				return nil
			}
			consume(path, true)
			return nil
		}); err != nil {
			return OperationStats{}, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return OperationStats{}, err
	}

	// Backward compatibility for pre-sharding receipts that lived directly at
	// the ledger root. New writes never add more files here.
	entries, err := os.ReadDir(l.root)
	if err != nil {
		return OperationStats{}, err
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" || len(entry.Name()) == 0 || entry.Name()[0] == '.' {
			continue
		}
		consume(filepath.Join(l.root, entry.Name()), false)
	}
	if err := l.writeStatsCacheUnlocked(stats); err != nil {
		return OperationStats{}, err
	}
	_ = os.Remove(l.statsDirtyPath())
	return stats, nil
}

func (l *OperationLedger) writeStatsCacheUnlocked(stats OperationStats) error {
	cache := operationStatsCache{
		Version:    operationStatsCacheVersion,
		Stats:      stats,
		WrittenUTC: time.Now().UTC().Format(time.RFC3339Nano),
	}
	body, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if len(body) > MaxOperationStatsCacheBytes {
		return fmt.Errorf("operation stats cache exceeds durable size limit: %d > %d", len(body), MaxOperationStatsCacheBytes)
	}
	return recordio.WriteFile(l.statsPath(), body, 0o600)
}

func incrementOperationState(stats *OperationStats, state string) bool {
	switch state {
	case "applied":
		stats.Applied++
	case "failed":
		stats.Failed++
	case "uncertain":
		stats.Uncertain++
	case "rolled_back":
		stats.RolledBack++
	case "cancelled":
		stats.Cancelled++
	default:
		return false
	}
	return true
}

func validOperationStats(stats OperationStats) bool {
	if stats.Total < 0 || stats.Running < 0 || stats.Applied < 0 || stats.Failed < 0 ||
		stats.Uncertain < 0 || stats.RolledBack < 0 || stats.Cancelled < 0 {
		return false
	}
	return stats.Total == stats.Running+stats.Applied+stats.Failed+stats.Uncertain+stats.RolledBack+stats.Cancelled
}
