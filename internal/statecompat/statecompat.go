// Package statecompat owns the on-disk ReverseResearch state-layout contract.
//
// Layout migrations are forward-only. A binary may import an older layout, but
// once it publishes the current marker, rollback tooling must not launch a
// binary whose declared maximum layout is lower than the state layout.
package statecompat

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"reverseresearch/internal/recordio"
	"reverseresearch/internal/securefile"
)

const (
	MarkerSchema              = "reverseresearch.state-layout.v1"
	CapabilitiesSchema        = "reverseresearch.state-layout-capabilities.v1"
	LegacyUnversionedLayout   = 1
	CurrentLayoutVersion      = 2
	maxStateLayoutMarkerBytes = int64(16 << 10)
)

var (
	ErrStateLayoutTooNew  = errors.New("state layout is newer than this binary")
	ErrStateLayoutInvalid = errors.New("state layout marker is invalid")
)

type Marker struct {
	SchemaVersion string `json:"schema_version"`
	LayoutVersion int    `json:"layout_version"`
	CreatedUTC    string `json:"created_utc"`
	UpdatedUTC    string `json:"updated_utc,omitempty"`
	MigratedFrom  int    `json:"migrated_from,omitempty"`
}

type Status struct {
	SchemaVersion string `json:"schema_version"`
	MarkerPath    string `json:"marker_path"`
	MarkerPresent bool   `json:"marker_present"`
	LayoutVersion int    `json:"layout_version"`
	Conservative  bool   `json:"conservative_inference"`
	CreatedUTC    string `json:"created_utc,omitempty"`
	UpdatedUTC    string `json:"updated_utc,omitempty"`
}

type Capabilities struct {
	SchemaVersion           string `json:"schema_version"`
	LegacyUnversionedLayout int    `json:"legacy_unversioned_layout"`
	MinSupportedLayout      int    `json:"min_supported_layout"`
	MaxSupportedLayout      int    `json:"max_supported_layout"`
	WritesLayout            int    `json:"writes_layout"`
}

func BinaryCapabilities() Capabilities {
	return Capabilities{
		SchemaVersion:           CapabilitiesSchema,
		LegacyUnversionedLayout: LegacyUnversionedLayout,
		MinSupportedLayout:      LegacyUnversionedLayout,
		MaxSupportedLayout:      CurrentLayoutVersion,
		WritesLayout:            CurrentLayoutVersion,
	}
}

func MarkerPath(root string) (string, error) {
	absolute, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	return filepath.Join(absolute, "state", ".layout.json"), nil
}

// Inspect never mutates state. A non-empty unversioned state tree is
// conservatively treated as the current layout: this intentionally prefers a
// false rollback refusal over launching a legacy executable against state that
// may already have been migrated before layout markers existed.
func Inspect(root string) (Status, error) {
	markerPath, err := MarkerPath(root)
	if err != nil {
		return Status{}, err
	}
	marker, err := readMarker(markerPath)
	if err == nil {
		return Status{
			SchemaVersion: MarkerSchema,
			MarkerPath:    markerPath,
			MarkerPresent: true,
			LayoutVersion: marker.LayoutVersion,
			CreatedUTC:    marker.CreatedUTC,
			UpdatedUTC:    marker.UpdatedUTC,
		}, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return Status{}, err
	}

	stateRoot := filepath.Dir(markerPath)
	nonEmpty, err := stateTreeNonEmpty(stateRoot)
	if err != nil {
		return Status{}, err
	}
	version := LegacyUnversionedLayout
	conservative := false
	if nonEmpty {
		version = CurrentLayoutVersion
		conservative = true
	}
	return Status{
		SchemaVersion: MarkerSchema,
		MarkerPath:    markerPath,
		MarkerPresent: false,
		LayoutVersion: version,
		Conservative:  conservative,
	}, nil
}

// Ensure publishes the current layout marker before any state owner is opened.
// A missing marker is the historical v1 layout. Existing package-level
// migrations can then run, but rollback to a v1-only binary is fail-closed from
// the moment this marker is published.
func Ensure(root string) (marker Marker, err error) {
	markerPath, err := MarkerPath(root)
	if err != nil {
		return Marker{}, err
	}
	stateRoot := filepath.Dir(markerPath)
	if err := os.MkdirAll(stateRoot, 0o700); err != nil {
		return Marker{}, err
	}
	if err := securefile.RestrictDir(stateRoot); err != nil {
		return Marker{}, fmt.Errorf("restrict state layout root: %w", err)
	}

	release, err := recordio.Acquire(filepath.Join(stateRoot, ".layout.lock"), 10*time.Second)
	if err != nil {
		return Marker{}, fmt.Errorf("lock state layout: %w", err)
	}
	defer func() { err = errors.Join(err, release()) }()

	existing, readErr := readMarker(markerPath)
	if readErr == nil {
		switch {
		case existing.LayoutVersion > CurrentLayoutVersion:
			return Marker{}, fmt.Errorf("%w: state=%d binary=%d", ErrStateLayoutTooNew, existing.LayoutVersion, CurrentLayoutVersion)
		case existing.LayoutVersion < LegacyUnversionedLayout:
			return Marker{}, fmt.Errorf("%w: unsupported layout version %d", ErrStateLayoutInvalid, existing.LayoutVersion)
		case existing.LayoutVersion == CurrentLayoutVersion:
			return existing, nil
		case existing.LayoutVersion == LegacyUnversionedLayout:
			now := time.Now().UTC().Format(time.RFC3339Nano)
			existing.LayoutVersion = CurrentLayoutVersion
			existing.UpdatedUTC = now
			existing.MigratedFrom = LegacyUnversionedLayout
			if err := writeMarker(markerPath, existing); err != nil {
				return Marker{}, err
			}
			return existing, nil
		default:
			return Marker{}, fmt.Errorf("%w: unsupported layout transition %d -> %d", ErrStateLayoutInvalid, existing.LayoutVersion, CurrentLayoutVersion)
		}
	}
	if !errors.Is(readErr, os.ErrNotExist) {
		return Marker{}, readErr
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	marker = Marker{
		SchemaVersion: MarkerSchema,
		LayoutVersion: CurrentLayoutVersion,
		CreatedUTC:    now,
		MigratedFrom:  LegacyUnversionedLayout,
	}
	if err := writeMarker(markerPath, marker); err != nil {
		return Marker{}, err
	}
	return marker, nil
}

func readMarker(path string) (Marker, error) {
	body, err := recordio.ReadFileLimit(path, maxStateLayoutMarkerBytes)
	if err != nil {
		return Marker{}, err
	}
	var marker Marker
	if err := json.Unmarshal(body, &marker); err != nil {
		return Marker{}, fmt.Errorf("%w: decode %s: %v", ErrStateLayoutInvalid, path, err)
	}
	if marker.SchemaVersion != MarkerSchema || marker.LayoutVersion < LegacyUnversionedLayout || marker.CreatedUTC == "" {
		return Marker{}, fmt.Errorf("%w: %s", ErrStateLayoutInvalid, path)
	}
	return marker, nil
}

func writeMarker(path string, marker Marker) error {
	body, err := json.MarshalIndent(marker, "", "  ")
	if err != nil {
		return err
	}
	if int64(len(body)) > maxStateLayoutMarkerBytes {
		return fmt.Errorf("%w: encoded marker exceeds limit", ErrStateLayoutInvalid)
	}
	if err := recordio.WriteFile(path, body, 0o600); err != nil {
		return fmt.Errorf("write state layout marker: %w", err)
	}
	return nil
}

func stateTreeNonEmpty(stateRoot string) (bool, error) {
	entries, err := os.ReadDir(stateRoot)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		switch entry.Name() {
		case ".layout.json", ".layout.lock":
			continue
		default:
			return true, nil
		}
	}
	return false, nil
}
