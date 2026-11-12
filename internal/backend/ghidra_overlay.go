package backend

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

type ghidraRuntimeOverlay struct {
	source string
	target string
}

func syncGhidraRuntimeSources(root string) error {
	overlays := []ghidraRuntimeOverlay{
		{
			source: filepath.Join(root, "patches", "ghidra", "re_mcp_ghidra", "session.py"),
			target: filepath.Join(root, "runtime", "ghidra", "python-packages", "re_mcp_ghidra", "session.py"),
		},
		{
			source: filepath.Join(root, "patches", "ghidra", "re_mcp", "worker_provider.py"),
			target: filepath.Join(root, "runtime", "ghidra", "python-packages", "re_mcp", "worker_provider.py"),
		},
		{
			source: filepath.Join(root, "patches", "ghidra", "re_mcp_ghidra", "tools", "switches.py"),
			target: filepath.Join(root, "runtime", "ghidra", "python-packages", "re_mcp_ghidra", "tools", "switches.py"),
		},
	}
	if runtime.GOOS == "windows" {
		overlays = append(overlays, ghidraRuntimeOverlay{
			source: filepath.Join(root, "patches", "ghidra", "mcp", "os", "win32", "utilities.py"),
			target: filepath.Join(root, "runtime", "ghidra", "python-packages", "mcp", "os", "win32", "utilities.py"),
		})
	}
	for _, overlay := range overlays {
		if err := syncGhidraRuntimeSource(overlay.source, overlay.target); err != nil {
			return err
		}
	}
	return nil
}

func syncGhidraRuntimeSource(source, target string) error {
	expected, err := os.ReadFile(source)
	if err != nil {
		return fmt.Errorf("read Ghidra runtime overlay %s: %w", source, err)
	}
	current, err := os.ReadFile(target)
	if err == nil && bytes.Equal(current, expected) {
		return nil
	}
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read Ghidra runtime target %s: %w", target, err)
	}

	mode := os.FileMode(0o644)
	if info, statErr := os.Stat(target); statErr == nil {
		mode = info.Mode().Perm()
	} else if !os.IsNotExist(statErr) {
		return fmt.Errorf("stat Ghidra runtime target %s: %w", target, statErr)
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return fmt.Errorf("create Ghidra runtime target directory: %w", err)
	}

	temp, err := os.CreateTemp(filepath.Dir(target), ".rr-ghidra-overlay-*")
	if err != nil {
		return fmt.Errorf("create Ghidra runtime overlay temp: %w", err)
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if _, err := temp.Write(expected); err != nil {
		return errors.Join(fmt.Errorf("write Ghidra runtime overlay temp: %w", err), temp.Close())
	}
	if err := temp.Chmod(mode); err != nil {
		return errors.Join(fmt.Errorf("set Ghidra runtime overlay mode: %w", err), temp.Close())
	}
	if err := temp.Sync(); err != nil {
		return errors.Join(fmt.Errorf("sync Ghidra runtime overlay temp: %w", err), temp.Close())
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close Ghidra runtime overlay temp: %w", err)
	}

	backup := target + ".rrbak"
	_ = os.Remove(backup)
	hadTarget := false
	if _, err := os.Stat(target); err == nil {
		if err := os.Rename(target, backup); err != nil {
			return fmt.Errorf("backup Ghidra runtime target %s: %w", target, err)
		}
		hadTarget = true
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("recheck Ghidra runtime target %s: %w", target, err)
	}

	if err := os.Rename(tempName, target); err != nil {
		if hadTarget {
			_ = os.Rename(backup, target)
		}
		return fmt.Errorf("publish Ghidra runtime overlay %s: %w", target, err)
	}
	if hadTarget {
		_ = os.Remove(backup)
	}
	return nil
}
