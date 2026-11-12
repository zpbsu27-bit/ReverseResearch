//go:build windows

package pointermap

import (
	"errors"
	"fmt"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

func snapshotModules(pid uint32) ([]Module, error) {
	const flags = windows.TH32CS_SNAPMODULE | windows.TH32CS_SNAPMODULE32
	var snapshot windows.Handle
	var err error
	for attempt := 0; attempt < 4; attempt++ {
		snapshot, err = windows.CreateToolhelp32Snapshot(flags, pid)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_BAD_LENGTH) {
			return nil, fmt.Errorf("snapshot process %d modules: %w", pid, err)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("snapshot process %d modules: %w", pid, err)
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ModuleEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Module32First(snapshot, &entry); err != nil {
		return nil, fmt.Errorf("enumerate process %d modules: %w", pid, err)
	}
	modules := make([]Module, 0, 32)
	for {
		path := filepath.Clean(windows.UTF16ToString(entry.ExePath[:]))
		if path != "" && entry.ModBaseAddr != 0 && entry.ModBaseSize != 0 {
			modules = append(modules, Module{
				Path: path, Base: uint64(entry.ModBaseAddr), Size: uint64(entry.ModBaseSize),
			})
		}
		entry.Size = uint32(unsafe.Sizeof(entry))
		if err := windows.Module32Next(snapshot, &entry); err != nil {
			if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
				break
			}
			return nil, fmt.Errorf("enumerate process %d modules: %w", pid, err)
		}
	}
	if len(modules) == 0 {
		return nil, fmt.Errorf("process %d has no visible modules", pid)
	}
	return modules, nil
}
