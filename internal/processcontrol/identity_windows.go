//go:build windows

package processcontrol

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"reverseresearch/internal/targetidentity"
)

type processSnapshot struct {
	path         string
	creationNano int64
}

func Inspect(pid uint32) (Identity, error) {
	if pid == 0 {
		return Identity{}, errors.New("pid is required")
	}
	before, err := queryProcess(pid)
	if err != nil {
		return Identity{}, err
	}
	imageBefore, err := targetidentity.Inspect(before.path)
	if err != nil {
		return Identity{}, fmt.Errorf("inspect process image: %w", err)
	}
	base, err := mainModuleBase(pid, before.path)
	if err != nil {
		return Identity{}, err
	}
	after, err := queryProcess(pid)
	if err != nil {
		return Identity{}, fmt.Errorf("%w: process disappeared during inspection: %v", ErrProcessChanged, err)
	}
	if before.creationNano != after.creationNano || !strings.EqualFold(filepath.Clean(before.path), filepath.Clean(after.path)) {
		return Identity{}, errors.New("process changed during identity inspection")
	}
	imageAfter, err := targetidentity.Inspect(after.path)
	if err != nil {
		return Identity{}, fmt.Errorf("reinspect process image: %w", err)
	}
	if imageBefore.SHA256 != imageAfter.SHA256 || imageBefore.Size != imageAfter.Size {
		return Identity{}, errors.New("process image changed during identity inspection")
	}
	created := time.Unix(0, before.creationNano).UTC()
	return Identity{
		PID:              pid,
		CreationUTC:      created.Format(time.RFC3339Nano),
		CreationUnixNano: before.creationNano,
		MainModuleBase:   base,
		Image:            imageAfter,
		Key:              buildIdentityKey(pid, before.creationNano, base, imageAfter.SHA256),
	}, nil
}

func queryProcess(pid uint32) (processSnapshot, error) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return processSnapshot{}, fmt.Errorf("open process %d: %w", pid, err)
	}
	defer windows.CloseHandle(handle)

	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(handle, &creation, &exit, &kernel, &user); err != nil {
		return processSnapshot{}, fmt.Errorf("query process %d creation time: %w", pid, err)
	}
	buffer := make([]uint16, 32768)
	size := uint32(len(buffer))
	if err := windows.QueryFullProcessImageName(handle, 0, &buffer[0], &size); err != nil {
		return processSnapshot{}, fmt.Errorf("query process %d image path: %w", pid, err)
	}
	if size == 0 {
		return processSnapshot{}, errors.New("process image path is empty")
	}
	return processSnapshot{
		path:         filepath.Clean(windows.UTF16ToString(buffer[:size])),
		creationNano: creation.Nanoseconds(),
	}, nil
}

func mainModuleBase(pid uint32, imagePath string) (uint64, error) {
	const flags = windows.TH32CS_SNAPMODULE | windows.TH32CS_SNAPMODULE32
	var snapshot windows.Handle
	var err error
	for attempt := 0; attempt < 4; attempt++ {
		snapshot, err = windows.CreateToolhelp32Snapshot(flags, pid)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_BAD_LENGTH) {
			return 0, fmt.Errorf("snapshot process %d modules: %w", pid, err)
		}
	}
	if err != nil {
		return 0, fmt.Errorf("snapshot process %d modules: %w", pid, err)
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ModuleEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Module32First(snapshot, &entry); err != nil {
		return 0, fmt.Errorf("enumerate process %d modules: %w", pid, err)
	}
	for {
		modulePath := filepath.Clean(windows.UTF16ToString(entry.ExePath[:]))
		if modulePath != "" && strings.EqualFold(modulePath, filepath.Clean(imagePath)) {
			if entry.ModBaseAddr == 0 {
				return 0, errors.New("main module base is zero")
			}
			return uint64(entry.ModBaseAddr), nil
		}
		entry.Size = uint32(unsafe.Sizeof(entry))
		if err := windows.Module32Next(snapshot, &entry); err != nil {
			if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
				break
			}
			return 0, fmt.Errorf("enumerate process %d modules: %w", pid, err)
		}
	}
	return 0, fmt.Errorf("main module for %s was not found in process %d", imagePath, pid)
}
