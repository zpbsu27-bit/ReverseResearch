//go:build windows

package modules

import (
	"errors"
	"fmt"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"

	"reverseresearch/internal/targetidentity"
)

func moduleEvidenceForAddress(pid uint32, address uint64) (X32WriteWatchModule, error) {
	if address == 0 {
		return X32WriteWatchModule{}, nil
	}
	const flags = windows.TH32CS_SNAPMODULE | windows.TH32CS_SNAPMODULE32
	var snapshot windows.Handle
	var err error
	for attempt := 0; attempt < 4; attempt++ {
		snapshot, err = windows.CreateToolhelp32Snapshot(flags, pid)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_BAD_LENGTH) {
			return X32WriteWatchModule{}, fmt.Errorf("snapshot process %d modules: %w", pid, err)
		}
	}
	if err != nil {
		return X32WriteWatchModule{}, err
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ModuleEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Module32First(snapshot, &entry); err != nil {
		return X32WriteWatchModule{}, err
	}
	for {
		base := uint64(entry.ModBaseAddr)
		size := uint64(entry.ModBaseSize)
		if address >= base && address-base < size {
			path := filepath.Clean(windows.UTF16ToString(entry.ExePath[:]))
			rva := address - base
			result := X32WriteWatchModule{
				Path: path, Base: base, ImageSize: size, RVA: rva, RVAHex: fmt.Sprintf("0x%X", rva),
			}
			if identity, inspectErr := targetidentity.Inspect(path); inspectErr == nil {
				result.Path = identity.Path
				result.SHA256 = identity.SHA256
				result.FileSize = identity.Size
			}
			return result, nil
		}
		entry.Size = uint32(unsafe.Sizeof(entry))
		if err := windows.Module32Next(snapshot, &entry); err != nil {
			if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
				break
			}
			return X32WriteWatchModule{}, err
		}
	}
	return X32WriteWatchModule{}, nil
}
