//go:build windows

package memscan

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

type windowsProcessMemory struct {
	handle windows.Handle
}

func openProcessMemory(pid uint32) (processMemory, error) {
	if pid == 0 {
		return nil, errors.New("pid is required")
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return nil, fmt.Errorf("open process %d for read-only memory scan: %w", pid, err)
	}
	return &windowsProcessMemory{handle: handle}, nil
}

func (m *windowsProcessMemory) Query(address uint64) (RegionIdentity, error) {
	if uint64(uintptr(address)) != address {
		return RegionIdentity{}, fmt.Errorf("address 0x%X does not fit this process architecture", address)
	}
	var info windows.MemoryBasicInformation
	if err := windows.VirtualQueryEx(m.handle, uintptr(address), &info, unsafe.Sizeof(info)); err != nil {
		return RegionIdentity{}, err
	}
	return RegionIdentity{
		BaseAddress: uint64(info.BaseAddress), AllocationBase: uint64(info.AllocationBase),
		AllocationProtect: info.AllocationProtect, RegionSize: uint64(info.RegionSize),
		State: info.State, Protect: info.Protect, Type: info.Type,
	}, nil
}

func (m *windowsProcessMemory) Read(address uint64, size int) ([]byte, error) {
	if size <= 0 {
		return nil, errors.New("memory read size must be positive")
	}
	if uint64(uintptr(address)) != address {
		return nil, fmt.Errorf("address 0x%X does not fit this process architecture", address)
	}
	buffer := make([]byte, size)
	var read uintptr
	if err := windows.ReadProcessMemory(m.handle, uintptr(address), &buffer[0], uintptr(size), &read); err != nil {
		return nil, err
	}
	if read != uintptr(size) {
		return nil, fmt.Errorf("short process memory read at 0x%X: got %d want %d", address, read, size)
	}
	return buffer, nil
}

func (m *windowsProcessMemory) Close() error {
	if m.handle == 0 {
		return nil
	}
	err := windows.CloseHandle(m.handle)
	m.handle = 0
	return err
}
