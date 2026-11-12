//go:build windows

package remoteagent

import (
	"context"
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

func platformProcessInventory(ctx context.Context, maxEntries int) ([]ProcessInfo, bool, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, false, err
	}
	defer windows.CloseHandle(snapshot)

	entry := windows.ProcessEntry32{}
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snapshot, &entry); err != nil {
		return nil, false, err
	}
	out := make([]ProcessInfo, 0, min(maxEntries, 256))
	for {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		if len(out) >= maxEntries {
			return out, true, nil
		}
		out = append(out, ProcessInfo{
			PID: entry.ProcessID, ParentPID: entry.ParentProcessID,
			Name: windows.UTF16ToString(entry.ExeFile[:]),
		})
		err = windows.Process32Next(snapshot, &entry)
		if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
			return out, false, nil
		}
		if err != nil {
			return nil, false, err
		}
	}
}
