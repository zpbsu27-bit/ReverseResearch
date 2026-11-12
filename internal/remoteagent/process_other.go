//go:build !windows

package remoteagent

import (
	"context"
	"errors"
	"os"
	"runtime"
	"strconv"
	"strings"
)

func platformProcessInventory(ctx context.Context, maxEntries int) ([]ProcessInfo, bool, error) {
	if runtime.GOOS != "linux" {
		return nil, false, errors.New("process.inventory is not implemented on this platform")
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, false, err
	}
	out := make([]ProcessInfo, 0, min(maxEntries, 256))
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		pid64, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil || !entry.IsDir() {
			continue
		}
		if len(out) >= maxEntries {
			return out, true, nil
		}
		nameBody, _ := os.ReadFile("/proc/" + entry.Name() + "/comm")
		statusBody, _ := os.ReadFile("/proc/" + entry.Name() + "/status")
		var parent uint64
		for _, line := range strings.Split(string(statusBody), "\n") {
			if strings.HasPrefix(line, "PPid:") {
				parent, _ = strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "PPid:")), 10, 32)
				break
			}
		}
		out = append(out, ProcessInfo{PID: uint32(pid64), ParentPID: uint32(parent), Name: strings.TrimSpace(string(nameBody))})
	}
	return out, false, nil
}
