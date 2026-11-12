//go:build !windows && !linux

package backend

import (
	"errors"
	"os/exec"
)

func hiddenCommand(path string, args ...string) *exec.Cmd { return exec.Command(path, args...) }
func xdbgHostError() error                                { return errors.New("x32/x64dbg backend requires a Windows host") }
func prepareBackendProcess(cmd *exec.Cmd) (preparedBackendProcess, error) {
	return nil, errors.New("backend process-tree ownership unavailable on this host; no child started")
}
func openProcessWatcher(cmd *exec.Cmd) (func() (bool, error), func() error, error) {
	return nil, nil, errors.New("backend readiness watcher unavailable on this host")
}
