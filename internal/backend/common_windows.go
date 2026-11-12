//go:build windows

package backend

import (
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func hiddenCommand(path string, args ...string) *exec.Cmd {
	cmd := exec.Command(path, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000, // CREATE_NO_WINDOW
	}
	return cmd
}

func openProcessWatcher(cmd *exec.Cmd) (func() (bool, error), func() error, error) {
	if cmd == nil || cmd.Process == nil {
		return func() (bool, error) { return true, nil }, func() error { return nil }, nil
	}
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(cmd.Process.Pid))
	if err != nil {
		return nil, nil, fmt.Errorf("open backend process for readiness tracking: %w", err)
	}
	return func() (bool, error) {
		event, err := windows.WaitForSingleObject(handle, 0)
		return event != windows.WAIT_OBJECT_0, err
	}, func() error { return windows.CloseHandle(handle) }, nil
}

type windowsBackendProcess struct{ cmd *exec.Cmd }

func prepareBackendProcess(cmd *exec.Cmd) (preparedBackendProcess, error) {
	if cmd == nil {
		return nil, errors.New("backend command is nil")
	}
	return windowsBackendProcess{cmd}, nil
}
func (s windowsBackendProcess) claim(log io.Closer, ownWait bool) (func() error, error) {
	if ownWait {
		return processCleanup(s.cmd, log)
	}
	return attachKillOnCloseJob(s.cmd, log)
}
func (s windowsBackendProcess) abort(log io.Closer, started bool) error {
	var err error
	if started {
		err = reapStartedCommand(s.cmd)
	}
	return errors.Join(err, closeOptional(log))
}
func xdbgHostError() error { return nil }

func processCleanup(cmd *exec.Cmd, log io.Closer) (func() error, error) {
	if cmd == nil || cmd.Process == nil {
		err := errors.New("backend process is not started")
		if log != nil {
			err = errors.Join(err, log.Close())
		}
		return nil, err
	}
	job, err := createKillOnCloseJob(cmd.Process.Pid)
	if err != nil {
		var cleanupErr error
		if killErr := cmd.Process.Kill(); killErr != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("kill unowned backend process: %w", killErr))
		}
		if waitErr := cmd.Wait(); waitErr != nil {
			var exitErr *exec.ExitError
			if !errors.As(waitErr, &exitErr) {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("wait unowned backend process: %w", waitErr))
			}
		}
		if log != nil {
			cleanupErr = errors.Join(cleanupErr, log.Close())
		}
		return nil, errors.Join(fmt.Errorf("assign backend process tree to job object: %w", err), cleanupErr)
	}

	var once sync.Once
	var result error
	return func() error {
		once.Do(func() {
			if closeErr := windows.CloseHandle(job); closeErr != nil {
				result = errors.Join(result, fmt.Errorf("close backend job object: %w", closeErr))
			}
			if waitErr := cmd.Wait(); waitErr != nil {
				var exitErr *exec.ExitError
				if !errors.As(waitErr, &exitErr) {
					result = errors.Join(result, fmt.Errorf("wait backend process: %w", waitErr))
				}
			}
			if log != nil {
				if closeErr := log.Close(); closeErr != nil {
					result = errors.Join(result, fmt.Errorf("close backend log: %w", closeErr))
				}
			}
		})
		return result
	}, nil
}

// attachKillOnCloseJob owns the process tree of an already-started child whose
// lifecycle (Start/Wait) is driven by someone else, such as the MCP command
// transport. It must not Wait, because that owner already does.
func attachKillOnCloseJob(cmd *exec.Cmd, log io.Closer) (func() error, error) {
	if cmd == nil || cmd.Process == nil {
		err := errors.New("backend process is not started")
		if log != nil {
			err = errors.Join(err, log.Close())
		}
		return nil, err
	}
	job, err := createKillOnCloseJob(cmd.Process.Pid)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("assign backend process tree to job object: %w", err), closeOptional(log))
	}
	var once sync.Once
	var result error
	return func() error {
		once.Do(func() {
			if closeErr := windows.CloseHandle(job); closeErr != nil {
				result = errors.Join(result, fmt.Errorf("close backend job object: %w", closeErr))
			}
			result = errors.Join(result, closeOptional(log))
		})
		return result
	}, nil
}

// reapStartedCommand terminates a child that an MCP transport already started
// but never handed back, so a failed handshake cannot leave an orphan holding
// the engine and its ports. It deliberately does not Wait: the transport's own
// reader goroutine is still attached to the stdout pipe, and calling Wait while
// a pipe reader is active is not safe. The killed child releases everything the
// backend owns; the process object itself is reaped when RR exits.
func reapStartedCommand(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	if err := cmd.Process.Kill(); err != nil {
		return fmt.Errorf("kill backend child after failed handshake: %w", err)
	}
	return nil
}

func createKillOnCloseJob(pid int) (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = windows.CloseHandle(job)
		}
	}()

	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	); err != nil {
		return 0, err
	}

	process, err := windows.OpenProcess(
		windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE,
		false,
		uint32(pid),
	)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(process)
	if err := windows.AssignProcessToJobObject(job, process); err != nil {
		return 0, err
	}
	ok = true
	return job, nil
}
