//go:build linux

package backend

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func hiddenCommand(path string, args ...string) *exec.Cmd { return exec.Command(path, args...) }

func xdbgHostError() error { return errors.New("x32/x64dbg backend requires a Windows host") }

func openProcessWatcher(cmd *exec.Cmd) (func() (bool, error), func() error, error) {
	if cmd == nil || cmd.Process == nil {
		return func() (bool, error) { return true, nil }, func() error { return nil }, nil
	}
	fd, err := unix.PidfdOpen(cmd.Process.Pid, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open backend pidfd readiness watcher: %w", err)
	}
	return func() (bool, error) {
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		_, err := unix.Poll(fds, 0)
		if errors.Is(err, unix.EINTR) {
			return true, nil
		}
		if fds[0].Revents&unix.POLLNVAL != 0 {
			return false, errors.New("backend pidfd watcher invalid")
		}
		return fds[0].Revents&(unix.POLLIN|unix.POLLHUP) == 0, err
	}, func() error { return unix.Close(fd) }, nil
}

// A native cgroup is an execution-tree owner, not a VM/security sandbox.
// No migration or numeric-PID kill fallback is used. The child is created in
// this exact group before exec; delegated cgroup v2 and clone3 are required.
type linuxBackendProcess struct {
	cmd               *exec.Cmd
	path              string
	identity          os.FileInfo
	dir, kill, events *os.File
	once              sync.Once
	result            error
}

func linuxBackendCgroupParent() (string, error) {
	body, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}
	if len(body) > 8192 {
		return "", errors.New("cgroup membership exceeds bound")
	}
	for _, line := range strings.Split(string(body), "\n") {
		if !strings.HasPrefix(line, "0::/") {
			continue
		}
		rel := strings.TrimPrefix(line, "0::/")
		for _, part := range strings.Split(rel, "/") {
			if part == "." || part == ".." {
				return "", errors.New("invalid cgroup membership path")
			}
		}
		return filepath.Join("/sys/fs/cgroup", rel), nil
	}
	return "", errors.New("Linux backend requires unified cgroup v2")
}

func prepareBackendProcess(cmd *exec.Cmd) (preparedBackendProcess, error) {
	if cmd == nil || cmd.Process != nil {
		return nil, errors.New("backend command must be prepared before Start")
	}
	if cmd.SysProcAttr != nil && cmd.SysProcAttr.UseCgroupFD {
		return nil, errors.New("backend command already has a cgroup owner")
	}
	parent, err := linuxBackendCgroupParent()
	if err != nil {
		return nil, err
	}
	s := &linuxBackendProcess{cmd: cmd}
	s.path, err = os.MkdirTemp(parent, "rr-backend-")
	if err != nil {
		return nil, fmt.Errorf("create delegated backend cgroup before Start: %w", err)
	}
	s.identity, err = os.Stat(s.path)
	if err != nil {
		return nil, errors.Join(err, os.Remove(s.path))
	}
	fail := func(cause error) (preparedBackendProcess, error) {
		return nil, errors.Join(cause, closeLinuxFile(s.events), closeLinuxFile(s.kill), closeLinuxFile(s.dir), s.removeOwnedGroup())
	}
	s.dir, err = os.Open(s.path)
	if err != nil {
		return fail(err)
	}
	var fs unix.Statfs_t
	if err := unix.Fstatfs(int(s.dir.Fd()), &fs); err != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return fail(errors.Join(errors.New("backend scope is not cgroup v2"), err))
	}
	// Open relative to the captured directory; later path replacement cannot
	// retarget a kill to another group.
	open := func(name string, flags int) (*os.File, error) {
		fd, err := unix.Openat(int(s.dir.Fd()), name, flags|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return nil, err
		}
		return os.NewFile(uintptr(fd), name), nil
	}
	s.kill, err = open("cgroup.kill", unix.O_WRONLY)
	if err != nil {
		return fail(fmt.Errorf("backend cgroup.kill unavailable: %w", err))
	}
	s.events, err = open("cgroup.events", unix.O_RDONLY)
	if err != nil {
		return fail(err)
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.UseCgroupFD, cmd.SysProcAttr.CgroupFD = true, int(s.dir.Fd())
	if cmd.WaitDelay == 0 {
		cmd.WaitDelay = 5 * time.Second
	}
	return s, nil
}

func closeLinuxFile(file *os.File) error {
	if file == nil {
		return nil
	}
	return file.Close()
}

func (s *linuxBackendProcess) removeOwnedGroup() error {
	current, err := os.Lstat(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !os.SameFile(s.identity, current) {
		return errors.New("backend cgroup path identity changed; removal refused")
	}
	return os.Remove(s.path) // No recursive removal, never a parent cgroup.
}

func (s *linuxBackendProcess) closeTree() error {
	s.once.Do(func() {
		_, s.result = s.kill.WriteString("1")
		if s.result == nil {
			until := time.Now().Add(5 * time.Second)
			for {
				if _, err := s.events.Seek(0, 0); err != nil {
					s.result = err
					break
				}
				body, err := io.ReadAll(io.LimitReader(s.events, 4097))
				if err != nil || len(body) > 4096 {
					s.result = errors.Join(errors.New("read bounded backend cgroup.events"), err)
					break
				}
				populated := -1
				for _, line := range strings.Split(string(body), "\n") {
					if line == "populated 0" {
						populated = 0
					}
					if line == "populated 1" {
						populated = 1
					}
				}
				if populated == 0 {
					break
				}
				if populated < 0 || time.Now().After(until) {
					s.result = errors.New("backend cgroup did not become unpopulated; cleanup unverified")
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
		}
		s.result = errors.Join(s.result, closeOptional(s.events), closeOptional(s.kill), closeOptional(s.dir))
		if s.result == nil {
			s.result = s.removeOwnedGroup()
		}
	})
	return s.result
}

func (s *linuxBackendProcess) abort(log io.Closer, started bool) error {
	return errors.Join(s.closeTree(), closeOptional(log))
}

func (s *linuxBackendProcess) claim(log io.Closer, ownWait bool) (func() error, error) {
	if s.cmd.Process == nil || s.cmd.SysProcAttr == nil || !s.cmd.SysProcAttr.UseCgroupFD || s.cmd.SysProcAttr.CgroupFD != int(s.dir.Fd()) {
		return nil, errors.Join(errors.New("backend command is not started in its prepared owner"), s.abort(log, s.cmd.Process != nil))
	}
	var once sync.Once
	var result error
	return func() error {
		once.Do(func() {
			result = s.closeTree()
			if result == nil && ownWait {
				if err := s.cmd.Wait(); err != nil {
					var exit *exec.ExitError
					if !errors.As(err, &exit) {
						result = errors.Join(result, err)
					}
				}
			}
			result = errors.Join(result, closeOptional(log))
		})
		return result
	}, nil
}
