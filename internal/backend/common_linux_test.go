//go:build linux

package backend

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Linux acceptance deliberately requires the real delegated kernel feature.
// A missing cgroup is a failed gate, not a skipped successful tree test.
func linuxScopeForTest(t *testing.T, cmd *exec.Cmd) *linuxBackendProcess {
	t.Helper()
	prepared, err := prepareBackendProcess(cmd)
	if err != nil {
		t.Fatal(err)
	}
	scope := prepared.(*linuxBackendProcess)
	t.Cleanup(func() {
		if err := scope.closeTree(); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})
	return scope
}

func TestLinuxBackendScopeRefusesReownedCommandAndCleansStartFailure(t *testing.T) {
	cmd := hiddenCommand("/rr-owned-nonexistent-fixture")
	scope := linuxScopeForTest(t, cmd)
	if !cmd.SysProcAttr.UseCgroupFD || cmd.SysProcAttr.CgroupFD != int(scope.dir.Fd()) {
		t.Fatal("owner not bound before Start")
	}
	if _, err := prepareBackendProcess(cmd); err == nil {
		t.Fatal("second owner accepted")
	}
	if err := cmd.Start(); err == nil {
		t.Fatal("nonexistent fixture unexpectedly started")
	}
	if err := scope.abort(nil, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(scope.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("empty failed-start cgroup remains")
	}
}

func TestLinuxBackendTreeClosesAfterSDKOwnedParentWait(t *testing.T) {
	root := t.TempDir()
	marker := filepath.Join(root, "child.txt")
	// The detached child outlives its parent and a process group/stdio close.
	cmd := hiddenCommand("/usr/bin/python3", "-c", `import os,sys,time
p=os.fork()
if p==0:
 os.setsid()
 open(sys.argv[1],'w').write(str(os.getpid()))
 time.sleep(90)
else:
 os._exit(0)
`, marker)
	scope := linuxScopeForTest(t, cmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	cleanup, err := scope.claim(nil, false)
	if err != nil {
		t.Fatal(err)
	}
	// Only the transport/test owns Wait. Cleanup must still close descendants.
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	var pid int
	until := time.Now().Add(3 * time.Second)
	for time.Now().Before(until) {
		b, err := os.ReadFile(marker)
		if err == nil {
			pid, _ = strconv.Atoi(strings.TrimSpace(string(b)))
			if pid > 0 {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if pid == 0 {
		t.Fatal("owned child did not publish its marker")
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		t.Fatal(err)
	}
	defer process.Release()
	alive, closeWatch, err := openProcessWatcher(&exec.Cmd{Process: process})
	if err != nil {
		t.Fatal(err)
	}
	defer closeWatch()
	if running, err := alive(); err != nil || !running {
		t.Fatal("detached child was not live")
	}
	foreign := hiddenCommand("/usr/bin/python3", "-c", "import time; time.sleep(90)")
	foreignScope := linuxScopeForTest(t, foreign)
	if err := foreign.Start(); err != nil {
		t.Fatal(err)
	}
	foreignCleanup, err := foreignScope.claim(nil, true)
	if err != nil {
		t.Fatal(err)
	}
	defer foreignCleanup()
	foreignAlive, closeForeign, err := openProcessWatcher(foreign)
	if err != nil {
		t.Fatal(err)
	}
	defer closeForeign()
	var wg sync.WaitGroup
	errorsOut := make(chan error, 16)
	for range 16 {
		wg.Add(1)
		go func() { defer wg.Done(); errorsOut <- cleanup() }()
	}
	wg.Wait()
	close(errorsOut)
	for err := range errorsOut {
		if err != nil {
			t.Fatal(err)
		}
	}
	if running, err := alive(); err != nil || running {
		t.Fatalf("owned descendant remained live: %v %v", running, err)
	}
	if running, err := foreignAlive(); err != nil || !running {
		t.Fatalf("foreign owned tree was touched: %v %v", running, err)
	}
	if _, err := os.Stat(scope.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("closed cgroup remains")
	}
}

func TestLinuxBackendReadinessRejectsExitedChildAndPreservesLogPrivacy(t *testing.T) {
	root := t.TempDir()
	log, err := openLog(root, "native.log")
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	info, err := os.Stat(filepath.Join(root, "evidence", "native.log"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("native log not private")
	}
	cmd := hiddenCommand("/usr/bin/python3", "-c", "pass")
	scope := linuxScopeForTest(t, cmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	cleanup, err := scope.claim(log, true)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	// Even a ready foreign port is not this exited backend's readiness.
	time.Sleep(100 * time.Millisecond)
	if err := waitTCP(context.Background(), listener.Addr().String(), time.Second, cmd); err == nil {
		t.Fatal("foreign ready port hid backend exit")
	}
	if err := xdbgHostError(); err == nil {
		t.Fatal("Windows-only debugger accepted Linux host")
	}
}
