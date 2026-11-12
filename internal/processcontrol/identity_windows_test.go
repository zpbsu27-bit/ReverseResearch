//go:build windows

package processcontrol

import (
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"
)

func TestInspectCurrentProcessHasStableRuntimeIdentity(t *testing.T) {
	got, err := Inspect(uint32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	if got.PID != uint32(os.Getpid()) || got.Key == "" || got.CreationUTC == "" {
		t.Fatalf("identity=%+v", got)
	}
	if got.Image.Path == "" || len(got.Image.SHA256) != 64 || got.Image.PE == nil {
		t.Fatalf("image identity=%+v", got.Image)
	}
	wantBits := 64
	if runtime.GOARCH == "386" {
		wantBits = 32
	}
	if got.Image.PE.Bits != wantBits {
		t.Fatalf("bits=%d want=%d", got.Image.PE.Bits, wantBits)
	}
	if got.MainModuleBase == 0 {
		t.Fatalf("missing main module base: %+v", got)
	}
	current, err := Validate(got)
	if err != nil || current.Key != got.Key {
		t.Fatalf("validate current=%+v err=%v", current, err)
	}
}

func TestValidateRejectsExitedProcessInstance(t *testing.T) {
	if os.Getenv("RR_PROCESS_IDENTITY_HELPER") == "1" {
		time.Sleep(30 * time.Second)
		return
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestValidateRejectsExitedProcessInstance$")
	cmd.Env = append(os.Environ(), "RR_PROCESS_IDENTITY_HELPER=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	identity, err := Inspect(uint32(cmd.Process.Pid))
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatal(err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("killed helper unexpectedly exited successfully")
	}
	if _, err := Validate(identity); err == nil {
		t.Fatal("exited process identity remained valid")
	}
}
