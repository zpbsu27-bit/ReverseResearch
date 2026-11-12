//go:build windows

package securefile

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestRestrictFileAndDirRemainUsableByCurrentUser(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "private")
	if err := os.MkdirAll(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(path, []byte("secret"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := RestrictDir(dir); err != nil {
		t.Fatal(err)
	}
	if err := RestrictFile(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("updated"), 0o600); err != nil {
		t.Fatalf("current user lost write access: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("current user lost read access: %v", err)
	}
	if string(body) != "updated" {
		t.Fatalf("body=%q", body)
	}
	assertPrivateDACL(t, dir)
	assertPrivateDACL(t, path)
}

func assertPrivateDACL(t *testing.T, path string) {
	t.Helper()

	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{
		user.User.Sid.String(): true,
		"S-1-5-18":             true,
		"S-1-5-32-544":         true,
	}

	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if dacl == nil {
		t.Fatal("nil DACL is fully permissive")
	}
	if dacl.AceCount != 3 {
		t.Fatalf("ACE count=%d, want 3", dacl.AceCount)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		if !allowed[sid] {
			t.Fatalf("unexpected allowed SID %s on %s", sid, path)
		}
	}
}
