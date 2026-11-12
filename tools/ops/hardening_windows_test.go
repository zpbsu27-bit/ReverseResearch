package ops

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func privateFixtureACL(path string, requireProtected bool) bool {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	control, _, err := sd.Control()
	if err != nil || (requireProtected && control&windows.SE_DACL_PROTECTED == 0) {
		return false
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return false
	}
	allowed := map[string]bool{user.User.Sid.String(): true, "S-1-5-18": true, "S-1-5-32-544": true}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount != 3 {
		return false
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(dacl, i, &ace) != nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Mask&0x1f01ff != 0x1f01ff {
			return false
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		if !allowed[sid] {
			return false
		}
		delete(allowed, sid)
	}
	return len(allowed) == 0
}

type aclFixtureObservation struct {
	RootPrivateBefore bool `json:"root_private_before"`
	RootPrivateAfter  bool `json:"root_private_after"`
	DescendantsOnly   bool `json:"descendants_only"`
	LinkItself        bool `json:"link_itself"`
}

func init() {
	fixtureACLReset = func() int {
		root, marker := os.Getenv("RR_TEST_ACL_ROOT"), os.Getenv("RR_TEST_ACL_MARKER")
		if root == "" || marker == "" {
			return 97
		}
		obs := aclFixtureObservation{RootPrivateBefore: privateFixtureACL(root, true)}
		if len(os.Args) > 1 {
			obs.DescendantsOnly = os.Args[1] == filepath.Join(root, "*")
		}
		for _, arg := range os.Args[2:] {
			obs.LinkItself = obs.LinkItself || strings.EqualFold(arg, "/L")
		}
		exit := 7 // A deterministic failed reset must retain Root's private DACL.
		if os.Getenv("RR_TEST_ACL_NATIVE") == "1" && obs.DescendantsOnly && obs.LinkItself {
			cmd := exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "icacls.exe"), os.Args[1:]...)
			output, err := cmd.CombinedOutput()
			exit = 0
			if err != nil {
				fmt.Fprintln(os.Stderr, string(output), err)
				exit = 8
			}
		}
		obs.RootPrivateAfter = privateFixtureACL(root, true)
		body, _ := json.Marshal(obs)
		if os.WriteFile(marker, body, 0o600) != nil {
			return 98
		}
		return exit
	}
}

func hardeningFixture(t *testing.T) (root, marker string, env []string) {
	t.Helper()
	base := t.TempDir()
	parent := filepath.Join(base, "wide parent")
	root, marker = filepath.Join(parent, "RR ACL 测试"), filepath.Join(base, "observation.json")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	// Reproduce the real incident's public parent using only an owned fixture.
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + user.User.Sid.String() + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;AU)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(parent, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	// Mark it as a project so unknown neighboring directories are not promoted
	// to important runtime paths. Contents are entirely owned test fixtures.
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(base, "bin")
	copyArtifactFixture(t, filepath.Join(bin, "icacls.exe"), false)
	env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "RR_TEST_ACL_ROOT="+root, "RR_TEST_ACL_MARKER="+marker)
	return
}

func readACLObservation(t *testing.T, marker string) aclFixtureObservation {
	t.Helper()
	body, err := os.ReadFile(marker)
	var observed aclFixtureObservation
	if err != nil || json.Unmarshal(body, &observed) != nil {
		t.Fatalf("missing native ACL observation: %s %v", body, err)
	}
	if !observed.RootPrivateBefore || !observed.RootPrivateAfter || !observed.DescendantsOnly || !observed.LinkItself {
		t.Fatalf("root or link boundary changed during reset: %+v", observed)
	}
	return observed
}

func TestHardeningNativeResetKeepsRootPrivateAndLinkTargetUnchanged(t *testing.T) {
	root, marker, env := hardeningFixture(t)
	child := filepath.Join(root, "protected-public-child.txt")
	if err := os.WriteFile(child, []byte("owned ACL fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	parentSD, err := windows.GetNamedSecurityInfo(filepath.Dir(root), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	publicDACL, _, err := parentSD.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(child, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, publicDACL, nil); err != nil {
		t.Fatal(err)
	}
	if privateFixtureACL(child, false) {
		t.Fatal("fixture child is not reproducing a protected public DACL")
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "junction")
	cmd := exec.Command("powershell.exe", "-NoProfile", "-Command", "New-Item -ItemType Junction -Path $env:RR_TEST_LINK -Target $env:RR_TEST_OUTSIDE | Out-Null")
	cmd.Env = append(os.Environ(), "RR_TEST_LINK="+link, "RR_TEST_OUTSIDE="+outside)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("create owned junction: %s %v", output, err)
	}
	before, err := windows.GetNamedSecurityInfo(outside, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	oldSDDL := before.String()
	source, _ := filepath.Abs("harden-local-install.ps1")
	cmd = exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", source, "-Action", "Apply", "-Root", root)
	cmd.Env = append(env, "RR_TEST_ACL_NATIVE=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("native descendant hardening: %s %v", output, err)
	}
	readACLObservation(t, marker)
	if !privateFixtureACL(child, false) {
		t.Fatal("full Apply left a protected public child unchanged")
	}
	after, err := windows.GetNamedSecurityInfo(outside, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil || after.String() != oldSDDL {
		t.Fatalf("hardening followed link to outside directory: %v", err)
	}
}

func TestPromotionHardeningFailureRetainsPrivateRootAndInstalledBytes(t *testing.T) {
	root, marker, env := hardeningFixture(t)
	installed := filepath.Join(root, "ReverseResearch-MCP.exe")
	candidate := filepath.Join(root, "dist", "candidate", "ReverseResearch-MCP.exe")
	copyArtifactFixture(t, installed, false)
	copyArtifactFixture(t, candidate, true)
	before, _ := os.ReadFile(installed)
	source, _ := filepath.Abs("manage-promotion.ps1")
	cmd := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", source, "-Action", "Promote", "-Root", root, "-Candidate", candidate, "-TaskName", "RR ACL failure "+filepath.Base(t.TempDir()))
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "local install hardening failed") {
		t.Fatalf("hardening failure did not stop publication: %s %v", output, err)
	}
	readACLObservation(t, marker)
	after, _ := os.ReadFile(installed)
	if !bytes.Equal(before, after) {
		t.Fatal("installed bytes changed before ACL preparation passed")
	}
	if _, err := os.Stat(filepath.Join(root, ".tmp", "promotion", "promotion.json")); !os.IsNotExist(err) {
		t.Fatalf("hardening failure published a receipt: %v", err)
	}
}

func TestHardeningRepairRestoresImportantPathsWithoutReset(t *testing.T) {
	root, marker, env := hardeningFixture(t)
	if privateFixtureACL(root, true) {
		t.Fatal("fixture is not reproducing an inherited public root")
	}
	source, _ := filepath.Abs("harden-local-install.ps1")
	cmd := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", source, "-Action", "Repair", "-Root", root)
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	if err != nil || !privateFixtureACL(root, true) {
		t.Fatalf("repair did not restore the canonical private root: %s %v", output, err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("repair invoked recursive reset: %v", err)
	}
}
