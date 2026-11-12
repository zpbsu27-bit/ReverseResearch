package targetidentity

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestCaptureFileBoundsAndContainerAllocationGuards(t *testing.T) {
	p := filepath.Join(t.TempDir(), "artifact")
	os.WriteFile(p, []byte("fixture"), 0o600)
	b, abs, sha, err := CaptureFile(p, 7)
	if err != nil || string(b) != "fixture" || !filepath.IsAbs(abs) || len(sha) != 64 {
		t.Fatalf("capture %q %q %q %v", b, abs, sha, err)
	}
	if _, _, _, err := CaptureFile(p, 6); err == nil {
		t.Fatal("accepted oversized capture")
	}
	pe := make([]byte, 128)
	copy(pe, "MZ")
	binary.LittleEndian.PutUint32(pe[60:64], 64)
	copy(pe[64:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(pe[70:72], 65535)
	if err := ValidateContainerBudget(bytes.NewReader(pe), int64(len(pe))); err == nil {
		t.Fatal("accepted oversized PE inventory")
	}
	elf := make([]byte, 128)
	copy(elf, "\x7fELF")
	elf[4] = 2
	elf[5] = 1
	binary.LittleEndian.PutUint64(elf[40:48], 64)
	binary.LittleEndian.PutUint64(elf[96:104], 1<<40)
	if err := ValidateContainerBudget(bytes.NewReader(elf), int64(len(elf))); err == nil {
		t.Fatal("accepted oversized extended ELF count")
	}
	elf = make([]byte, 128)
	copy(elf, "\x7fELF")
	elf[4] = 2
	elf[5] = 1
	binary.LittleEndian.PutUint16(elf[56:58], 5000)
	if err := ValidateContainerBudget(bytes.NewReader(elf), int64(len(elf))); err == nil {
		t.Fatal("accepted oversized ELF program count")
	}
	binary.LittleEndian.PutUint16(elf[56:58], 0xffff)
	binary.LittleEndian.PutUint64(elf[40:48], 64)
	binary.LittleEndian.PutUint32(elf[108:112], 1<<30)
	if err := ValidateContainerBudget(bytes.NewReader(elf), int64(len(elf))); err == nil {
		t.Fatal("accepted oversized PN_XNUM allocation")
	}
}

func TestCaptureFileRejectsFinalSymlink(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "source")
	if err := os.WriteFile(p, []byte("same"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(d, "link")
	if err := os.Symlink(p, link); err != nil {
		t.Skipf("host cannot create symlink: %v", err)
	}
	if _, _, _, err := CaptureFile(link, 10); err == nil {
		t.Fatal("final symlink admitted")
	}
}
