package targetidentity

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInspectSmokePE(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "testdata", "mcp-smoke.exe"))
	got, err := Inspect(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Path == "" || got.SHA256 == "" || got.Size <= 0 {
		t.Fatalf("incomplete identity: %+v", got)
	}
	if len(got.SHA256) != 64 {
		t.Fatalf("sha256 length=%d want=64", len(got.SHA256))
	}
	if got.PE == nil {
		t.Fatalf("expected PE identity: %+v", got)
	}
	if got.PE.Bits != 32 || !strings.EqualFold(got.PE.Machine, "i386") {
		t.Fatalf("PE identity=%+v want 32-bit i386", got.PE)
	}
	if got.PE.EntryPointRVA == 0 {
		t.Fatalf("entry point missing: %+v", got.PE)
	}
	if len(got.PE.Sections) == 0 {
		t.Fatalf("sections missing: %+v", got.PE)
	}
}

func TestCompareUsesContentIdentity(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "testdata", "mcp-smoke.exe"))
	got, err := Compare(path, path)
	if err != nil {
		t.Fatal(err)
	}
	if !got.SameContent || got.Left.SHA256 != got.Right.SHA256 {
		t.Fatalf("same file compare=%+v", got)
	}
}

func TestInspectELF64Identity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sample.elf")
	body := minimalELF64(binary.LittleEndian, 62, 0x401000)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Inspect(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Format != "elf" || got.ELF == nil {
		t.Fatalf("identity=%+v", got)
	}
	if got.ELF.Class != "ELFCLASS64" || got.ELF.Machine != "EM_X86_64" || got.ELF.Entry != 0x401000 {
		t.Fatalf("ELF identity=%+v", got.ELF)
	}
	if got.PE != nil {
		t.Fatalf("ELF target unexpectedly has PE identity: %+v", got.PE)
	}
}

func TestCompareELFArchitecture(t *testing.T) {
	root := t.TempDir()
	left := filepath.Join(root, "left.elf")
	right := filepath.Join(root, "right.elf")
	if err := os.WriteFile(left, minimalELF64(binary.LittleEndian, 62, 0x401000), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(right, minimalELF64(binary.LittleEndian, 62, 0x402000), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Compare(left, right)
	if err != nil {
		t.Fatal(err)
	}
	if got.SameContent || !got.SameArchitecture || got.SamePEArch {
		t.Fatalf("ELF compare=%+v", got)
	}
}

func TestInspectMachO64Identity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sample.macho")
	body := minimalMachO64(binary.LittleEndian, 0x0100000c, 0, 2)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Inspect(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Format != "mach-o" || got.MachO == nil || got.MachO.Fat {
		t.Fatalf("identity=%+v", got)
	}
	if len(got.MachO.Architectures) != 1 || got.MachO.Architectures[0].CPU != "CpuArm64" {
		t.Fatalf("Mach-O identity=%+v", got.MachO)
	}
}

func TestCompareMachOArchitecture(t *testing.T) {
	root := t.TempDir()
	left := filepath.Join(root, "left.macho")
	right := filepath.Join(root, "right.macho")
	if err := os.WriteFile(left, minimalMachO64(binary.LittleEndian, 0x0100000c, 0, 2), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(right, minimalMachO64(binary.LittleEndian, 0x0100000c, 0, 6), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Compare(left, right)
	if err != nil {
		t.Fatal(err)
	}
	if got.SameContent || !got.SameArchitecture || got.SamePEArch {
		t.Fatalf("Mach-O compare=%+v", got)
	}
}

func minimalMachO64(order binary.ByteOrder, cpu, subcpu, fileType uint32) []byte {
	body := make([]byte, 32)
	order.PutUint32(body[0:4], 0xfeedfacf)
	order.PutUint32(body[4:8], cpu)
	order.PutUint32(body[8:12], subcpu)
	order.PutUint32(body[12:16], fileType)
	order.PutUint32(body[16:20], 0)
	order.PutUint32(body[20:24], 0)
	order.PutUint32(body[24:28], 0)
	order.PutUint32(body[28:32], 0)
	return body
}

func minimalELF64(order binary.ByteOrder, machine uint16, entry uint64) []byte {
	body := make([]byte, 64)
	copy(body[:4], []byte{0x7f, 'E', 'L', 'F'})
	body[4] = 2
	body[5] = 1
	body[6] = 1
	body[7] = 0
	order.PutUint16(body[16:18], 2)
	order.PutUint16(body[18:20], machine)
	order.PutUint32(body[20:24], 1)
	order.PutUint64(body[24:32], entry)
	order.PutUint16(body[52:54], 64)
	order.PutUint16(body[54:56], 56)
	order.PutUint16(body[56:58], 0)
	order.PutUint16(body[58:60], 64)
	order.PutUint16(body[60:62], 0)
	order.PutUint16(body[62:64], 0)
	return body
}

func TestInspectBoundedRejectsOversizedTarget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversized.bin")
	if err := os.WriteFile(path, make([]byte, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := InspectBounded(path, 1024)
	if !errors.Is(err, ErrTargetTooLarge) {
		t.Fatalf("InspectBounded error = %v, want ErrTargetTooLarge", err)
	}
}

func TestInspectContextHonorsCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cancel.bin")
	if err := os.WriteFile(path, make([]byte, 1<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := InspectContext(ctx, path)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("InspectContext error = %v, want context canceled", err)
	}
}
