package targetidentity

import (
	"context"
	"crypto/sha256"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type Identity struct {
	ID          string         `json:"id"`
	Path        string         `json:"path"`
	SHA256      string         `json:"sha256"`
	Size        int64          `json:"size"`
	ModifiedUTC string         `json:"modified_utc"`
	Format      string         `json:"format"`
	PE          *PEIdentity    `json:"pe,omitempty"`
	ELF         *ELFIdentity   `json:"elf,omitempty"`
	MachO       *MachOIdentity `json:"macho,omitempty"`
}

type ELFIdentity struct {
	Class    string       `json:"class"`
	Data     string       `json:"data"`
	Machine  string       `json:"machine"`
	Type     string       `json:"type"`
	OSABI    string       `json:"osabi"`
	Entry    uint64       `json:"entry"`
	BuildID  string       `json:"build_id,omitempty"`
	Sections []ELFSection `json:"sections,omitempty"`
}

type ELFSection struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Flags  string `json:"flags"`
	Addr   uint64 `json:"addr"`
	Offset uint64 `json:"offset"`
	Size   uint64 `json:"size"`
}

type MachOIdentity struct {
	Fat           bool        `json:"fat"`
	Architectures []MachOArch `json:"architectures"`
}

type MachOArch struct {
	CPU      string         `json:"cpu"`
	SubCPU   uint32         `json:"sub_cpu"`
	Type     string         `json:"type"`
	Flags    uint32         `json:"flags"`
	Sections []MachOSection `json:"sections,omitempty"`
}

type MachOSection struct {
	Name    string `json:"name"`
	Segment string `json:"segment"`
	Addr    uint64 `json:"addr"`
	Size    uint64 `json:"size"`
	Offset  uint32 `json:"offset"`
}

type PEIdentity struct {
	Machine       string    `json:"machine"`
	Bits          int       `json:"bits"`
	TimeDateStamp uint32    `json:"time_date_stamp"`
	ImageBase     uint64    `json:"image_base"`
	EntryPointRVA uint32    `json:"entry_point_rva"`
	Subsystem     uint16    `json:"subsystem"`
	Sections      []Section `json:"sections"`
}

type Section struct {
	Name            string `json:"name"`
	VirtualAddress  uint32 `json:"virtual_address"`
	VirtualSize     uint32 `json:"virtual_size"`
	RawSize         uint32 `json:"raw_size"`
	RawOffset       uint32 `json:"raw_offset"`
	Characteristics uint32 `json:"characteristics"`
}

type Comparison struct {
	Left             Identity `json:"left"`
	Right            Identity `json:"right"`
	SameContent      bool     `json:"same_content"`
	SizeDelta        int64    `json:"size_delta"`
	SamePEArch       bool     `json:"same_pe_arch"`
	SameArchitecture bool     `json:"same_architecture"`
}

var ErrTargetTooLarge = errors.New("target exceeds bounded identity size")

func Inspect(path string) (Identity, error) {
	return InspectContext(context.Background(), path)
}

func InspectContext(ctx context.Context, path string) (Identity, error) {
	return inspectContext(ctx, path, 0, nil)
}

func InspectBounded(path string, maxBytes int64) (Identity, error) {
	return InspectBoundedContext(context.Background(), path, maxBytes)
}

func InspectBoundedContext(ctx context.Context, path string, maxBytes int64) (Identity, error) {
	if maxBytes <= 0 {
		return Identity{}, errors.New("max_bytes must be greater than zero")
	}
	return inspectContext(ctx, path, maxBytes, nil)
}

// inspect keeps one open file handle for hashing and binary parsing. The hook is
// a test seam used to deterministically exercise path replacement after hashing.
func inspect(path string, afterHash func()) (Identity, error) {
	return inspectContext(context.Background(), path, 0, afterHash)
}

func inspectContext(ctx context.Context, path string, maxBytes int64, afterHash func()) (Identity, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	resolved, err := resolveFile(path)
	if err != nil {
		return Identity{}, err
	}
	file, err := os.Open(resolved)
	if err != nil {
		return Identity{}, fmt.Errorf("open target: %w", err)
	}
	defer file.Close()

	before, err := file.Stat()
	if err != nil {
		return Identity{}, fmt.Errorf("stat open target: %w", err)
	}
	if !before.Mode().IsRegular() {
		return Identity{}, fmt.Errorf("target is not a regular file: %s", resolved)
	}
	if maxBytes > 0 && before.Size() > maxBytes {
		return Identity{}, fmt.Errorf("%w: size=%d max=%d", ErrTargetTooLarge, before.Size(), maxBytes)
	}

	hash := sha256.New()
	var hashReader io.Reader = contextReader{ctx: ctx, reader: file}
	if maxBytes > 0 {
		hashReader = io.LimitReader(hashReader, maxBytes+1)
	}
	if n, err := io.Copy(hash, hashReader); err != nil {
		return Identity{}, fmt.Errorf("hash target: %w", err)
	} else if maxBytes > 0 && n > maxBytes {
		return Identity{}, ErrTargetTooLarge
	}
	if afterHash != nil {
		afterHash()
	}
	if err := validateCurrentFile(resolved, file, before); err != nil {
		return Identity{}, err
	}
	if maxBytes > 0 {
		if err := ValidateContainerBudget(file, before.Size()); err != nil {
			return Identity{}, err
		}
	}

	digest := hex.EncodeToString(hash.Sum(nil))
	identity := Identity{
		ID:          "sha256:" + digest,
		Path:        resolved,
		SHA256:      digest,
		Size:        before.Size(),
		ModifiedUTC: before.ModTime().UTC().Format(time.RFC3339Nano),
		Format:      "binary",
	}

	peFile, peErr := pe.NewFile(file)
	if peErr == nil {
		peID := &PEIdentity{
			Machine:       machineName(peFile.FileHeader.Machine),
			TimeDateStamp: peFile.FileHeader.TimeDateStamp,
			Sections:      make([]Section, 0, len(peFile.Sections)),
		}
		switch header := peFile.OptionalHeader.(type) {
		case *pe.OptionalHeader32:
			peID.Bits = 32
			peID.ImageBase = uint64(header.ImageBase)
			peID.EntryPointRVA = header.AddressOfEntryPoint
			peID.Subsystem = header.Subsystem
		case *pe.OptionalHeader64:
			peID.Bits = 64
			peID.ImageBase = header.ImageBase
			peID.EntryPointRVA = header.AddressOfEntryPoint
			peID.Subsystem = header.Subsystem
		default:
			if err := validateCurrentFile(resolved, file, before); err != nil {
				return Identity{}, err
			}
			return identity, nil
		}
		for _, section := range peFile.Sections {
			peID.Sections = append(peID.Sections, Section{
				Name:            section.Name,
				VirtualAddress:  section.VirtualAddress,
				VirtualSize:     section.VirtualSize,
				RawSize:         section.Size,
				RawOffset:       section.Offset,
				Characteristics: section.Characteristics,
			})
		}
		if err := validateCurrentFile(resolved, file, before); err != nil {
			return Identity{}, err
		}
		identity.Format = "pe"
		identity.PE = peID
		return identity, nil
	}

	elfFile, elfErr := elf.NewFile(file)
	if elfErr != nil {
		if thin, machErr := macho.NewFile(file); machErr == nil {
			identity.Format = "mach-o"
			identity.MachO = &MachOIdentity{Architectures: []MachOArch{machOArch(thin)}}
			if err := validateCurrentFile(resolved, file, before); err != nil {
				return Identity{}, err
			}
			return identity, nil
		}
		if fat, fatErr := macho.NewFatFile(file); fatErr == nil {
			mid := &MachOIdentity{Fat: true, Architectures: make([]MachOArch, 0, len(fat.Arches))}
			for _, arch := range fat.Arches {
				mid.Architectures = append(mid.Architectures, machOArch(arch.File))
			}
			sort.Slice(mid.Architectures, func(i, j int) bool {
				if mid.Architectures[i].CPU != mid.Architectures[j].CPU {
					return mid.Architectures[i].CPU < mid.Architectures[j].CPU
				}
				return mid.Architectures[i].SubCPU < mid.Architectures[j].SubCPU
			})
			identity.Format = "mach-o"
			identity.MachO = mid
			if err := validateCurrentFile(resolved, file, before); err != nil {
				return Identity{}, err
			}
			return identity, nil
		}
		if err := validateCurrentFile(resolved, file, before); err != nil {
			return Identity{}, err
		}
		return identity, nil
	}
	elfID := &ELFIdentity{
		Class: elfFile.Class.String(), Data: elfFile.Data.String(), Machine: elfFile.Machine.String(),
		Type: elfFile.Type.String(), OSABI: elfFile.OSABI.String(), Entry: elfFile.Entry,
		Sections: make([]ELFSection, 0, len(elfFile.Sections)),
	}
	for _, section := range elfFile.Sections {
		elfID.Sections = append(elfID.Sections, ELFSection{
			Name: section.Name, Type: section.Type.String(), Flags: section.Flags.String(),
			Addr: section.Addr, Offset: section.Offset, Size: section.Size,
		})
		if section.Name == ".note.gnu.build-id" && section.Size <= 65536 {
			if body, err := section.Data(); err == nil {
				if buildID := parseGNUBuildID(body, elfFile.ByteOrder); buildID != "" {
					elfID.BuildID = buildID
				}
			}
		}
	}
	if err := validateCurrentFile(resolved, file, before); err != nil {
		return Identity{}, err
	}
	identity.Format = "elf"
	identity.ELF = elfID
	return identity, nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	select {
	case <-r.ctx.Done():
		return 0, r.ctx.Err()
	default:
		return r.reader.Read(p)
	}
}

func validateCurrentFile(path string, file *os.File, before os.FileInfo) error {
	after, err := file.Stat()
	if err != nil {
		return fmt.Errorf("restat open target: %w", err)
	}
	current, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("target changed during identity inspection: %w", err)
	}
	if !os.SameFile(before, after) || !os.SameFile(after, current) ||
		before.Size() != after.Size() || after.Size() != current.Size() ||
		!before.ModTime().Equal(after.ModTime()) || !after.ModTime().Equal(current.ModTime()) {
		return errors.New("target changed during identity inspection")
	}
	return nil
}

func Compare(leftPath, rightPath string) (Comparison, error) {
	return CompareContext(context.Background(), leftPath, rightPath)
}

func CompareContext(ctx context.Context, leftPath, rightPath string) (Comparison, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	left, err := InspectContext(ctx, leftPath)
	if err != nil {
		return Comparison{}, fmt.Errorf("inspect left target: %w", err)
	}
	right, err := InspectContext(ctx, rightPath)
	if err != nil {
		return Comparison{}, fmt.Errorf("inspect right target: %w", err)
	}
	samePEArch := false
	sameArchitecture := false
	if left.PE != nil && right.PE != nil {
		samePEArch = left.PE.Bits == right.PE.Bits && left.PE.Machine == right.PE.Machine
		sameArchitecture = samePEArch
	}
	if left.ELF != nil && right.ELF != nil {
		sameArchitecture = left.ELF.Class == right.ELF.Class && left.ELF.Machine == right.ELF.Machine && left.ELF.Data == right.ELF.Data
	}
	if left.MachO != nil && right.MachO != nil {
		sameArchitecture = machOArchitectureKey(left.MachO) == machOArchitectureKey(right.MachO)
	}
	return Comparison{
		Left: left, Right: right, SameContent: left.SHA256 == right.SHA256,
		SizeDelta: right.Size - left.Size, SamePEArch: samePEArch, SameArchitecture: sameArchitecture,
	}, nil
}

func machOArch(file *macho.File) MachOArch {
	arch := MachOArch{
		CPU: file.Cpu.String(), SubCPU: uint32(file.SubCpu), Type: file.Type.String(),
		Flags: uint32(file.Flags), Sections: make([]MachOSection, 0, len(file.Sections)),
	}
	for _, section := range file.Sections {
		arch.Sections = append(arch.Sections, MachOSection{
			Name: section.Name, Segment: section.Seg, Addr: section.Addr,
			Size: section.Size, Offset: section.Offset,
		})
	}
	return arch
}

func machOArchitectureKey(identity *MachOIdentity) string {
	if identity == nil {
		return ""
	}
	parts := make([]string, 0, len(identity.Architectures))
	for _, arch := range identity.Architectures {
		parts = append(parts, fmt.Sprintf("%s/%d", arch.CPU, arch.SubCPU))
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func parseGNUBuildID(body []byte, order binary.ByteOrder) string {
	if len(body) < 12 || order == nil {
		return ""
	}
	namesz := int(order.Uint32(body[0:4]))
	descsz := int(order.Uint32(body[4:8]))
	noteType := order.Uint32(body[8:12])
	if namesz <= 0 || descsz <= 0 || noteType != 3 {
		return ""
	}
	nameStart := 12
	nameEnd := nameStart + namesz
	if nameEnd > len(body) {
		return ""
	}
	descStart := (nameEnd + 3) &^ 3
	descEnd := descStart + descsz
	if descStart < 0 || descEnd > len(body) || descStart > descEnd {
		return ""
	}
	name := strings.TrimRight(string(body[nameStart:nameEnd]), "\x00")
	if name != "GNU" {
		return ""
	}
	return hex.EncodeToString(body[descStart:descEnd])
}

func resolveFile(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("target path is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve target path: %w", err)
	}
	absolute = filepath.Clean(absolute)
	if _, err := os.Stat(absolute); err != nil {
		return "", fmt.Errorf("target path %s: %w", absolute, err)
	}
	if resolved, err := filepath.EvalSymlinks(absolute); err == nil {
		absolute = resolved
	}
	return absolute, nil
}

func machineName(machine uint16) string {
	switch machine {
	case 0x014c:
		return "i386"
	case 0x8664:
		return "amd64"
	case 0xaa64:
		return "arm64"
	case 0x01c0:
		return "arm"
	default:
		return fmt.Sprintf("0x%04x", machine)
	}
}
