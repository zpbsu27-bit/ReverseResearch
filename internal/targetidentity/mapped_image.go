package targetidentity

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"errors"
	"math"
)

// MappedImage is an inert file snapshot view owned by the native container
// layer. It creates no file, target session, loaded-image claim or identity DB.
type ImageRegion struct {
	Name                                      string
	Address, FileOffset, FileSize, MemorySize uint64
}
type ImageSpan struct{ Address, Size uint64 }
type MappedImage struct {
	Format   string
	WordSize int
	Order    binary.ByteOrder
	Regions  []ImageRegion
	GoData   []ImageSpan
	body     []byte
}

func ParseMappedImage(body []byte) (*MappedImage, error) {
	if len(body) < 4 {
		return nil, errors.New("native image header is truncated")
	}
	if err := ValidateContainerBudget(bytes.NewReader(body), int64(len(body))); err != nil {
		return nil, err
	}
	m := &MappedImage{body: body, Order: binary.LittleEndian}
	add := func(r ImageRegion) error {
		if len(m.Regions) >= 4096 || r.Address > math.MaxUint64-r.MemorySize || r.Address > math.MaxUint64-r.FileSize || r.FileOffset > uint64(len(body)) || r.FileSize > uint64(len(body))-r.FileOffset || r.FileSize > r.MemorySize {
			return errors.New("native mapping range is invalid or exceeds profile")
		}
		m.Regions = append(m.Regions, r)
		return nil
	}
	switch {
	case bytes.Equal(body[:2], []byte("MZ")):
		f, err := pe.NewFile(bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		defer f.Close()
		m.Format = "pe"
		base := uint64(0)
		switch h := f.OptionalHeader.(type) {
		case *pe.OptionalHeader32:
			m.WordSize = 4
			base = uint64(h.ImageBase)
		case *pe.OptionalHeader64:
			m.WordSize = 8
			base = h.ImageBase
		default:
			return nil, errors.New("PE image lacks an admitted optional header")
		}
		for _, s := range f.Sections {
			if uint64(s.VirtualAddress) > math.MaxUint64-base {
				return nil, errors.New("PE image address overflows")
			}
			address := base + uint64(s.VirtualAddress)
			if err := add(ImageRegion{s.Name, address, uint64(s.Offset), uint64(s.Size), max(uint64(s.VirtualSize), uint64(s.Size))}); err != nil {
				return nil, err
			}
			if s.VirtualAddress != 0 && s.Size != 0 && s.Characteristics&^uint32(0x600000) == 0xc0000040 && len(m.GoData) == 0 {
				m.GoData = append(m.GoData, ImageSpan{address, uint64(s.Size)})
			}
		}
	case bytes.Equal(body[:4], []byte("\x7fELF")):
		f, err := elf.NewFile(bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		defer f.Close()
		m.Format = "elf"
		m.Order = f.ByteOrder
		switch f.Class {
		case elf.ELFCLASS32:
			m.WordSize = 4
		case elf.ELFCLASS64:
			m.WordSize = 8
		default:
			return nil, errors.New("unsupported ELF class")
		}
		for _, p := range f.Progs {
			if p.Type == elf.PT_LOAD {
				if err := add(ImageRegion{"PT_LOAD", p.Vaddr, p.Off, p.Filesz, p.Memsz}); err != nil {
					return nil, err
				}
			}
		}
		for _, s := range f.Sections {
			if s.Name == ".go.buildinfo" {
				m.GoData = append(m.GoData, ImageSpan{s.Addr, s.Size})
			}
		}
		if len(m.GoData) == 0 {
			for _, p := range f.Progs {
				if p.Type == elf.PT_LOAD && p.Flags == elf.PF_R|elf.PF_W && p.Filesz > 0 {
					m.GoData = append(m.GoData, ImageSpan{p.Vaddr, p.Filesz})
				}
			}
		}
	default:
		f, err := macho.NewFile(bytes.NewReader(body))
		if err != nil {
			return nil, errors.New("metadata mapping requires PE/ELF/thin Mach-O")
		}
		defer f.Close()
		m.Format = "mach-o"
		m.Order = f.ByteOrder
		m.WordSize = 4
		if f.Magic == macho.Magic64 {
			m.WordSize = 8
		}
		for _, l := range f.Loads {
			if s, ok := l.(*macho.Segment); ok && s.Name != "__PAGEZERO" {
				if err := add(ImageRegion{s.Name, s.Addr, s.Offset, s.Filesz, s.Memsz}); err != nil {
					return nil, err
				}
			}
		}
		for _, s := range f.Sections {
			if s.Name == "__go_buildinfo" {
				m.GoData = append(m.GoData, ImageSpan{s.Addr, s.Size})
			}
		}
	}
	if len(m.GoData) > 4096 {
		return nil, errors.New("Go data span count exceeds native profile")
	}
	return m, nil
}

func (m *MappedImage) FileBytes(address, size uint64) ([]byte, uint64, error) {
	if address > math.MaxUint64-size {
		return nil, 0, errors.New("virtual byte range overflows")
	}
	found := -1
	offset := uint64(0)
	for i, r := range m.Regions {
		if size > 0 && address < r.Address+r.FileSize && r.Address < address+size &&
			!(address >= r.Address && address-r.Address <= r.FileSize && size <= r.FileSize-(address-r.Address)) {
			return nil, 0, errors.New("virtual bytes cross an ambiguous partial file mapping")
		}
		if address >= r.Address && address-r.Address <= r.FileSize && size <= r.FileSize-(address-r.Address) {
			if found != -1 {
				return nil, 0, errors.New("virtual bytes have ambiguous file mappings")
			}
			found = i
			offset = r.FileOffset + address - r.Address
		}
	}
	if found == -1 {
		return nil, 0, errors.New("virtual bytes are not completely file backed")
	}
	return m.body[offset : offset+size], offset, nil
}

func (m *MappedImage) ZeroFill(address, size uint64) bool {
	if address > math.MaxUint64-size {
		return false
	}
	found := false
	for _, r := range m.Regions {
		if size > 0 && address < r.Address+r.FileSize && r.Address < address+size {
			return false
		}
		if address >= r.Address && address-r.Address <= r.MemorySize && size <= r.MemorySize-(address-r.Address) {
			if found || address-r.Address < r.FileSize {
				return false
			}
			found = true
		}
	}
	return found
}
