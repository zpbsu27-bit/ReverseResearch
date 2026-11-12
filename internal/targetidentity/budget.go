package targetidentity

import (
	"encoding/binary"
	"errors"
	"io"
)

// ValidateContainerBudget checks allocation-driving header counts. Container
// interpretation and returned layout remain with the existing identity owner.
func ValidateContainerBudget(r io.ReaderAt, size int64) error {
	read := func(off uint64, n int) ([]byte, bool) {
		if size < 0 || off > uint64(size) || uint64(n) > uint64(size)-off {
			return nil, false
		}
		b := make([]byte, n)
		_, err := r.ReadAt(b, int64(off))
		return b, err == nil
	}
	if size < 8 {
		return nil
	}
	h, ok := read(0, int(min(size, int64(64))))
	if !ok {
		return nil
	}
	if string(h[:2]) == "MZ" {
		if len(h) < 64 {
			return nil
		}
		p, ok := read(uint64(binary.LittleEndian.Uint32(h[60:64])), 24)
		if !ok || string(p[:4]) != "PE\x00\x00" {
			return nil
		}
		if binary.LittleEndian.Uint16(p[6:8]) > 4096 || binary.LittleEndian.Uint32(p[16:20]) > 1<<20 {
			return errors.New("PE metadata table count exceeds bounded profile")
		}
		ptr, count := uint64(binary.LittleEndian.Uint32(p[12:16])), uint64(binary.LittleEndian.Uint32(p[16:20]))
		if ptr != 0 {
			length, ok := read(ptr+count*18, 4)
			if !ok {
				return errors.New("COFF symbol/string table outside artifact")
			}
			n := uint64(binary.LittleEndian.Uint32(length))
			if n > 16<<20 || n > uint64(size) || ptr+count*18 > uint64(size)-n {
				return errors.New("COFF string table exceeds bounded profile")
			}
		}
	}
	if string(h[:4]) == "\x7fELF" {
		if len(h) < 52 {
			return nil
		}
		var order binary.ByteOrder = binary.LittleEndian
		if h[5] == 2 {
			order = binary.BigEndian
		} else if h[5] != 1 {
			return nil
		}
		var count uint64
		var programs uint64
		var off uint64
		var width int
		switch h[4] {
		case 1:
			count = uint64(order.Uint16(h[48:50]))
			programs = uint64(order.Uint16(h[44:46]))
			off = uint64(order.Uint32(h[32:36]))
			width = 40
		case 2:
			if len(h) < 64 {
				return nil
			}
			count = uint64(order.Uint16(h[60:62]))
			programs = uint64(order.Uint16(h[56:58]))
			off = order.Uint64(h[40:48])
			width = 64
		default:
			return nil
		}
		if (count == 0 || programs == 0xffff) && off != 0 {
			s, ok := read(off, width)
			if !ok {
				return nil
			}
			if h[4] == 1 {
				if count == 0 {
					count = uint64(order.Uint32(s[20:24]))
				}
				if programs == 0xffff {
					programs = uint64(order.Uint32(s[28:32]))
				}
			} else {
				if count == 0 {
					count = order.Uint64(s[32:40])
				}
				if programs == 0xffff {
					programs = uint64(order.Uint32(s[44:48]))
				}
			}
		}
		if count > 4096 {
			return errors.New("ELF section count exceeds bounded profile")
		}
		if programs > 4096 {
			return errors.New("ELF program count exceeds bounded profile")
		}
	}
	magic := binary.LittleEndian.Uint32(h[:4])
	var order binary.ByteOrder = binary.LittleEndian
	switch magic {
	case 0xcefaedfe, 0xcffaedfe:
		order = binary.BigEndian
		fallthrough
	case 0xfeedface, 0xfeedfacf:
		if len(h) < 28 {
			return nil
		}
		if order.Uint32(h[16:20]) > 4096 || uint64(order.Uint32(h[20:24])) > uint64(size) {
			return errors.New("Mach-O load table exceeds bounded profile")
		}
	case 0xbebafeca, 0xbfbafeca:
		if binary.BigEndian.Uint32(h[4:8]) > 64 {
			return errors.New("fat Mach-O architecture count exceeds bounded profile")
		}
	case 0xcafebabe, 0xcafebabf:
		if binary.LittleEndian.Uint32(h[4:8]) > 64 {
			return errors.New("fat Mach-O architecture count exceeds bounded profile")
		}
	}
	return nil
}
