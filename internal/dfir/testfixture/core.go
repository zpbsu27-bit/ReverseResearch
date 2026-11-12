// Package testfixture builds inert ELF core snapshots; no test crashes or
// attaches to a live process to obtain these vectors.
package testfixture

import "encoding/binary"

func note(owner []byte, kind uint32, desc []byte) []byte {
	b := binary.LittleEndian.AppendUint32(nil, uint32(len(owner)))
	b = binary.LittleEndian.AppendUint32(b, uint32(len(desc)))
	b = binary.LittleEndian.AppendUint32(b, kind)
	b = append(b, owner...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	b = append(b, desc...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}
func Core() []byte {
	var notes []byte
	for i := 0; i < 2; i++ {
		desc := make([]byte, 336)
		binary.LittleEndian.PutUint16(desc[12:14], 11)
		binary.LittleEndian.PutUint32(desc[32:36], uint32(4242+i))
		for j := 0; j < 27; j++ {
			binary.LittleEndian.PutUint64(desc[112+j*8:], 0xffff000000000000+uint64(i*100+j))
		}
		notes = append(notes, note([]byte("CORE\x00"), 1, desc)...)
	}
	signal := make([]byte, 128)
	binary.LittleEndian.PutUint32(signal, 11)
	binary.LittleEndian.PutUint32(signal[8:], 2)
	binary.LittleEndian.PutUint64(signal[16:], 0xfffff123456789ab)
	notes = append(notes, note([]byte("CORE\x00"), 0x53494749, signal)...)
	notes = append(notes, note([]byte{0xff, 0}, 0x87654321, []byte{1, 2, 3})...)
	b := make([]byte, 176)
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0, 0})
	binary.LittleEndian.PutUint16(b[16:], 4)
	binary.LittleEndian.PutUint16(b[18:], 62)
	binary.LittleEndian.PutUint32(b[20:], 1)
	binary.LittleEndian.PutUint64(b[32:], 64)
	binary.LittleEndian.PutUint16(b[52:], 64)
	binary.LittleEndian.PutUint16(b[54:], 56)
	binary.LittleEndian.PutUint16(b[56:], 2)
	binary.LittleEndian.PutUint32(b[64:], 4)
	binary.LittleEndian.PutUint64(b[72:], 176)
	binary.LittleEndian.PutUint64(b[96:], uint64(len(notes)))
	binary.LittleEndian.PutUint64(b[104:], uint64(len(notes)))
	binary.LittleEndian.PutUint64(b[112:], 4)
	binary.LittleEndian.PutUint32(b[120:], 1)
	binary.LittleEndian.PutUint32(b[124:], 6)
	binary.LittleEndian.PutUint64(b[128:], uint64(176+len(notes)))
	binary.LittleEndian.PutUint64(b[136:], 0xffff000000001000)
	binary.LittleEndian.PutUint64(b[152:], 4)
	binary.LittleEndian.PutUint64(b[160:], 0x1000)
	binary.LittleEndian.PutUint64(b[168:], 0x1000)
	b = append(b, notes...)
	return append(b, 0xde, 0xad, 0xbe, 0xef)
}
