package testfixture

import "encoding/binary"

// Independent compiler wire sentinels, used to assemble inert test containers.
func GoFramedModule(body []byte) []byte {
	prefix := []byte{0x30, 0x77, 0xaf, 0x0c, 0x92, 0x74, 0x08, 0x02, 0x41, 0xe1, 0xc1, 0x07, 0xe6, 0xd6, 0x18, 0xe6}
	suffix := []byte{0xf9, 0x32, 0x43, 0x31, 0x86, 0x18, 0x20, 0x72, 0, 0x82, 0x42, 0x10, 0x41, 0x16, 0xd8, 0xf2}
	return append(append(prefix, body...), suffix...)
}

func GoMetadataPE(record []byte, virtualSize uint32) []byte {
	b := make([]byte, 1024)
	copy(b, "MZ")
	binary.LittleEndian.PutUint32(b[60:], 128)
	copy(b[128:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(b[132:], 0x14c)
	binary.LittleEndian.PutUint16(b[134:], 1)
	binary.LittleEndian.PutUint16(b[148:], 224)
	h := b[152:]
	binary.LittleEndian.PutUint16(h, 0x10b)
	binary.LittleEndian.PutUint32(h[28:], 0x400000)
	binary.LittleEndian.PutUint32(h[32:], 0x1000)
	binary.LittleEndian.PutUint32(h[36:], 512)
	binary.LittleEndian.PutUint32(h[56:], 0x3000)
	binary.LittleEndian.PutUint32(h[60:], 512)
	binary.LittleEndian.PutUint32(h[92:], 16)
	s := b[376:416]
	copy(s, ".data")
	binary.LittleEndian.PutUint32(s[8:], virtualSize)
	binary.LittleEndian.PutUint32(s[12:], 0x1000)
	binary.LittleEndian.PutUint32(s[16:], 512)
	binary.LittleEndian.PutUint32(s[20:], 512)
	binary.LittleEndian.PutUint32(s[36:], 0xc0000040)
	copy(b[512:], record)
	return b
}
func GoInlineRecord(version, module []byte) []byte {
	b := make([]byte, 32)
	copy(b, []byte("\xff Go buildinf:"))
	b[14] = 4
	b[15] = 2
	b = binary.AppendUvarint(b, uint64(len(version)))
	b = append(b, version...)
	b = binary.AppendUvarint(b, uint64(len(module)))
	return append(b, module...)
}
func GoPointerRecord(zeroModule bool) []byte {
	b := make([]byte, 256)
	copy(b, []byte("\xff Go buildinf:"))
	b[14] = 4
	binary.LittleEndian.PutUint32(b[16:], 0x401040)
	modulePtr := uint32(0x401050)
	if zeroModule {
		modulePtr = 0x401200
	}
	binary.LittleEndian.PutUint32(b[20:], modulePtr)
	binary.LittleEndian.PutUint32(b[64:], 0x401060)
	binary.LittleEndian.PutUint32(b[68:], 9)
	copy(b[96:], "go-fixture")
	if !zeroModule {
		binary.LittleEndian.PutUint32(b[80:], 0x401078)
		binary.LittleEndian.PutUint32(b[84:], 3)
		copy(b[120:], []byte{0xff, 0, 0xfe})
	}
	return b
}
func GoMetadataELF(record []byte) []byte {
	record = append([]byte{}, record...)
	if len(record) >= 15 {
		record[14] = 8
	}
	size := max(512, 128+len(record))
	b := make([]byte, size)
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(b[16:], 2)
	binary.LittleEndian.PutUint16(b[18:], 62)
	binary.LittleEndian.PutUint32(b[20:], 1)
	binary.LittleEndian.PutUint64(b[32:], 64)
	binary.LittleEndian.PutUint16(b[52:], 64)
	binary.LittleEndian.PutUint16(b[54:], 56)
	binary.LittleEndian.PutUint16(b[56:], 1)
	binary.LittleEndian.PutUint32(b[64:], 1)
	binary.LittleEndian.PutUint32(b[68:], 6)
	binary.LittleEndian.PutUint64(b[72:], 128)
	binary.LittleEndian.PutUint64(b[80:], 0x401000)
	binary.LittleEndian.PutUint64(b[96:], uint64(size-128))
	binary.LittleEndian.PutUint64(b[104:], uint64(max(512, size-128)))
	copy(b[128:], record)
	return b
}
func GoMetadataMachO(record []byte) []byte {
	record = append([]byte{}, record...)
	if len(record) >= 15 {
		record[14] = 8
	}
	b := make([]byte, 512)
	binary.LittleEndian.PutUint32(b, 0xfeedfacf)
	binary.LittleEndian.PutUint32(b[4:], 0x1000007)
	binary.LittleEndian.PutUint32(b[8:], 3)
	binary.LittleEndian.PutUint32(b[12:], 2)
	binary.LittleEndian.PutUint32(b[16:], 1)
	binary.LittleEndian.PutUint32(b[20:], 152)
	l := b[32:184]
	binary.LittleEndian.PutUint32(l, 0x19)
	binary.LittleEndian.PutUint32(l[4:], 152)
	copy(l[8:24], "__DATA")
	binary.LittleEndian.PutUint64(l[24:], 0x100000000)
	binary.LittleEndian.PutUint64(l[32:], 0x1000)
	binary.LittleEndian.PutUint64(l[48:], 512)
	binary.LittleEndian.PutUint32(l[56:], 3)
	binary.LittleEndian.PutUint32(l[60:], 3)
	binary.LittleEndian.PutUint32(l[64:], 1)
	s := l[72:]
	copy(s, "__go_buildinfo")
	copy(s[16:], "__DATA")
	binary.LittleEndian.PutUint64(s[32:], 0x100000100)
	binary.LittleEndian.PutUint64(s[40:], uint64(len(record)))
	binary.LittleEndian.PutUint32(s[48:], 256)
	copy(b[256:], record)
	return b
}

func GoBigEndianPointerELF() []byte {
	b := make([]byte, 512)
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 2, 1})
	binary.BigEndian.PutUint16(b[16:], 2)
	binary.BigEndian.PutUint16(b[18:], 21)
	binary.BigEndian.PutUint32(b[20:], 1)
	binary.BigEndian.PutUint64(b[32:], 64)
	binary.BigEndian.PutUint16(b[52:], 64)
	binary.BigEndian.PutUint16(b[54:], 56)
	binary.BigEndian.PutUint16(b[56:], 1)
	binary.BigEndian.PutUint32(b[64:], 1)
	binary.BigEndian.PutUint32(b[68:], 6)
	binary.BigEndian.PutUint64(b[72:], 128)
	binary.BigEndian.PutUint64(b[80:], 0x401000)
	binary.BigEndian.PutUint64(b[96:], 384)
	binary.BigEndian.PutUint64(b[104:], 512)
	r := b[128:]
	copy(r, []byte("\xff Go buildinf:"))
	r[14] = 8
	r[15] = 1
	binary.BigEndian.PutUint64(r[16:], 0x401040)
	binary.BigEndian.PutUint64(r[24:], 0x401050)
	binary.BigEndian.PutUint64(r[64:], 0x401060)
	binary.BigEndian.PutUint64(r[72:], 9)
	binary.BigEndian.PutUint64(r[80:], 0x401078)
	binary.BigEndian.PutUint64(r[88:], 3)
	copy(r[96:], "go-fixtur")
	copy(r[120:], []byte{0xff, 0, 0xfe})
	return b
}
