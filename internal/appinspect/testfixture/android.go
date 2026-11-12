package testfixture

import (
	"encoding/binary"
	"unicode/utf16"
)

func androidChunk(kind uint16, header int, content []byte) []byte {
	b := make([]byte, header)
	b = append(b, content...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	binary.LittleEndian.PutUint16(b, kind)
	binary.LittleEndian.PutUint16(b[2:], uint16(header))
	binary.LittleEndian.PutUint32(b[4:], uint32(len(b)))
	return b
}

// AndroidPool builds byte-level vectors independently of appinspect parsers.
func AndroidPool(texts []string, utf8Encoding bool) []byte {
	b := make([]byte, 28+4*len(texts))
	binary.LittleEndian.PutUint16(b, 1)
	binary.LittleEndian.PutUint16(b[2:], 28)
	binary.LittleEndian.PutUint32(b[8:], uint32(len(texts)))
	binary.LittleEndian.PutUint32(b[20:], uint32(len(b)))
	if utf8Encoding {
		binary.LittleEndian.PutUint32(b[16:], 0x100)
	}
	start := len(b)
	length8 := func(n int) []byte {
		if n < 128 {
			return []byte{byte(n)}
		}
		return []byte{byte(n>>8) | 0x80, byte(n)}
	}
	for i, s := range texts {
		binary.LittleEndian.PutUint32(b[28+i*4:], uint32(len(b)-start))
		units := utf16.Encode([]rune(s))
		if utf8Encoding {
			b = append(b, length8(len(units))...)
			b = append(b, length8(len(s))...)
			b = append(b, []byte(s)...)
			b = append(b, 0)
		} else {
			n := len(units)
			if n > 32767 {
				b = append(b, byte(n>>16), byte(n>>24)|0x80)
			}
			b = append(b, byte(n), byte(n>>8))
			for _, v := range units {
				b = append(b, byte(v), byte(v>>8))
			}
			b = append(b, 0, 0)
		}
	}
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	binary.LittleEndian.PutUint32(b[4:], uint32(len(b)))
	return b
}

func AndroidManifest() []byte {
	texts := []string{"manifest", "package", "rrfixture.demo", "application", "activity", "http://schemas.android.com/apk/res/android", "name", "rrfixture.demo.Main", "uses-permission", "android.permission.INTERNET", "android", "exported"}
	pool := AndroidPool(texts, true)
	resourceMap := androidChunk(0x180, 8, make([]byte, len(texts)*4))
	binary.LittleEndian.PutUint32(resourceMap[8+6*4:], 0x01010003)
	binary.LittleEndian.PutUint32(resourceMap[8+11*4:], 0x01010010)
	node := func(kind uint16, ext []byte) []byte {
		b := androidChunk(kind, 16, ext)
		binary.LittleEndian.PutUint32(b[8:], 1)
		binary.LittleEndian.PutUint32(b[12:], 0xffffffff)
		return b
	}
	pair := func(a, b uint32) []byte {
		v := make([]byte, 8)
		binary.LittleEndian.PutUint32(v, a)
		binary.LittleEndian.PutUint32(v[4:], b)
		return v
	}
	attr := func(ns, name, raw uint32, typ byte, data uint32) []byte {
		v := make([]byte, 20)
		binary.LittleEndian.PutUint32(v, ns)
		binary.LittleEndian.PutUint32(v[4:], name)
		binary.LittleEndian.PutUint32(v[8:], raw)
		binary.LittleEndian.PutUint16(v[12:], 8)
		v[15] = typ
		binary.LittleEndian.PutUint32(v[16:], data)
		return v
	}
	start := func(name uint32, attrs ...[]byte) []byte {
		ext := make([]byte, 20)
		binary.LittleEndian.PutUint32(ext, 0xffffffff)
		binary.LittleEndian.PutUint32(ext[4:], name)
		binary.LittleEndian.PutUint16(ext[8:], 20)
		binary.LittleEndian.PutUint16(ext[10:], 20)
		binary.LittleEndian.PutUint16(ext[12:], uint16(len(attrs)))
		for _, a := range attrs {
			ext = append(ext, a...)
		}
		return node(0x102, ext)
	}
	content := append([]byte{}, pool...)
	content = append(content, resourceMap...)
	content = append(content, node(0x100, pair(10, 5))...)
	content = append(content, start(0, attr(0xffffffff, 1, 2, 3, 2))...)
	content = append(content, start(8, attr(5, 6, 9, 3, 9))...)
	content = append(content, node(0x103, pair(0xffffffff, 8))...)
	content = append(content, start(3)...)
	content = append(content, start(4, attr(5, 6, 7, 3, 7), attr(5, 11, 0xffffffff, 0x12, 0))...)
	for _, n := range []uint32{4, 3, 0} {
		content = append(content, node(0x103, pair(0xffffffff, n))...)
	}
	content = append(content, node(0x101, pair(10, 5))...)
	return androidChunk(3, 8, content)
}

// AndroidResources contains one scalar and one bag configuration in package 7f.
func AndroidResources(indexEncoding uint8, compact bool) []byte {
	global := AndroidPool([]string{"hello"}, true)
	types := AndroidPool([]string{"string"}, false)
	keys := AndroidPool([]string{"title", "bag"}, true)
	spec := androidChunk(0x202, 16, make([]byte, 8))
	spec[8] = 1
	binary.LittleEndian.PutUint32(spec[12:], 2)
	entry0 := make([]byte, 16)
	binary.LittleEndian.PutUint16(entry0, 8)
	binary.LittleEndian.PutUint16(entry0[2:], 2)
	binary.LittleEndian.PutUint16(entry0[8:], 8)
	entry0[11] = 3
	if compact {
		entry0 = make([]byte, 8)
		binary.LittleEndian.PutUint16(entry0[2:], 0x030a)
	}
	entry1 := make([]byte, 28)
	binary.LittleEndian.PutUint16(entry1, 16)
	binary.LittleEndian.PutUint16(entry1[2:], 1)
	binary.LittleEndian.PutUint32(entry1[4:], 1)
	binary.LittleEndian.PutUint32(entry1[12:], 1)
	binary.LittleEndian.PutUint32(entry1[16:], 0x01000000)
	binary.LittleEndian.PutUint16(entry1[20:], 8)
	entry1[23] = 0x10
	binary.LittleEndian.PutUint32(entry1[24:], 7)
	width := 4
	if indexEncoding == 2 {
		width = 2
	}
	offsets := make([]byte, width*2)
	if indexEncoding == 1 {
		binary.LittleEndian.PutUint16(offsets[4:], 1)
		binary.LittleEndian.PutUint16(offsets[6:], uint16(len(entry0)/4))
	} else if indexEncoding == 2 {
		binary.LittleEndian.PutUint16(offsets[2:], uint16(len(entry0)/4))
	} else {
		binary.LittleEndian.PutUint32(offsets[4:], uint32(len(entry0)))
	}
	header := 28
	entriesStart := header + len(offsets)
	content := append(offsets, entry0...)
	content = append(content, entry1...)
	typ := androidChunk(0x201, header, content)
	typ[8] = 1
	typ[9] = indexEncoding
	binary.LittleEndian.PutUint32(typ[12:], 2)
	binary.LittleEndian.PutUint32(typ[16:], uint32(entriesStart))
	binary.LittleEndian.PutUint32(typ[20:], 8)
	packageContent := append([]byte{}, types...)
	packageContent = append(packageContent, keys...)
	packageContent = append(packageContent, spec...)
	packageContent = append(packageContent, typ...)
	pkg := androidChunk(0x200, 288, packageContent)
	binary.LittleEndian.PutUint32(pkg[8:], 0x7f)
	for i, v := range utf16.Encode([]rune("rrfixture.demo")) {
		binary.LittleEndian.PutUint16(pkg[12+i*2:], v)
	}
	binary.LittleEndian.PutUint32(pkg[268:], 288)
	binary.LittleEndian.PutUint32(pkg[276:], uint32(288+len(types)))
	b := androidChunk(2, 12, append(global, pkg...))
	binary.LittleEndian.PutUint32(b[8:], 1)
	return b
}
