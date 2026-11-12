package testfixture

import (
	"crypto/sha1"
	"encoding/binary"
	"hash/adler32"
	"unicode/utf16"
)

// DEX is an independently encoded, inert metadata vector, not a runnable app.
// One class defines constructor/value/nativeProbe; Object::referencedOnly is
// only a reference. The heap includes encoded NUL, a surrogate pair and a lone
// surrogate (allowed in DEX strings, but not valid as a type/member name).
func DEX() []byte {
	return DEXWithInstructions([]uint16{0x7012, 0x000f}, 1, 0)
}

// DEXWithInstructions changes only the independently encoded value-method
// code item. It still has no executable Android entry point.
func DEXWithInstructions(code []uint16, registers, outgoing uint16) []byte {
	strings := []string{"<init>", "Example.java", "I", "Ldemo/Example;", "Ljava/lang/Object;", "V", "nativeProbe", "referencedOnly", "value", "zero\x00😀"}
	const stringCount = 11
	const stringIDs = 112
	const typeIDs = stringIDs + stringCount*4
	const protoIDs = typeIDs + 4*4
	const fieldIDs = protoIDs + 2*12
	const methodIDs = fieldIDs + 8
	const classDefs = methodIDs + 4*8
	const dataStart = classDefs + 32
	b := make([]byte, dataStart)
	put16 := func(at int, v uint16) { binary.LittleEndian.PutUint16(b[at:], v) }
	put32 := func(at int, v uint32) { binary.LittleEndian.PutUint32(b[at:], v) }
	copy(b, "dex\n035\x00")
	put32(36, 112)
	put32(40, 0x12345678)
	for i, v := range [][2]uint32{{stringCount, stringIDs}, {4, typeIDs}, {2, protoIDs}, {1, fieldIDs}, {4, methodIDs}, {1, classDefs}} {
		put32(56+i*8, v[0])
		put32(60+i*8, v[1])
	}
	appendULEB := func(dst []byte, v uint32) []byte {
		for {
			q := byte(v & 127)
			v >>= 7
			if v != 0 {
				q |= 128
			}
			dst = append(dst, q)
			if v == 0 {
				return dst
			}
		}
	}
	for i := 0; i < stringCount; i++ {
		put32(stringIDs+i*4, uint32(len(b)))
		var units []uint16
		if i == 10 {
			units = []uint16{0xd800}
		} else {
			units = utf16.Encode([]rune(strings[i]))
		}
		b = appendULEB(b, uint32(len(units)))
		for _, v := range units {
			switch {
			case v > 0 && v < 128:
				b = append(b, byte(v))
			case v < 2048:
				b = append(b, 0xc0|byte(v>>6), 0x80|byte(v&63))
			default:
				b = append(b, 0xe0|byte(v>>12), 0x80|byte(v>>6&63), 0x80|byte(v&63))
			}
		}
		b = append(b, 0)
	}
	classData := len(b)
	b = append(b, make([]byte, 32)...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	ctorCode := len(b)
	b = append(b, make([]byte, 16)...)
	b = append(b, 0x0e, 0x00)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	valueCode := len(b)
	b = append(b, make([]byte, 16)...)
	for _, unit := range code {
		b = append(b, byte(unit), byte(unit>>8))
	}
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	mapOff := len(b)
	items := [][3]uint32{{0, 1, 0}, {1, stringCount, stringIDs}, {2, 4, typeIDs}, {3, 2, protoIDs}, {4, 1, fieldIDs}, {5, 4, methodIDs}, {6, 1, classDefs}, {0x2002, stringCount, dataStart}, {0x2000, 1, uint32(classData)}, {0x2001, 2, uint32(ctorCode)}, {0x1000, 1, uint32(mapOff)}}
	b = append(b, make([]byte, 4+12*len(items))...)
	put32(32, uint32(len(b)))
	put32(52, uint32(mapOff))
	put32(104, uint32(len(b)-dataStart))
	put32(108, dataStart)
	for i, v := range []uint32{2, 3, 4, 5} {
		put32(typeIDs+i*4, v)
	}
	put32(protoIDs, 2)
	put32(protoIDs+4, 0)
	put32(protoIDs+12, 5)
	put32(protoIDs+16, 3)
	put16(fieldIDs, 1)
	put16(fieldIDs+2, 0)
	put32(fieldIDs+4, 8)
	for i, m := range [][3]uint32{{1, 1, 0}, {1, 0, 6}, {1, 0, 8}, {2, 1, 7}} {
		at := methodIDs + i*8
		put16(at, uint16(m[0]))
		put16(at+2, uint16(m[1]))
		put32(at+4, m[2])
	}
	put32(classDefs, 1)
	put32(classDefs+4, 1)
	put32(classDefs+8, 2)
	put32(classDefs+16, 1)
	put32(classDefs+24, uint32(classData))
	c := []byte{1, 0, 3, 0, 0, 9}
	for _, m := range [][3]uint32{{0, 0x10001, uint32(ctorCode)}, {1, 0x109, 0}, {1, 9, uint32(valueCode)}} {
		for _, v := range m {
			c = appendULEB(c, v)
		}
	}
	copy(b[classData:], c)
	put16(ctorCode, 1)
	put16(ctorCode+2, 1)
	put32(ctorCode+12, 1)
	put16(valueCode, registers)
	put16(valueCode+4, outgoing)
	put32(valueCode+12, uint32(len(code)))
	put32(mapOff, uint32(len(items)))
	for i, v := range items {
		at := mapOff + 4 + i*12
		put16(at, uint16(v[0]))
		put32(at+4, v[1])
		put32(at+8, v[2])
	}
	RepairDEXHashes(b)
	return b
}

func RepairDEXHashes(b []byte) {
	sig := sha1.Sum(b[32:])
	copy(b[12:32], sig[:])
	binary.LittleEndian.PutUint32(b[8:], adler32.Checksum(b[12:]))
}
