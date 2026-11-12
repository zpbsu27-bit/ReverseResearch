// Package testfixture constructs inert serialization vectors independently of
// production decoders. It does not invoke Foundation, UIKit or platform tools.
package testfixture

import (
	"bytes"
	"encoding/binary"
)

const KeyedXML = `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>$archiver</key><string>NSKeyedArchiver</string><key>$version</key><integer>100000</integer><key>$objects</key><array><string>$null</string><dict><key>$class</key><dict><key>CF$UID</key><integer>2</integer></dict><key>self</key><dict><key>CF$UID</key><integer>1</integer></dict><key>missing</key><dict><key>CF$UID</key><integer>99</integer></dict><key>blob</key><data>AP8=</data></dict><dict><key>$classname</key><string>Fixture</string><key>$classes</key><array><string>Fixture</string><string>NSObject</string></array></dict></array><key>$top</key><dict><key>root</key><dict><key>CF$UID</key><integer>1</integer></dict></dict></dict></plist>`

// BinaryPlist uses a fixed four-byte offset table and one-byte reference IDs.
// Callers supply literal encoded objects, keeping expectations independent.
func BinaryPlist(objects [][]byte, root int) []byte {
	b := []byte("bplist00")
	offsets := make([]uint32, len(objects))
	for i, o := range objects {
		offsets[i] = uint32(len(b))
		b = append(b, o...)
	}
	table := len(b)
	for _, off := range offsets {
		b = binary.BigEndian.AppendUint32(b, off)
	}
	trailer := make([]byte, 32)
	trailer[6] = 4
	trailer[7] = 1
	binary.BigEndian.PutUint64(trailer[8:16], uint64(len(objects)))
	binary.BigEndian.PutUint64(trailer[16:24], uint64(root))
	binary.BigEndian.PutUint64(trailer[24:32], uint64(table))
	return append(b, trailer...)
}

func BinaryKeyed() []byte {
	text := func(s string) []byte {
		if len(s) < 15 {
			return append([]byte{0x50 | byte(len(s))}, []byte(s)...)
		}
		return append([]byte{0x5f, 0x10, byte(len(s))}, []byte(s)...)
	}
	return BinaryPlist([][]byte{
		{0xd4, 1, 2, 3, 4, 5, 6, 7, 8}, text("$archiver"), text("$version"), text("$objects"), text("$top"), text("NSKeyedArchiver"), {0x12, 0, 1, 0x86, 0xa0}, {0xa3, 9, 10, 11}, {0xd1, 21, 15}, text("$null"), {0xd2, 12, 13, 14, 15}, {0xd2, 16, 17, 18, 19}, text("$class"), text("self"), {0x80, 2}, {0x80, 1}, text("$classname"), text("$classes"), text("Fixture"), {0xa2, 18, 20}, text("NSObject"), text("root"),
	}, 0)
}

func NIB() []byte {
	// Two objects share one class; each carries a cyclic object reference.
	objects := []byte{0x80, 0x80, 0x82, 0x80, 0x82, 0x81}
	keys := append([]byte{0x84}, []byte("link")...)
	keys = append(keys, 0x83)
	keys = append(keys, []byte("big")...)
	values := []byte{0x80, 10, 1, 0, 0, 0, 0x81, 3}
	values = binary.LittleEndian.AppendUint64(values, 0x7fffffffffffffff)
	values = append(values, 0x80, 10, 0, 0, 0, 0)
	classes := []byte{0x88, 0x81, 0x78, 0x56, 0x34, 0x12}
	classes = append(classes, []byte("Fixture\x00")...)
	b := make([]byte, 50)
	copy(b, []byte("NIBArchive"))
	binary.LittleEndian.PutUint32(b[10:14], 1)
	binary.LittleEndian.PutUint32(b[14:18], 900)
	for i, part := range [][]byte{objects, keys, values, classes} {
		count := []uint32{2, 2, 3, 1}[i]
		binary.LittleEndian.PutUint32(b[18+i*8:], count)
		binary.LittleEndian.PutUint32(b[22+i*8:], uint32(len(b)))
		b = append(b, part...)
	}
	return b
}

func XMLUTF16(s string) []byte {
	var b bytes.Buffer
	b.Write([]byte{0xff, 0xfe})
	for _, r := range s {
		if r > 0xffff {
			r -= 0x10000
			binary.Write(&b, binary.LittleEndian, uint16(0xd800+r>>10))
			binary.Write(&b, binary.LittleEndian, uint16(0xdc00+r&0x3ff))
		} else {
			binary.Write(&b, binary.LittleEndian, uint16(r))
		}
	}
	return b.Bytes()
}
