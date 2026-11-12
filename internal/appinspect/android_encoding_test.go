package appinspect

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"testing"

	"reverseresearch/internal/appinspect/testfixture"
)

func TestAndroidStringPoolsPreserveModifiedUTF8Units(t *testing.T) {
	for _, v := range []struct {
		name          string
		raw           []byte
		units         byte
		text          string
		valid, reject bool
	}{
		{"aapt2-cesu8", []byte{0xe4, 0xbd, 0xa0, 0xe5, 0xa5, 0xbd, 0xed, 0xa0, 0xbd, 0xed, 0xb8, 0x80}, 4, "你好😀", true, false},
		{"standard-utf8", []byte{0xf0, 0x9f, 0x98, 0x80}, 2, "😀", true, false},
		{"encoded-nul", []byte{0xc0, 0x80}, 1, "\x00", true, false},
		{"unpaired-unit", []byte{0xed, 0xa0, 0x80}, 1, "", false, false},
		{"overlong", []byte{0xe0, 0x80, 0x80}, 1, "", false, true},
		{"bad-continuation", []byte{0xed, 0xa0, 0x41}, 1, "", false, true},
		{"scalar-out-of-range", []byte{0xf4, 0x90, 0x80, 0x80}, 2, "", false, true},
		{"wrong-units", []byte{0xed, 0xa0, 0xbd, 0xed, 0xb8, 0x80}, 3, "", false, true},
	} {
		t.Run(v.name, func(t *testing.T) {
			b := make([]byte, 32)
			binary.LittleEndian.PutUint16(b, 1)
			binary.LittleEndian.PutUint16(b[2:], 28)
			binary.LittleEndian.PutUint32(b[8:], 1)
			binary.LittleEndian.PutUint32(b[16:], 0x100)
			binary.LittleEndian.PutUint32(b[20:], 32)
			b = append(b, v.units, byte(len(v.raw)))
			b = append(b, v.raw...)
			b = append(b, 0)
			for len(b)%4 != 0 {
				b = append(b, 0)
			}
			binary.LittleEndian.PutUint32(b[4:], uint32(len(b)))
			c, err := androidChunkAt(b, 0)
			if err != nil {
				t.Fatal(err)
			}
			p, err := parseAndroidPool(c, b, &androidBudget{})
			if v.reject {
				if err == nil {
					t.Fatal("invalid encoded declaration accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			s := p.strings[0]
			if len(s.units) != int(v.units) || s.valid != v.valid || s.text != v.text {
				t.Fatalf("units/text lost: %+v", s)
			}
			report, err := p.value(0)
			if err != nil {
				t.Fatal(err)
			}
			if !v.valid && (report.Text != nil || report.UTF8Available) {
				t.Fatal("unpaired surrogate became text")
			}
			raw, err := base64.StdEncoding.DecodeString(report.DataBase64)
			if err != nil || !bytes.Equal(raw, b[32:35+len(v.raw)]) {
				t.Fatalf("raw encoding lost: %x %v", raw, err)
			}
		})
	}
}

func TestDEXDoesNotAdmitStandardFourByteUTF8(t *testing.T) {
	b := testfixture.DEX()
	off := binary.LittleEndian.Uint32(b[112+9*4:])
	copy(b[off:], []byte{7, 'z', 'e', 'r', 'o', 0xc0, 0x80, 0xf0, 0x9f, 0x98, 0x80, 0})
	testfixture.RepairDEXHashes(b)
	if _, err := parseDEX(b); err == nil {
		t.Fatal("DEX admitted four-byte UTF-8")
	}
}
