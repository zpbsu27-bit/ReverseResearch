package appinspect

import (
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"

	"reverseresearch/internal/appinspect/testfixture"
)

func TestGoRawIgnoresImpossibleAlignedMarkerAlongsideActualHeader(t *testing.T) {
	b := testfixture.GoMetadataPE(testfixture.GoInlineRecord([]byte("go-test"), []byte("module")), 512)
	copy(b[768:], goBuildMagic)
	b[782], b[783] = 0, 0
	r, err := ReadGoMetadata(input(t, "literal-marker.exe", b), GoMetadataOptions{Part: "version"})
	if err != nil || r.HeaderRange == nil || r.HeaderRange.Offset != 512 || r.GoVersion == nil || *r.GoVersion != "go-test" {
		t.Fatalf("data marker shadowed valid header: %+v %v", r, err)
	}
}

func TestGoRawMetadataPreservesInlineBytesAcrossContainers(t *testing.T) {
	version, module := []byte{'g', 'o', 0xff}, []byte{'p', 'a', 't', 'h', '\t', 0xfe, '\n'}
	record := testfixture.GoInlineRecord(version, module)
	for name, b := range map[string][]byte{"pe": testfixture.GoMetadataPE(record, 512), "elf": testfixture.GoMetadataELF(record), "macho": testfixture.GoMetadataMachO(record)} {
		t.Run(name, func(t *testing.T) {
			p := input(t, name, b)
			r, err := ReadGoMetadata(p, GoMetadataOptions{Part: "version"})
			if err != nil {
				t.Fatal(err)
			}
			if !r.BuildInfoAvailable || r.Encoding != "inline-varint" || r.GoVersion != nil || r.VersionUTF8 || r.ModuleUTF8 || r.DataBase64 != base64.StdEncoding.EncodeToString(version) || r.VersionSHA256 != digest(version) {
				t.Fatalf("raw %+v", r)
			}
			if r.VersionRange.Size != 3 || string(b[r.VersionRange.Offset:r.VersionRange.Offset+3]) != string(version) {
				t.Fatal("version source range mismatch")
			}
			m, err := ReadGoMetadata(p, GoMetadataOptions{PageOptions: PageOptions{ExpectedSHA256: r.SHA256, Limit: 1}, Part: "module"})
			if err != nil || m.NextOffset == nil || m.ReadBytes != 1 {
				t.Fatalf("module page %+v %v", m, err)
			}
			if _, err := ReadGoMetadata(p, GoMetadataOptions{PageOptions: PageOptions{ExpectedSHA256: strings.Repeat("0", 64)}}); err == nil {
				t.Fatal("stale bytes admitted")
			}
		})
	}
}
func TestGoRawHistoricalPointerAndZeroFillModule(t *testing.T) {
	big, err := ReadGoMetadata(input(t, "big.elf", testfixture.GoBigEndianPointerELF()), GoMetadataOptions{})
	if err != nil || big.ByteOrder != "big-endian" || big.WordSize != 8 || big.GoVersion == nil || *big.GoVersion != "go-fixtur" || big.ModuleRange.Offset != 248 {
		t.Fatalf("big endian %+v %v", big, err)
	}
	for _, zero := range []bool{false, true} {
		b := testfixture.GoMetadataPE(testfixture.GoPointerRecord(zero), 1024)
		r, err := ReadGoMetadata(input(t, "old.exe", b), GoMetadataOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if r.Encoding != "pointer-string" || r.GoVersion == nil || *r.GoVersion != "go-fixtur" {
			t.Fatalf("historical %+v", r)
		}
		if zero {
			if r.ModuleRange.Size != 0 || r.ModuleRange.Basis != "zero-fill-empty-module-pointer-anchor" || r.ModuleSHA256 != digest(nil) || r.ReadBytes != 0 {
				t.Fatal(r)
			}
		} else {
			if r.ModuleRange.Offset != 632 || r.ModuleRange.Size != 3 || r.ModuleUTF8 {
				t.Fatal(r)
			}
		}
	}
}

func TestGoRawModuleBodyNeedsExactSentinels(t *testing.T) {
	module := append(append(append([]byte{}, goModuleStart...), []byte("path\texample\n")...), goModuleEnd...)
	b := testfixture.GoMetadataPE(testfixture.GoInlineRecord([]byte("go-test"), module), 512)
	r, err := ReadGoMetadata(input(t, "framed.exe", b), GoMetadataOptions{Part: "module-body"})
	if err != nil || !r.ModuleFramingRecognized || r.ModuleUTF8 || r.ModuleBodyUTF8 == nil || !*r.ModuleBodyUTF8 || r.DataBase64 != base64.StdEncoding.EncodeToString([]byte("path\texample\n")) {
		t.Fatalf("framed %+v %v", r, err)
	}
	module[0] ^= 1
	b = testfixture.GoMetadataPE(testfixture.GoInlineRecord([]byte("go-test"), module), 512)
	if _, err := ReadGoMetadata(input(t, "fake-frame.exe", b), GoMetadataOptions{Part: "module-body"}); err == nil {
		t.Fatal("newline heuristic accepted forged framing")
	}
}
func TestGoRawMalformedRecognitionFailsExplicitly(t *testing.T) {
	good := testfixture.GoMetadataPE(testfixture.GoInlineRecord([]byte("go-test"), []byte("module")), 512)
	for name, change := range map[string]func([]byte){"flags": func(b []byte) { b[527] = 0x82 }, "pointer-size": func(b []byte) { b[526] = 3 }, "length": func(b []byte) {
		for i := 544; i < 554; i++ {
			b[i] = 0xff
		}
	}, "duplicate": func(b []byte) { copy(b[768:], b[512:576]) }, "bad-range": func(b []byte) { binary.LittleEndian.PutUint32(b[396:], 1024) }} {
		t.Run(name, func(t *testing.T) {
			b := append([]byte{}, good...)
			change(b)
			if _, err := ReadGoMetadata(input(t, name, b), GoMetadataOptions{}); err == nil {
				t.Fatal("malformed recognized metadata accepted")
			}
		})
	}
	r, err := ReadGoMetadata(input(t, "notgo.exe", testfixture.GoMetadataPE(nil, 512)), GoMetadataOptions{})
	if err != nil || r.BuildInfoAvailable || r.UnavailableReason == "" {
		t.Fatalf("missing %+v %v", r, err)
	}
	if _, err := ReadGoMetadata(input(t, "raw", []byte("not a container")), GoMetadataOptions{}); err == nil {
		t.Fatal("arbitrary byte carrier interpreted as Go")
	}
}
