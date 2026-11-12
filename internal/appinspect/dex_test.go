package appinspect

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"reverseresearch/internal/appinspect/testfixture"
)

func writeDEXFixture(t *testing.T, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "classes.dex")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDEXDefinitionsReferencesAndRawMUTF8(t *testing.T) {
	b := testfixture.DEX()
	p := writeDEXFixture(t, b)
	r, err := InspectDEX(p, DEXOptions{View: "methods"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Version != "035" || r.TotalMethods != 4 || r.DefinedMethods != 3 || r.TotalClasses != 1 || r.TotalFields != 1 || r.ExecutionPerformed || r.NetworkInteraction || !r.SignatureVerified || !r.ChecksumVerified {
		t.Fatalf("report: %+v", r)
	}
	if r.Methods[0].Name != "<init>" || r.Methods[0].Descriptor != "()V" || r.Methods[1].Name != "nativeProbe" || !r.Methods[1].NativeDeclared || r.Methods[1].CodeOffset != 0 || r.Methods[2].CodeUnits != 2 || r.Methods[3].Defined || r.Methods[3].MethodKind != "reference-only" {
		t.Fatalf("method distinction: %+v", r.Methods)
	}
	classes, err := InspectDEX(p, DEXOptions{})
	if err != nil || classes.Classes[0].Descriptor != "Ldemo/Example;" || classes.Classes[0].DirectMethods != 3 || classes.Classes[0].StaticFields != 1 {
		t.Fatalf("classes: %+v %v", classes, err)
	}
	heap, err := InspectDEX(p, DEXOptions{View: "strings"})
	if err != nil {
		t.Fatal(err)
	}
	if heap.Strings[9].UTF16Units != 7 || heap.Strings[9].TextPreview == nil || *heap.Strings[9].TextPreview != "zero\x00😀" || heap.Strings[10].UTF8Available || heap.Strings[10].TextPreview != nil {
		t.Fatalf("MUTF-8 lost units: %+v", heap.Strings)
	}
	i := 10
	raw, err := InspectDEX(p, DEXOptions{View: "string-bytes", StringIndex: &i})
	if err != nil {
		t.Fatal(err)
	}
	v, _ := base64.StdEncoding.DecodeString(raw.DataBase64)
	if !bytes.Equal(v, []byte{1, 0xed, 0xa0, 0x80, 0}) {
		t.Fatalf("lone surrogate was transformed: %x", v)
	}
	next, err := InspectDEX(p, DEXOptions{View: "methods", PageOptions: PageOptions{Offset: 1, Limit: 1, ExpectedSHA256: r.SHA256}})
	if err != nil || next.Methods[0].Index != 1 || next.NextOffset == nil || *next.NextOffset != 2 {
		t.Fatalf("page: %+v %v", next, err)
	}
	if _, err := InspectDEX(p, DEXOptions{PageOptions: PageOptions{Offset: 1}}); err == nil {
		t.Fatal("unfenced page accepted")
	}
	if _, err := InspectDEX(p, DEXOptions{PageOptions: PageOptions{ExpectedSHA256: strings.Repeat("0", 64)}}); err == nil {
		t.Fatal("stale input accepted")
	}
	for _, version := range []string{"037", "038", "039", "040"} {
		v := bytes.Clone(b)
		copy(v[4:7], version)
		testfixture.RepairDEXHashes(v)
		if _, err := parseDEX(v); err != nil {
			t.Fatalf("version %s: %v", version, err)
		}
	}
}

func TestDEXRejectsHiddenMalformedMetadataBeforePageSelection(t *testing.T) {
	base := testfixture.DEX()
	read32 := func(at int) uint32 { return binary.LittleEndian.Uint32(base[at:]) }
	methods, classes := int(read32(92)), int(read32(100))
	classData := int(read32(classes + 24))
	lastString := int(read32(int(read32(60)) + 10*4))
	tests := []struct {
		name   string
		mutate func([]byte)
	}{
		{"unsupported-container", func(b []byte) { copy(b[4:7], "041") }},
		{"wrong-file-size", func(b []byte) { binary.LittleEndian.PutUint32(b[32:], uint32(len(b)-1)) }},
		{"reverse-endian", func(b []byte) { binary.LittleEndian.PutUint32(b[40:], 0x78563412) }},
		{"count-overflow", func(b []byte) { binary.LittleEndian.PutUint32(b[56:], 0xffffffff) }},
		{"table-overlap", func(b []byte) { binary.LittleEndian.PutUint32(b[68:], read32(60)) }},
		{"last-method-hidden-bad-index", func(b []byte) { binary.LittleEndian.PutUint32(b[methods+3*8+4:], 0xffffffff) }},
		{"duplicate-method", func(b []byte) { copy(b[methods+8:methods+16], b[methods:methods+8]) }},
		{"wrong-definition-class", func(b []byte) { binary.LittleEndian.PutUint16(b[methods:], 2) }},
		{"classdata-overflow", func(b []byte) { copy(b[classData:], []byte{0xff, 0xff, 0xff, 0xff, 0x10}) }},
		{"classdata-duplicate-method", func(b []byte) { b[classData+12] = 0 }},
		{"mutf8-truncated-unit", func(b []byte) { b[lastString+3] = 0x41 }},
		{"mutf8-four-byte-scalar", func(b []byte) { b[lastString+1] = 0xf0 }},
		{"mutf8-wrong-length", func(b []byte) { b[lastString] = 2 }},
		{"map-order", func(b []byte) { at := int(read32(52)); binary.LittleEndian.PutUint32(b[at+4+12+8:], 0) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			b := bytes.Clone(base)
			test.mutate(b)
			testfixture.RepairDEXHashes(b)
			p := writeDEXFixture(t, b)
			if _, err := InspectDEX(p, DEXOptions{View: "methods", PageOptions: PageOptions{Limit: 1}}); err == nil {
				t.Fatal("malformed hidden data accepted")
			}
		})
	}
	bad := bytes.Clone(base)
	bad[len(bad)-1] ^= 1
	if _, err := parseDEX(bad); err == nil {
		t.Fatal("checksum corruption accepted")
	}
}

func TestDEXUsesCanonicalZIPCRCAndMemberIdentity(t *testing.T) {
	var archive bytes.Buffer
	w := zip.NewWriter(&archive)
	f, _ := w.CreateHeader(&zip.FileHeader{Name: "classes2.dex", Method: zip.Store})
	_, _ = f.Write(testfixture.DEX())
	_ = w.Close()
	p := filepath.Join(t.TempDir(), "app.apk")
	if err := os.WriteFile(p, archive.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := InspectDEX(p, DEXOptions{Entry: "classes2.dex", View: "methods"})
	if err != nil || !r.CRCVerified || r.Entry == nil || r.Entry.Path != "classes2.dex" || r.ContentSHA256 != digest(testfixture.DEX()) || r.SHA256 == r.ContentSHA256 {
		t.Fatalf("member identity: %+v %v", r, err)
	}
	v := bytes.Clone(archive.Bytes())
	at := bytes.Index(v, []byte("dex\n035"))
	v[at+8] ^= 1
	_ = os.WriteFile(p, v, 0o600)
	if _, err := InspectDEX(p, DEXOptions{Entry: "classes2.dex"}); err == nil {
		t.Fatal("corrupt ZIP member accepted")
	}
}

func TestDEXLEBBoundariesAndNames(t *testing.T) {
	for _, b := range [][]byte{{0x80}, {0xff, 0xff, 0xff, 0xff, 0x10}, {0x80, 0x80, 0x80, 0x80, 0x80, 0}} {
		at := uint32(0)
		if _, err := dexULEB(b, &at, uint32(len(b))); err == nil {
			t.Fatalf("invalid ULEB accepted: %x", b)
		}
	}
	b := []byte{0xff, 0xff, 0xff, 0xff, 0x0f}
	at := uint32(0)
	v, err := dexULEB(b, &at, uint32(len(b)))
	if err != nil || v != 0xffffffff {
		t.Fatalf("ULEB full width: %x %v", v, err)
	}
	for _, b := range [][]byte{{0x80}, {0x80, 0x80, 0x80, 0x80, 0x70}} {
		at := uint32(0)
		if _, err := dexSLEB(b, &at, uint32(len(b))); err == nil {
			t.Fatalf("invalid SLEB accepted: %x", b)
		}
	}
	if dexSimpleName("a b", "039") || !dexSimpleName("a b", "040") || !dexSimpleName("😀", "035") || dexTypeValid("[V", "040") || dexTypeValid("Lbad.name;", "040") {
		t.Fatal("DEX name/version/type grammar drift")
	}
}

func FuzzDEXDoesNotPanic(f *testing.F) {
	f.Add(testfixture.DEX())
	f.Add([]byte("dex\n041\x00"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) < 32 || len(b) > 2<<20 {
			return
		}
		v := bytes.Clone(b)
		testfixture.RepairDEXHashes(v)
		_, _ = parseDEX(v)
	})
}
