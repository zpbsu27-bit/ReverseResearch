package iosinspect

import (
	"encoding/base64"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"reverseresearch/internal/iosinspect/testfixture"
)

func appleInput(t *testing.T, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(p, b, 0600); err != nil {
		t.Fatal(err)
	}
	return p
}
func TestPlistBinaryTypedObjectTable(t *testing.T) {
	wide := append([]byte{0x14}, make([]byte, 16)...)
	wide[9] = 0x80 // +2^63, beyond signed64 and exact JSON numbers.
	b := testfixture.BinaryPlist([][]byte{{0xa5, 1, 2, 3, 4, 5}, wide, {0x13, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, {0x41, 0xff}, {0x81, 0xff, 0xff}, {0x62, 0xd8, 0x3d, 0xde, 0x00}}, 0)
	p := appleInput(t, b)
	r, err := InspectPlist(p, InspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !r.CoverageComplete || r.Objects[1].Text != "9223372036854775808" || r.Objects[2].Text != "-1" || r.Objects[4].Text != "65535" || r.Objects[5].Text != "😀" || r.RangeSHA256 != r.SHA256 {
		t.Fatalf("typed objects %+v", r)
	}
	data, err := ReadPlistData(p, PlistDataOptions{ObjectIndex: 3, InspectOptions: InspectOptions{ExpectedSHA256: r.SHA256}})
	if err != nil || data.DataBase64 != "/w==" || data.Size != 1 {
		t.Fatalf("data %+v %v", data, err)
	}
	if _, err := InspectPlist(p, InspectOptions{ExpectedSHA256: strings.Repeat("0", 64)}); err == nil {
		t.Fatal("stale accepted")
	}
}
func TestPlistSharedDAGDoesNotExpand(t *testing.T) {
	objects := [][]byte{{0x51, 'x'}}
	for i := 1; i < 70; i++ {
		objects = append(objects, []byte{0xa2, byte(i - 1), byte(i - 1)})
	}
	d, err := parsePlist(testfixture.BinaryPlist(objects, 69))
	if err != nil || len(d.nodes) != 70 {
		t.Fatalf("DAG %d %v", len(d.nodes), err)
	}
	objects = append(objects, []byte{0xa1, 70})
	if _, err := parsePlist(testfixture.BinaryPlist(objects, 70)); err == nil {
		t.Fatal("binary cycle accepted")
	}
	objects = [][]byte{{0x51, 'x'}}
	for i := 1; i < 130; i++ {
		objects = append(objects, []byte{0xa1, byte(i - 1)})
	}
	if _, err := parsePlist(testfixture.BinaryPlist(objects, 129)); err == nil {
		t.Fatal("deep DAG accepted")
	}
}
func TestPlistMalformedWholeTableBeforePaging(t *testing.T) {
	for name, objects := range map[string][][]byte{"hidden-ref": {{0x51, 'a'}, {0xa1, 3}}, "surrogate": {{0x61, 0xd8, 0x00}}, "duplicate-key": {{0xd2, 1, 1, 2, 2}, {0x51, 'k'}, {0x09}}, "hidden-type": {{0x51, 'a'}, {0xff}}, "bad-ascii": {{0x51, 0xff}}} {
		t.Run(name, func(t *testing.T) {
			if _, err := InspectPlist(appleInput(t, testfixture.BinaryPlist(objects, 0)), InspectOptions{Limit: 1}); err == nil {
				t.Fatal("malformed table accepted")
			}
		})
	}
	b := testfixture.BinaryPlist([][]byte{{0x52, 'a', 'b'}, {0x09}}, 0)
	table := binary.BigEndian.Uint64(b[len(b)-8:])
	binary.BigEndian.PutUint32(b[table+4:], 9)
	if _, err := parsePlist(b); err == nil {
		t.Fatal("overlapping object ranges accepted")
	}
}
func TestPlistXMLBoundsAndRanges(t *testing.T) {
	x := `<plist version="1.0"><dict><key>__proto__</key><integer>18446744073709551615</integer><key>empty</key><data></data><key>real</key><real>NaN</real></dict></plist>`
	for _, b := range [][]byte{[]byte(x), testfixture.XMLUTF16(x)} {
		r, err := InspectPlist(appleInput(t, b), InspectOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if r.Objects[2].Text != "18446744073709551615" || r.Objects[1].Text != "__proto__" || r.Objects[4].DataSHA256 != contentHash(nil) || r.Objects[6].IEEE754Hex == "" || r.Objects[0].ByteLength == 0 {
			t.Fatalf("XML %+v", r)
		}
		if r.RangeSHA256 != contentHash([]byte(x)) {
			t.Fatal("normalized range identity")
		}
	}
	for _, x := range []string{`<!DOCTYPE plist [<!ENTITY a "boom">]><plist><string>&a;</string></plist>`, `<plist><dict><key>x</key><true/><key>x</key><false/></dict></plist>`, `<plist><array><key>x</key></array></plist>`, `<plist><data>Zh==</data></plist>`, `<plist><true/><false/></plist>`, `<plist>` + strings.Repeat("<array>", 129) + `<string>x</string>` + strings.Repeat("</array>", 129) + `</plist>`} {
		if _, err := parsePlist([]byte(x)); err == nil {
			t.Fatalf("malformed XML accepted %.80s", x)
		}
	}
}
func TestKeyedArchivePreservesCycleNilAndUnresolved(t *testing.T) {
	binary, err := InspectKeyedArchive(appleInput(t, testfixture.BinaryKeyed()), KeyedArchiveOptions{})
	if err != nil || binary.Format != "binary-plist" || binary.Version != "100000" || binary.Objects[1].ClassName != "Fixture" || !binary.ReferenceResolutionComplete {
		t.Fatalf("binary keyed %+v %v", binary, err)
	}
	p := appleInput(t, []byte(testfixture.KeyedXML))
	r, err := InspectKeyedArchive(p, KeyedArchiveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Objects) != 3 || r.Objects[0].Kind != "nil" || r.Objects[1].ClassName != "Fixture" || r.Objects[1].ClassStatus != "declared" || r.ReferenceResolutionComplete || r.ExecutionPerformed {
		t.Fatalf("archive %+v", r)
	}
	self, missing := false, false
	for _, ref := range r.Objects[1].References {
		if ref.Path == "/self" && ref.Status == "resolved" && *ref.TargetIndex == 1 {
			self = true
		}
		if ref.Path == "/missing" && ref.Status == "unresolved" && ref.RawIndex == "99" {
			missing = true
		}
	}
	if !self || !missing {
		t.Fatal("archive reference identities lost")
	}
	wideXML := strings.Replace(testfixture.KeyedXML, "<integer>99</integer>", "<integer>340282366920938463463374607431768211455</integer>", 1)
	wide, err := InspectKeyedArchive(appleInput(t, []byte(wideXML)), KeyedArchiveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range wide.Objects[1].References {
		if ref.Path == "/missing" && (ref.Status != "unresolved" || ref.RawIndex != "340282366920938463463374607431768211455") {
			t.Fatal("wide positive UID was narrowed or treated as malformed")
		}
	}
	if _, err := InspectKeyedArchive(p, KeyedArchiveOptions{Root: "absent"}); err == nil {
		t.Fatal("missing root accepted")
	}
	if _, err := InspectKeyedArchive(appleInput(t, []byte(`<plist><dict/></plist>`)), KeyedArchiveOptions{}); err == nil {
		t.Fatal("ordinary plist accepted as archive")
	}
	d, _ := parsePlist([]byte(testfixture.KeyedXML))
	for i, n := range d.nodes {
		if n.kind == "data" {
			v, err := ReadPlistData(p, PlistDataOptions{ObjectIndex: i, InspectOptions: InspectOptions{Limit: 1}})
			if err != nil {
				t.Fatal(err)
			}
			b, _ := base64.StdEncoding.DecodeString(v.DataBase64)
			if len(b) != 1 || b[0] != 0 || v.NextOffset == nil {
				t.Fatal("data pagination")
			}
		}
	}
}
func TestNIBInertTablesAndHiddenCorruption(t *testing.T) {
	b := testfixture.NIB()
	p := appleInput(t, b)
	r, err := InspectNIB(p, NIBOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if r.TotalObjects != 2 || r.Objects[0].ClassName != "Fixture" || r.Objects[0].Values[1].Text != "9223372036854775807" || *r.Objects[0].Values[0].ObjectReference != 1 || r.Objects[0].ClassExtensions[0] != 0x12345678 {
		t.Fatalf("NIB %+v", r)
	}
	v, err := InspectNIB(p, NIBOptions{InspectOptions: InspectOptions{Offset: 2, Limit: 1}, View: "values"})
	if err != nil || len(v.Values) != 1 || *v.Values[0].ObjectReference != 0 {
		t.Fatalf("values %+v %v", v, err)
	}
	for name, change := range map[string]func([]byte){"hidden-reference-key": func(x []byte) { off := binary.LittleEndian.Uint32(x[38:42]); x[off+16] = 0xff }, "offset": func(x []byte) { binary.LittleEndian.PutUint32(x[30:34], 49) }, "count": func(x []byte) { binary.LittleEndian.PutUint32(x[18:22], 0xffffffff) }, "version": func(x []byte) { x[10] = 2 }} {
		t.Run(name, func(t *testing.T) {
			bad := append([]byte{}, b...)
			change(bad)
			if _, err := InspectNIB(appleInput(t, bad), NIBOptions{InspectOptions: InspectOptions{Limit: 1}}); err == nil {
				t.Fatal("hidden malformed NIB accepted")
			}
		})
	}
}
