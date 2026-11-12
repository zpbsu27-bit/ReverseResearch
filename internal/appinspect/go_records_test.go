package appinspect

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestGoModuleRecordsPreserveGrammarRawBytesAndReplacementIdentity(t *testing.T) {
	body := []byte("path\texample/cmd\nmod\texample\t(devel)\n=>\t../local\t\t\n" + "dep\tx/one\tv1.0.0\th1:first\n=>\tx/two\tv2.0.0\th1:second\n" + "build\t\"key=part\"=\"hello\\nworld\"\nbuild\tempty=\nbuild\tbinary=\"\\xff\"\n")
	o, err := parseGoModuleRecords(body, GoMetadataRange{Offset: 100, Size: uint64(len(body)), Basis: "original-file-bytes"})
	if err != nil || o.unparsed != 0 || o.textComplete || o.info.Path != "example/cmd" || o.info.Main.Replace.Path != "../local" || len(o.info.Deps) != 1 || o.info.Deps[0].Replace.Path != "x/two" || len(o.info.Settings) != 2 || o.settingsObserved != 3 {
		t.Fatalf("record semantic/identity lost: %+v %v", o, err)
	}
	if o.info.Settings[0].Key != "key=part" || o.info.Settings[0].Value != "hello\nworld" || o.info.Settings[1].Value != "" || o.rows[7].row.Fields[1].UTF8 {
		t.Fatal("quoted/empty/binary fields normalized")
	}
	if o.rows[1].row.Fields[0].Name != "path" || len(o.rows[1].row.Fields) != 2 || o.rows[2].row.ReplacementOf == nil || *o.rows[2].row.ReplacementOf != 1 {
		t.Fatal("missing sum/local replacement conflated")
	}
	for _, r := range o.rows {
		raw := body[r.row.BodyOffset : r.row.BodyOffset+int(r.row.Range.Size)]
		prefix, _ := base64.StdEncoding.DecodeString(r.row.RawPrefixBase64)
		if r.row.RawSHA256 != digest(raw) || r.row.Range.Offset != 100+uint64(r.row.BodyOffset) || !bytes.Equal(prefix, raw) {
			t.Fatal("raw source evidence changed")
		}
	}
}

func TestGoModuleRecordsRetainUnknownDuplicatesBadEncodingAndUnterminatedLines(t *testing.T) {
	body := []byte("path\tfirst\npath\tsecond\nmod\tm\t(devel)\nmod\tduplicate\t(devel)\n=>\tbad\t\t\n" + "dep\td\tv1\ndep\tbroken\n=>\twrong\t\t\nbuild\tbroken\nfuture\tvalue\n")
	body = append(body, []byte{'d', 'e', 'p', '\t', 0xff, '\n'}...)
	body = append(body, []byte("=>\tignored\t\t\npath\tunterminated")...)
	o, err := parseGoModuleRecords(body, GoMetadataRange{Size: uint64(len(body))})
	if err != nil || o.unparsed != 10 || o.info.Path != "first" || o.info.Main.Path != "m" || o.info.Main.Replace != nil || len(o.info.Deps) != 1 || o.info.Deps[0].Replace != nil || o.textComplete {
		t.Fatalf("partial/duplicate model incorrect: unparsed=%d %+v %v", o.unparsed, o.info, err)
	}
	if o.rows[len(o.rows)-1].row.Terminated || o.rows[10].row.RawUTF8 || o.rows[10].row.Status != "unparsed" {
		t.Fatal("invalid original bytes/termination lost")
	}
}

func TestGoModuleRecordsBoundInventoryWithoutDroppingLongFields(t *testing.T) {
	body := []byte("build\tlong=\"" + strings.Repeat("z", 10000) + "\"\n")
	o, err := parseGoModuleRecords(body, GoMetadataRange{Size: uint64(len(body))})
	if err != nil || len(o.rows[0].fields["value"]) != 10000 || o.rows[0].row.Fields[1].PreviewComplete || o.rows[0].row.RawPreviewComplete {
		t.Fatalf("long value lost or preview claimed complete: %v", err)
	}
	tooMany := bytes.Repeat([]byte{'\n'}, maxGoRecordCount+1)
	if _, err := parseGoModuleRecords(tooMany, GoMetadataRange{Size: uint64(len(tooMany))}); err == nil {
		t.Fatal("record inventory unbounded")
	}
	if _, err := parseGoModuleRecords(body, GoMetadataRange{Size: 1}); err == nil {
		t.Fatal("source range mismatch accepted")
	}
}

func FuzzGoModuleRecords(f *testing.F) {
	for _, seed := range [][]byte{
		{}, []byte("\n\n"), []byte("path\tx\nmod\tm\t(devel)\n=>\t./local\t\t\n"),
		[]byte("build\t\"key=part\"=\"hello\\nworld\"\nbuild\tbinary=\"\\xff\"\n"),
		[]byte("dep\tbroken\n=>\torphan\t\t\nfuture\tx\nunterminated"),
		{'p', 'a', 't', 'h', '\t', 0xff, '\n'},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 64<<10 {
			t.Skip()
		}
		o, err := parseGoModuleRecords(body, GoMetadataRange{Offset: 128, Size: uint64(len(body)), Basis: "original-file-bytes"})
		if err != nil {
			t.Fatalf("bounded record body rejected: %v", err)
		}
		consumed, unparsed := 0, 0
		for index, record := range o.rows {
			r := record.row
			if r.Index != index || r.BodyOffset != consumed || r.Range.Offset != 128+uint64(consumed) || r.Range.Size == 0 || r.Range.Size > uint64(len(body)-consumed) {
				t.Fatal("record partition is invalid")
			}
			raw := body[consumed : consumed+int(r.Range.Size)]
			prefix, err := base64.StdEncoding.DecodeString(r.RawPrefixBase64)
			if err != nil || !bytes.Equal(prefix, raw[:min(len(raw), 256)]) || r.RawSHA256 != digest(raw) || r.RawUTF8 != utf8.Valid(raw) || r.Terminated != (raw[len(raw)-1] == '\n') {
				t.Fatal("raw record evidence changed")
			}
			if r.Status == "unparsed" {
				unparsed++
			}
			if r.ReplacementOf != nil && (*r.ReplacementOf < 0 || *r.ReplacementOf >= index || (o.rows[*r.ReplacementOf].row.Kind != "module" && o.rows[*r.ReplacementOf].row.Kind != "dependency")) {
				t.Fatal("replacement lost its valid antecedent")
			}
			for _, field := range r.Fields {
				value, ok := record.fields[field.Name]
				if !ok || field.Bytes != len(value) || field.SHA256 != digest(value) || field.UTF8 != utf8.Valid(value) || (field.TextPreview != nil && !utf8.ValidString(*field.TextPreview)) {
					t.Fatal("decoded field evidence changed")
				}
			}
			consumed += len(raw)
		}
		if consumed != len(body) || unparsed != o.unparsed || (unparsed > 0 && o.textComplete) {
			t.Fatal("partial grammar/coverage evidence differs")
		}
	})
}
