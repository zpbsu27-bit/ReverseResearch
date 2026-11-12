package appinspect

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"reverseresearch/internal/appinspect/testfixture"
)

func TestGoSemanticViewsShareSummaryAndPreserveAllOriginalLineBytes(t *testing.T) {
	body := []byte("path\tapp/main\nmod\tapp\t(devel)\ndep\tx/dep\tv1\n=>\t../local\t\t\nbuild\tquoted=\"hello\\nworld\"\nbuild\tbinary=\"\\xff\"\nfuture\tv\n")
	body = append(body, []byte{0xff, '\n'}...)
	body = append(body, []byte("tail without newline")...)
	module := testfixture.GoFramedModule(body)
	record := testfixture.GoInlineRecord([]byte("go-fixture"), module)
	for name, container := range map[string][]byte{"pe": testfixture.GoMetadataPE(record, 512), "elf": testfixture.GoMetadataELF(record), "macho": testfixture.GoMetadataMachO(record)} {
		t.Run(name, func(t *testing.T) {
			path := input(t, name, container)
			info, err := InspectGoBinary(path, PageOptions{})
			if err != nil || !info.BuildInfoAvailable || !info.ModuleSemanticsAvailable || info.GrammarComplete || info.TextSummaryComplete || info.UnparsedRecords != 3 || info.PackagePath != "app/main" || info.Main.Path != "app" || info.Dependencies[0].Replace.Path != "../local" || info.TotalSettingsObserved != 2 || len(info.Settings) != 1 {
				t.Fatalf("summary differs from lossless owner: %+v %v", info, err)
			}
			var rows []GoModuleRecord
			for offset := 0; ; {
				r, err := ReadGoMetadata(path, GoMetadataOptions{Part: "records", PageOptions: PageOptions{Offset: offset, Limit: 2, ExpectedSHA256: info.SHA256}})
				if err != nil || r.GrammarComplete || r.TextSummaryComplete || r.TotalRecords != 9 || r.UnparsedRecords != 3 {
					t.Fatalf("partial records lost: %+v %v", r, err)
				}
				rows = append(rows, r.Records...)
				if r.NextOffset == nil {
					break
				}
				offset = *r.NextOffset
			}
			var rebuilt []byte
			for _, row := range rows {
				raw := container[row.Range.Offset : row.Range.Offset+row.Range.Size]
				if row.RawSHA256 != digest(raw) {
					t.Fatal("record original range/hash mismatch")
				}
				rebuilt = append(rebuilt, raw...)
			}
			if !bytes.Equal(rebuilt, body) {
				t.Fatal("original module lines were dropped or normalized")
			}
			selected := 5
			r, err := ReadGoMetadata(path, GoMetadataOptions{Part: "record-field", RecordIndex: &selected, Field: "value", PageOptions: PageOptions{Limit: 1, ExpectedSHA256: info.SHA256}})
			if err != nil || r.DataBase64 != "/w==" || r.DecodedField.UTF8 || r.DecodedField.SHA256 != digest([]byte{0xff}) {
				t.Fatalf("escaped binary value lost: %+v %v", r, err)
			}
			selected = 3
			r, err = ReadGoMetadata(path, GoMetadataOptions{Part: "record-field", RecordIndex: &selected, Field: "sum"})
			if err != nil || r.ReadBytes != 0 || r.DecodedField == nil || r.DecodedField.Bytes != 0 || r.DecodedField.SHA256 != digest(nil) {
				t.Fatalf("explicit empty sum confused with missing: %+v %v", r, err)
			}
			selected = 2
			if _, err := ReadGoMetadata(path, GoMetadataOptions{Part: "record-field", RecordIndex: &selected, Field: "sum"}); err == nil {
				t.Fatal("missing sum invented")
			}
		})
	}
}

func TestGoSemanticSelectorsAndLongDecodedFieldsRemainBytePaged(t *testing.T) {
	long := strings.Repeat("x", 20000)
	body := []byte("build\tlong=\"" + long + "\"\n")
	path := input(t, "long.elf", testfixture.GoMetadataELF(testfixture.GoInlineRecord([]byte("go-fixture"), testfixture.GoFramedModule(body))))
	index := 0
	first, err := ReadGoMetadata(path, GoMetadataOptions{Part: "record-field", RecordIndex: &index, Field: "value", PageOptions: PageOptions{Limit: 16384}})
	if err != nil || first.NextOffset == nil || first.DecodedField.PreviewComplete || first.ReadBytes != 16384 {
		t.Fatalf("long decoded field not bounded: %+v %v", first, err)
	}
	second, err := ReadGoMetadata(path, GoMetadataOptions{Part: "record-field", RecordIndex: &index, Field: "value", PageOptions: PageOptions{Offset: *first.NextOffset, Limit: 16384, ExpectedSHA256: first.SHA256}})
	if err != nil || second.NextOffset != nil {
		t.Fatal(err)
	}
	a, _ := base64.StdEncoding.DecodeString(first.DataBase64)
	b, _ := base64.StdEncoding.DecodeString(second.DataBase64)
	if string(append(a, b...)) != long || first.DecodedField.SHA256 != digest([]byte(long)) {
		t.Fatal("decoded bytes not fully recoverable")
	}
	for _, o := range []GoMetadataOptions{
		{Part: "records", PageOptions: PageOptions{Limit: 201}}, {Part: "records", Field: "value"},
		{Part: "record-field", Field: "value"}, {Part: "record-field", RecordIndex: &index, Field: "unknown"},
		{Part: "record-field", RecordIndex: &index, Field: "value", PageOptions: PageOptions{Offset: 1}},
		{Part: "records", PageOptions: PageOptions{ExpectedSHA256: strings.Repeat("0", 64)}},
	} {
		if _, err := ReadGoMetadata(path, o); err == nil {
			t.Fatalf("invalid semantic selector accepted: %+v", o)
		}
	}
}

func TestGoSemanticViewsIncludeCompilerEncodingInTextCompleteness(t *testing.T) {
	body := testfixture.GoFramedModule([]byte("build\tvalid=value\n"))
	path := input(t, "binary-version.elf", testfixture.GoMetadataELF(testfixture.GoInlineRecord([]byte{0xff}, body)))
	info, err := InspectGoBinary(path, PageOptions{})
	if err != nil || !info.GrammarComplete || info.GoVersionUTF8 || info.TextSummaryComplete || info.GoVersion != "" {
		t.Fatalf("binary compiler declaration normalized: %+v %v", info, err)
	}
	index := 0
	for _, options := range []GoMetadataOptions{{Part: "records"}, {Part: "record-field", RecordIndex: &index, Field: "value"}} {
		r, err := ReadGoMetadata(path, options)
		if err != nil || !r.GrammarComplete || r.VersionUTF8 || r.TextSummaryComplete || r.GoVersion != nil {
			t.Fatalf("semantic completeness disagrees with summary: %+v %v", r, err)
		}
	}
}
