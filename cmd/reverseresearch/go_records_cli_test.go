package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"reverseresearch/internal/appinspect"
	"reverseresearch/internal/appinspect/testfixture"
)

func TestGoSemanticCLIUsesRecordLimitAndExplicitFieldSelector(t *testing.T) {
	root, _ := isolatedCLIRoot(t)
	p := filepath.Join(t.TempDir(), "module.exe")
	body := []byte("path\tapp\nmod\tm\t(devel)\nbuild\tbinary=\"\\xff\"\nunknown\tv\n")
	if err := os.WriteFile(p, testfixture.GoMetadataPE(testfixture.GoInlineRecord([]byte("go-fixture"), testfixture.GoFramedModule(body)), 512), 0600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		args []string
		part string
	}{
		{[]string{"app", "go-read", p, "--part", "records"}, "records"},
		{[]string{"app", "go-read", p, "--part", "record-field", "--record-index", "2", "--field", "value", "--limit", "1"}, "record-field"},
	} {
		var out, errout bytes.Buffer
		if err := runMain(context.Background(), root, test.args, &out, &errout); err != nil {
			t.Fatal(err)
		}
		var r appinspect.GoMetadataReport
		if err := json.Unmarshal(out.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		if test.part == "records" && (r.TotalRecords != 4 || len(r.Records) != 4 || r.GrammarComplete) {
			t.Fatalf("CLI default row limit/partial metadata lost: %+v", r)
		}
		if test.part == "record-field" && (r.DataBase64 != "/w==" || r.ReadBytes != 1) {
			t.Fatalf("CLI binary value/limit lost: %+v", r)
		}
	}
	for _, args := range [][]string{
		{"app", "go-read", p, "--part", "records", "--record-index", "0"},
		{"app", "go-read", p, "--part", "record-field", "--field", "value"},
		{"app", "go-read", p, "--part", "records", "--limit", "201"},
	} {
		var out, errout bytes.Buffer
		if err := runMain(context.Background(), root, args, &out, &errout); err == nil || out.Len() != 0 {
			t.Fatalf("invalid CLI selector returned success: %v %v", args, err)
		}
	}
}
