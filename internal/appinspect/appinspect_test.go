package appinspect

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"reverseresearch/internal/appinspect/testfixture"
	"reverseresearch/internal/targetidentity"
	"strings"
	"testing"
)

func input(t *testing.T, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
func TestASARReadsPackedBytesAndRejectsHiddenCorruption(t *testing.T) {
	p := input(t, "app.asar", testfixture.JavaScriptASAR())
	r, err := InspectASAR(p, PageOptions{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if r.TotalEntries != 4 || len(r.Entries) != 1 || r.CoverageComplete || r.NextOffset == nil {
		t.Fatalf("inventory %+v", r)
	}
	b, err := ReadASAR(p, EntryReadOptions{Entry: "main.js", Limit: 7, ExpectedSHA256: r.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	text, _ := base64.StdEncoding.DecodeString(b.DataBase64)
	if string(text) != "import " || b.CoverageComplete || b.ContentSHA256 == "" {
		t.Fatalf("read %+v", b)
	}
	for _, name := range []string{"external.js", "link.js"} {
		b, err := ReadASAR(p, EntryReadOptions{Entry: name})
		if err != nil || b.Entry.Available || b.Entry.UnavailableReason == "" {
			t.Fatalf("unavailable %+v %v", b, err)
		}
	}
	if _, err := InspectASAR(p, PageOptions{ExpectedSHA256: strings.Repeat("0", 64)}); err == nil {
		t.Fatal("accepted stale archive")
	}
	for _, header := range []string{
		`{"files":{"../escape":{"size":1,"offset":"0"}}}`,
		`{"files":{"a":{"size":1,"offset":"0"},"a":{"size":1,"offset":"1"}}}`,
		`{"files":{"a":{"size":2,"offset":"0"},"z":{"size":2,"offset":"1"}}}`,
		`{"files":{"a":{"size":1,"offset":"0"},"z":{"size":100,"offset":"2"}}}`,
	} {
		p := input(t, "bad.asar", testfixture.ASAR(header, []byte("abc")))
		if _, err := InspectASAR(p, PageOptions{Limit: 1}); err == nil {
			t.Fatalf("accepted invalid hidden entry: %s", header)
		}
	}
}

func TestASARIntegrityIsCheckedBeforePaging(t *testing.T) {
	header := `{"files":{"a":{"size":3,"offset":"0","integrity":{"algorithm":"SHA256","hash":"` + digest([]byte("abc")) + `","blockSize":2,"blocks":["` + digest([]byte("ab")) + `","` + digest([]byte("c")) + `"]}}}}`
	p := input(t, "integrity.asar", testfixture.ASAR(header, []byte("abc")))
	r, err := InspectASAR(p, PageOptions{})
	if err != nil || r.Entries[0].IntegrityState != "declared-sha256-verified" {
		t.Fatalf("integrity %+v %v", r, err)
	}
	p = input(t, "mismatch.asar", testfixture.ASAR(header, []byte("abd")))
	if _, err := InspectASAR(p, PageOptions{}); err == nil {
		t.Fatal("accepted integrity mismatch")
	}
}
func TestJavaScriptASTAndApplicationPreserveCandidates(t *testing.T) {
	code := []byte(`import x from './bridge.js'; const unrelated="require('fake')"; function require(x){return x}; require('shadow'); ipcRenderer.invoke(channel); fetch('/api');`)
	p := input(t, "module.js", code)
	r, err := InspectJavaScript(p, JavaScriptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	imports, shadow, dynamic := 0, 0, false
	for _, f := range r.Facts {
		if f.Kind == "import" {
			imports++
		}
		if f.Kind == "shadowed-module-call" {
			shadow++
		}
		if f.Kind == "electron-api-candidate" && f.Dynamic {
			dynamic = true
		}
		if f.Kind == "module-request" {
			t.Fatalf("shadow/string invented module: %+v", f)
		}
	}
	if imports != 1 || shadow != 1 || !dynamic {
		t.Fatalf("facts %+v", r)
	}
	if _, err := InspectJavaScript(input(t, "bad.js", []byte("function {")), JavaScriptOptions{}); err == nil {
		t.Fatal("accepted malformed JS")
	}
	a := input(t, "app.asar", testfixture.JavaScriptASAR())
	graph, err := InspectApplication(a, PageOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(graph.Modules) != 4 || graph.ExecutionPerformed {
		t.Fatalf("graph %+v", graph)
	}
	found := false
	for _, m := range graph.Modules {
		if m.Path == "main.js" {
			for _, rel := range m.Relations {
				if rel.Specifier == "./bridge.js" && rel.Resolution == "admitted-path-candidate" && len(rel.Candidates) == 1 && rel.Candidates[0] == "bridge.js" {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatalf("missing declared module relationship: %+v", graph)
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.js"), []byte("import './b.js'"), 0o600)
	os.WriteFile(filepath.Join(dir, "b.js"), []byte("export const b=1"), 0o600)
	first, err := InspectApplication(dir, PageOptions{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "b.js"), []byte("export const b=2"), 0o600)
	if _, err := InspectApplication(dir, PageOptions{Offset: 1, ExpectedSHA256: first.SHA256}); err == nil {
		t.Fatal("directory digest fence failed")
	}
}
func TestManagedMetadataCILAndComparisonUseBuildLocalTokens(t *testing.T) {
	p := input(t, "demo.dll", testfixture.Managed(42))
	r, err := InspectManaged(p, PageOptions{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !r.MetadataAvailable || r.Assembly != "Demo" || r.MVID != "12345678-9abc-def0-0102-030405060708" || r.TotalMethods != 2 || r.Methods[0].DeclaringType != "Example.Program" || len(r.NativeImports) != 1 || r.NativeImports[0].EntryPoint != "GetTickCount" {
		t.Fatalf("metadata %+v", r)
	}
	il, err := InspectManagedMethod(p, ManagedMethodOptions{Token: "0x06000001"})
	if err != nil {
		t.Fatal(err)
	}
	if il.TotalInstructions != 3 || il.Instructions[1].Opcode != "call" || il.Instructions[1].Token != "0x06000002" || il.Instructions[1].TargetName != "Native" || il.Instructions[1].Relationship != "declared-call" || il.ExecutionPerformed {
		t.Fatalf("CIL %+v", il)
	}
	unavailable, err := InspectManagedMethod(p, ManagedMethodOptions{Token: "0x06000002"})
	if err != nil || unavailable.BodyAvailable {
		t.Fatalf("native body %+v %v", unavailable, err)
	}
	other := input(t, "other.dll", testfixture.Managed(43))
	c, err := CompareManaged(p, other, CompareOptions{})
	if err != nil {
		t.Fatal(err)
	}
	changed := false
	for _, i := range c.Items {
		if i.ILComparable && !i.SameILBytes {
			changed = true
		}
	}
	if !changed {
		t.Fatalf("missed changed CIL: %+v", c)
	}
	if _, err := CompareManaged(p, other, CompareOptions{PageOptions: PageOptions{ExpectedSHA256: strings.Repeat("0", 64)}}); err == nil {
		t.Fatal("comparison digest fence failed")
	}
	for _, il := range [][]byte{{0x2b, 0xff, 0x2a}, {0xfe}, {0x28, 1}, {0x45, 0xff, 0xff, 0xff, 0xff}, {0xf7}} {
		if _, err := (&metadata{}).decodeCIL(il); err == nil {
			t.Fatalf("accepted invalid CIL %x", il)
		}
	}
	bad := testfixture.Managed(42)
	for i := 0x300; i < 0x304; i++ {
		bad[i] = 0
	}
	if _, err := InspectManaged(input(t, "bad.dll", bad), PageOptions{}); err == nil {
		t.Fatal("accepted malformed metadata")
	}
}
func TestPortableContainersGoMetadataEVMAndZIP(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	goInfo, err := InspectGoBinary(exe, PageOptions{})
	if err != nil || !goInfo.BuildInfoAvailable || goInfo.ExecutionPerformed {
		t.Fatalf("Go executable %+v %v", goInfo, err)
	}
	layout, err := targetidentity.InspectBounded(input(t, "layout.dll", testfixture.Managed(1)), MaxArtifactBytes)
	if err != nil || layout.Format != "pe" || layout.PE.Machine != "i386" || len(layout.PE.Sections) != 1 {
		t.Fatalf("layout %+v %v", layout, err)
	}
	p := input(t, "evm.hex", []byte("0x63a9059cbb1460105700"))
	evm, err := InspectEVM(context.Background(), p, EVMOptions{PageOptions: PageOptions{Limit: 2}})
	if err != nil || evm.TotalInstructions != 5 || evm.Instructions[0].Offset != 0 || len(evm.Selectors) != 1 || evm.Selectors[0].Value != "0xa9059cbb" || evm.CoverageComplete {
		t.Fatalf("EVM %+v %v", evm, err)
	}
	if _, err := InspectEVM(context.Background(), input(t, "truncated", []byte("63ab")), EVMOptions{}); err == nil {
		t.Fatal("accepted truncated PUSH")
	}
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	w, _ := z.Create("app/main.js")
	w.Write([]byte("hello"))
	z.Close()
	p = input(t, "app.zip", b.Bytes())
	zr, err := InspectZIP(p, PageOptions{})
	if err != nil || zr.TotalEntries != 1 {
		t.Fatalf("zip %+v %v", zr, err)
	}
	read, err := ReadZIP(p, EntryReadOptions{Entry: "app/main.js", Limit: 2, ExpectedSHA256: zr.SHA256})
	if err != nil || !read.CRCVerified || read.CoverageComplete || read.NextOffset == nil {
		t.Fatalf("read %+v %v", read, err)
	}
	b.Reset()
	z = zip.NewWriter(&b)
	z.Create("../escape")
	z.Close()
	if _, err := InspectZIP(input(t, "bad.zip", b.Bytes()), PageOptions{}); err == nil {
		t.Fatal("accepted ZIP traversal")
	}
}
