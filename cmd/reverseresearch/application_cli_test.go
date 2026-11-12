package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reverseresearch/internal/appinspect"
	"reverseresearch/internal/appinspect/testfixture"
	corefixture "reverseresearch/internal/dfir/testfixture"
	applefixture "reverseresearch/internal/iosinspect/testfixture"
	"strings"
	"testing"
)

func TestREAApplicationCLIPreservesIdentityAndFailureSemantics(t *testing.T) {
	root, _ := isolatedCLIRoot(t)
	assembly := filepath.Join(t.TempDir(), "demo.dll")
	os.WriteFile(assembly, testfixture.Managed(42), 0o600)
	asar := filepath.Join(t.TempDir(), "app.asar")
	os.WriteFile(asar, testfixture.JavaScriptASAR(), 0o600)
	input := func(name string, b []byte) string {
		p := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(p, b, 0600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	tar := input("app.tar", testfixture.TAR())
	plist := input("blob.plist", []byte(`<plist><data>AP8=</data></plist>`))
	keyed := input("keyed.plist", []byte(applefixture.KeyedXML))
	nib := input("view.nib", applefixture.NIB())
	core := input("recorded.core", corefixture.Core())
	hap := input("entry.hap", testfixture.HarmonyZIP())
	goRaw := input("old-go.exe", testfixture.GoMetadataPE(testfixture.GoPointerRecord(true), 1024))
	packageASAR := input("package-app.asar", testfixture.JavaScriptPackageASAR())
	bundleASAR := input("bundle-app.asar", testfixture.JavaScriptBundlerASAR())
	for _, call := range []struct {
		args  []string
		field string
		want  any
	}{
		{[]string{"app", "managed", assembly, "--limit", "1"}, "mvid", "12345678-9abc-def0-0102-030405060708"},
		{[]string{"app", "method", assembly, "--token", "0x06000001"}, "total_instructions", float64(3)},
		{[]string{"app", "analyze", asar, "--limit", "1"}, "total_modules", float64(4)},
		{[]string{"app", "analyze", packageASAR}, "package_manifests", float64(2)},
		{[]string{"app", "analyze", bundleASAR}, "total_virtual_modules", float64(2)},
		{[]string{"app", "javascript", bundleASAR, "--entry", "bundle.js"}, "content_sha256", fmt.Sprintf("%x", sha256.Sum256([]byte(testfixture.JavaScriptBundlerSource)))},
		{[]string{"app", "read", asar, "--entry", "link.js"}, "execution_performed", false},
		{[]string{"app", "tar", tar}, "total_entries", float64(1)},
		{[]string{"app", "package", hap, "--family", "harmony"}, "packaging_model_hint", "stage-path"},
		{[]string{"app", "go-read", goRaw, "--part", "module"}, "build_info_available", true},
		{[]string{"app", "tar-read", tar, "--entry", "app/main.txt"}, "data_base64", "YWJj"},
		{[]string{"ios", "plist", plist}, "total_objects", float64(1)},
		{[]string{"ios", "plist-data", plist, "--object-index", "0"}, "data_base64", "AP8="},
		{[]string{"ios", "keyed", keyed}, "reference_resolution_complete", false},
		{[]string{"ios", "nib", nib, "--view", "values"}, "total_values", float64(3)},
		{[]string{"crash", "inspect", core, "--view", "threads"}, "total_threads", float64(2)},
		{[]string{"crash", "note", core, "--note-index", "3"}, "data_base64", "AQID"},
		{[]string{"web", "locate", filepath.Join(root, "testdata", "rea-web-source.map"), "--line", "0", "--column", "0"}, "network_interaction", false},
		{[]string{"web", "har-api", filepath.Join(root, "testdata", "rea-web-capture.har")}, "total_entries", float64(2)},
	} {
		var out, errout bytes.Buffer
		if err := runMain(context.Background(), root, call.args, &out, &errout); err != nil {
			t.Fatalf("%v: %v %s", call.args, err, errout.String())
		}
		var v map[string]any
		if err := json.Unmarshal(out.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		if v[call.field] != call.want {
			t.Fatalf("%v result %+v", call.args, v)
		}
		if call.field == "total_virtual_modules" {
			var graph appinspect.ApplicationReport
			if err := json.Unmarshal(out.Bytes(), &graph); err != nil {
				t.Fatal(err)
			}
			if len(graph.Modules) != 1 || len(graph.Modules[0].VirtualModules) != 2 || len(graph.Modules[0].Relations) != 2 || graph.Modules[0].Relations[0].Resolution != "bundle-module-candidate" || len(graph.Modules[0].Relations[0].Candidates) != 0 {
				t.Fatalf("CLI bundle graph %+v", graph)
			}
		}
		if call.field == "package_manifests" {
			var graph appinspect.ApplicationReport
			if err := json.Unmarshal(out.Bytes(), &graph); err != nil {
				t.Fatal(err)
			}
			resolved := map[string]string{}
			for _, module := range graph.Modules {
				if module.Path == "main.js" {
					for _, rel := range module.Relations {
						if rel.Resolution == "admitted-path-candidate" && len(rel.Candidates) == 1 {
							resolved[rel.Specifier] = rel.Candidates[0]
						}
					}
				}
			}
			if resolved["#entry"] != "esm.mjs" || resolved["pkg"] != "node_modules/pkg/index.cjs" || graph.ExecutionPerformed {
				t.Fatalf("CLI package relation contract: %+v", graph)
			}
		}
	}
	for _, args := range [][]string{{"app", "managed", assembly, "--expected-sha256", strings.Repeat("0", 64)}, {"app", "method", assembly, "--token", "0x06000099"}, {"app", "managed", assembly, "--encoding", "raw"}, {"ios", "plist", plist, "--root", "x"}, {"ios", "plist-data", plist, "--object-index", "10"}, {"crash", "inspect", core, "--expected-sha256", strings.Repeat("0", 64)}, {"crash", "note", core, "--note-index", "10"}, {"app", "tar-read", tar, "--entry", "absent"}} {
		var out, errout bytes.Buffer
		if err := runMain(context.Background(), root, args, &out, &errout); err == nil || out.Len() != 0 {
			t.Fatalf("failure semantics: %v err=%v stdout=%s", args, err, out.String())
		}
	}
}
