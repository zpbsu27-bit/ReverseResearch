package appinspect

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reverseresearch/internal/appinspect/testfixture"
	"strings"
	"testing"
	"time"
)

func applicationTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func applicationRelation(t *testing.T, report ApplicationReport, source, specifier, loader string) ModuleRelation {
	t.Helper()
	for _, module := range report.Modules {
		if module.Path != source {
			continue
		}
		for _, relation := range module.Relations {
			if relation.Specifier == specifier && relation.Loader == loader {
				return relation
			}
		}
	}
	t.Fatalf("missing relation %s %s %s", source, specifier, loader)
	return ModuleRelation{}
}

func TestApplicationPackageMapsAndLoaderOrder(t *testing.T) {
	files := map[string]string{
		"main.js":      `import './lib'; require('./lib'); import '#internal'; require('#internal'); import 'app'; require('dep'); import 'dep'; import 'dep/feature/a'; import 'dep/private'; import 'dep/missing'; import 'dep/encoded'; require('legacy'); import 'legacy/sub'; require('legacy/sub'); import 'dep/data';`,
		"package.json": `{"name":"app","imports":{"#internal":{"import":"./esm.js","require":"./cjs.cjs"}},"exports":{"default":"./default.js","import":"./esm.js"}}`,
		"lib.js":       "export const x=1", "lib/index.js": "export const y=1", "esm.js": "", "cjs.cjs": "", "default.js": "",
		"node_modules/dep/package.json": `{"exports":{".":{"import":"./import.mjs","require":"./require.cjs"},"./feature/*":"./features/*.js","./private":null,"./missing":["bad-target","./absent.js","./import.mjs"],"./encoded":["./features%2fa.js","./import.mjs"],"./data":"./data.json"}}`,
		"node_modules/dep/import.mjs":   "", "node_modules/dep/require.cjs": "", "node_modules/dep/features/a.js": "", "node_modules/dep/data.json": "{}",
		"node_modules/legacy/package.json": `{"main":"entry"}`, "node_modules/legacy/entry.js": "", "node_modules/legacy/sub.js": "",
	}
	dir := applicationTree(t, files)
	r, err := InspectApplication(dir, PageOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ specifier, loader, state, candidate string }{
		{"./lib", "import", "not-found", ""}, {"./lib", "require", "admitted-path-candidate", "lib.js"},
		{"#internal", "import", "admitted-path-candidate", "esm.js"}, {"#internal", "require", "admitted-path-candidate", "cjs.cjs"},
		{"app", "import", "admitted-path-candidate", "default.js"}, {"dep", "import", "admitted-path-candidate", "node_modules/dep/import.mjs"},
		{"dep", "require", "admitted-path-candidate", "node_modules/dep/require.cjs"}, {"dep/feature/a", "import", "admitted-path-candidate", "node_modules/dep/features/a.js"},
		{"dep/private", "import", "package-map-blocked", ""}, {"dep/missing", "import", "not-found", ""}, {"dep/encoded", "import", "rejected", ""},
		{"legacy", "require", "admitted-path-candidate", "node_modules/legacy/entry.js"}, {"legacy/sub", "import", "not-found", ""},
		{"legacy/sub", "require", "admitted-path-candidate", "node_modules/legacy/sub.js"}, {"dep/data", "import", "admitted-path-candidate", "node_modules/dep/data.json"},
	} {
		rel := applicationRelation(t, r, "main.js", tc.specifier, tc.loader)
		if rel.Resolution != tc.state || (tc.candidate != "" && (len(rel.Candidates) != 1 || rel.Candidates[0] != tc.candidate)) || (tc.candidate == "" && len(rel.Candidates) != 0) {
			t.Errorf("%s %s: %+v", tc.loader, tc.specifier, rel)
		}
		if !strings.HasPrefix(tc.specifier, ".") && len(rel.Packages) == 0 {
			t.Errorf("missing package provenance: %+v", rel)
		}
		for _, p := range rel.Packages {
			if !p.Available || len(p.SHA256) != 64 {
				t.Errorf("bad metadata reference: %+v", p)
			}
		}
	}
	if r.PackageManifests != 3 || r.ExecutionPerformed || r.NetworkInteraction {
		t.Fatalf("bad scope %+v", r)
	}
}

func TestApplicationPackageFailureSemantics(t *testing.T) {
	for _, tc := range []struct{ name, metadata, specifier, state, target string }{
		{"condition-order", `{"exports":{"default":"./fallback.js","node":"./chosen.js"}}`, "pkg", "admitted-path-candidate", "./fallback.js"},
		{"nested-unmatched", `{"exports":{"node":{"custom":"./chosen.js"},"default":"./fallback.js"}}`, "pkg", "admitted-path-candidate", "./fallback.js"},
		{"null-array", `{"exports":[null,"./chosen.js"]}`, "pkg", "admitted-path-candidate", "./chosen.js"},
		{"invalid-array", `{"exports":[4,"../bad.js","./chosen.js"]}`, "pkg", "admitted-path-candidate", "./chosen.js"},
		{"empty-array", `{"exports":[]}`, "pkg", "package-map-blocked", ""},
		{"numeric-condition", `{"exports":[{"0":"./chosen.js"},"./fallback.js"]}`, "pkg", "invalid-package-config", ""},
		{"mixed-keys", `{"exports":{".":"./chosen.js","default":"./fallback.js"}}`, "pkg", "invalid-package-config", ""},
		{"no-encapsulation-fallback", `{"exports":{".":"./chosen.js"},"main":"./fallback.js"}`, "pkg/fallback.js", "package-map-unmatched", ""},
		{"forbidden-array-fallback", `{"exports":["./%2e%2e/out.js","./chosen.js"]}`, "pkg", "admitted-path-candidate", "./chosen.js"},
		{"pattern-specificity", `{"exports":{"./*":"./fallback.js","./feature/*":"./chosen.js"}}`, "pkg/feature/a", "admitted-path-candidate", "./chosen.js"},
		{"empty-pattern-match", `{"exports":{"./feature/*.js":"./chosen.js"}}`, "pkg/feature/.js", "package-map-unmatched", ""},
		{"query-identity", `{"exports":"./chosen.js?mode=test#one"}`, "pkg", "admitted-path-candidate", "./chosen.js?mode=test#one"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := applicationTree(t, map[string]string{"main.js": "import " + strconvJSON(tc.specifier), "node_modules/pkg/package.json": tc.metadata, "node_modules/pkg/chosen.js": "", "node_modules/pkg/fallback.js": ""})
			r, err := InspectApplication(dir, PageOptions{})
			if err != nil {
				t.Fatal(err)
			}
			rel := applicationRelation(t, r, "main.js", tc.specifier, "import")
			if rel.Resolution != tc.state || rel.Target != tc.target {
				t.Fatalf("%+v", rel)
			}
		})
	}
}

func strconvJSON(s string) string { b, _ := json.Marshal(s); return string(b) }

func TestApplicationPackageSnapshotAndValidationBeforePaging(t *testing.T) {
	dir := applicationTree(t, map[string]string{"a.js": "import '#x'", "b.js": "", "package.json": `{"imports":{"#x":"./b.js"}}`})
	first, err := InspectApplication(dir, PageOptions{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"imports":{"#x":null}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectApplication(dir, PageOptions{Offset: 1, ExpectedSHA256: first.SHA256}); err == nil {
		t.Fatal("metadata change did not fence pagination")
	}
	second, err := InspectApplication(dir, PageOptions{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "empty"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectApplication(dir, PageOptions{Offset: 1, ExpectedSHA256: second.SHA256}); err == nil {
		t.Fatal("directory boundary change did not fence pagination")
	}
	for _, body := range []string{`{"imports":{},"imports":{}}`, `null`, `[]`, string([]byte{0xff}), `{"exports":{"default":{"x":1,"x":2}}}`} {
		if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := InspectApplication(dir, PageOptions{Limit: 1}); err == nil {
			t.Fatalf("malformed/unselected metadata accepted %q", body)
		}
	}
}

func TestApplicationPackageScopesAndAncestorLookup(t *testing.T) {
	dir := applicationTree(t, map[string]string{
		"package.json": `{"imports":{"#x":"./root.js"}}`, "root.js": "",
		"nested/package.json": `{"name":"nested","exports":"./target.js"}`, "nested/target.js": "",
		"nested/main.js":            `import '#x'; import 'nested'; require('dep'); require('fs');`,
		"node_modules/dep/index.js": "", "nested/node_modules/dep/package.json": `{"main":"missing"}`,
		"nested/node_modules/fs/index.js": "",
	})
	r, err := InspectApplication(dir, PageOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ specifier, loader, state string }{
		{"#x", "import", "package-map-unmatched"}, {"nested", "import", "admitted-path-candidate"},
		{"dep", "require", "not-found"}, {"fs", "require", "external-or-unresolved"},
	} {
		if got := applicationRelation(t, r, "nested/main.js", tc.specifier, tc.loader); got.Resolution != tc.state {
			t.Errorf("%+v", got)
		}
	}
}

func TestApplicationPackageASARAndUnavailableMetadata(t *testing.T) {
	main := []byte(`import '#x'`)
	pkg := []byte(`{"imports":{"#x":"./target.js"}}`)
	header := map[string]any{"files": map[string]any{"main.js": map[string]any{"size": len(main), "offset": "0"}, "package.json": map[string]any{"size": len(pkg), "offset": strconvJSONOffset(len(main))}, "target.js": map[string]any{"size": 0, "offset": strconvJSONOffset(len(main) + len(pkg))}}}
	b, _ := json.Marshal(header)
	file := input(t, "app.asar", testfixture.ASAR(string(b), append(main, pkg...)))
	r, err := InspectApplication(file, PageOptions{})
	if err != nil {
		t.Fatal(err)
	}
	got := applicationRelation(t, r, "main.js", "#x", "import")
	if len(got.Candidates) != 1 || got.Candidates[0] != "target.js" {
		t.Fatalf("%+v", got)
	}
	header["files"].(map[string]any)["package.json"] = map[string]any{"size": len(pkg), "unpacked": true}
	b, _ = json.Marshal(header)
	file = input(t, "unpacked.asar", testfixture.ASAR(string(b), append(main, pkg...)))
	r, err = InspectApplication(file, PageOptions{})
	if err != nil {
		t.Fatal(err)
	}
	got = applicationRelation(t, r, "main.js", "#x", "import")
	if got.Resolution != "unavailable" || len(got.Packages) != 1 || got.Packages[0].Available {
		t.Fatalf("%+v", got)
	}
}

func strconvJSONOffset(n int) string { b, _ := json.Marshal(n); return string(b) }

func TestApplicationUnreadFilesAndASARLinkBoundaries(t *testing.T) {
	dir := applicationTree(t, map[string]string{"main.js": `require('./shadow'); require('./folder/'); import './art.png';`, "shadow": "", "shadow.js": "", "folder/index.js": "", "folder.js": "", "art.png": ""})
	r, err := InspectApplication(dir, PageOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, specifier := range []string{"./shadow", "./art.png"} {
		loader := "require"
		if specifier == "./art.png" {
			loader = "import"
		}
		rel := applicationRelation(t, r, "main.js", specifier, loader)
		if rel.Resolution != "unavailable" || len(rel.Candidates) != 0 {
			t.Fatalf("invented a fallback over an unread exact file: %+v", rel)
		}
	}
	rel := applicationRelation(t, r, "main.js", "./folder/", "require")
	if len(rel.Candidates) != 1 || rel.Candidates[0] != "folder/index.js" {
		t.Fatalf("trailing slash searched sibling extensions: %+v", rel)
	}
	main := []byte(`import 'dep'`)
	header := fmt.Sprintf(`{"files":{"main.js":{"size":%d,"offset":"0"},"node_modules":{"files":{"dep":{"link":"outside"}}}}}`, len(main))
	file := input(t, "linked.asar", testfixture.ASAR(header, main))
	r, err = InspectApplication(file, PageOptions{})
	if err != nil {
		t.Fatal(err)
	}
	rel = applicationRelation(t, r, "main.js", "dep", "import")
	if rel.Resolution != "unavailable" || len(rel.Candidates) != 0 {
		t.Fatalf("followed ASAR directory link: %+v", rel)
	}
}

func TestApplicationSnapshotResourceBudgets(t *testing.T) {
	for _, tc := range []struct {
		name        string
		count, size int
		directory   bool
	}{
		{"files", 2049, 0, false}, {"boundaries", 8193, 0, true}, {"file-bytes", 1, MaxJavaScriptBytes + 1, false}, {"selected-bytes", 33, MaxJavaScriptBytes, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]any{}
			for i := 0; i < tc.count; i++ {
				name := fmt.Sprintf("entry%04d.js", i)
				if tc.directory {
					files[name] = map[string]any{"files": map[string]any{}}
				} else {
					files[name] = map[string]any{"size": tc.size, "offset": fmt.Sprint(i * tc.size)}
				}
			}
			header, _ := json.Marshal(map[string]any{"files": files})
			file := input(t, "budget.asar", testfixture.ASAR(string(header), bytes.Repeat([]byte(" "), tc.count*tc.size)))
			if _, err := InspectApplication(file, PageOptions{Limit: 1}); err == nil {
				t.Fatal("resource budget was bypassed by paging")
			}
		})
	}
}

func TestApplicationIndependentNodeResolution(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("independent Node producer is unavailable")
	}
	dir := applicationTree(t, map[string]string{
		"entry.mjs": "", "entry.cjs": "", "package.json": `{"name":"self","imports":{"#x":{"import":"./esm.mjs","require":"./cjs.cjs"},"#pattern/*":"./features/*.js"},"exports":"./esm.mjs"}`,
		"esm.mjs": "", "cjs.cjs": "", "features/a.js": "", "rel.js": "", "..js": "", "index.js": "",
		"node_modules/pkg/package.json": `{"exports":{".":{"import":"./esm.mjs","require":"./cjs.cjs"},"./null-array":[null,"./esm.mjs"],"./invalid-array":[1,"./esm.mjs"],"./missing":["./absent.js","./esm.mjs"],"./private":null,"./encoded":["./x%2fy.js","./esm.mjs"],"./feature/*":"./features/*.js","./query":"./esm.mjs?one#two"}}`,
		"node_modules/pkg/esm.mjs":      "", "node_modules/pkg/cjs.cjs": "", "node_modules/pkg/features/a.js": "",
		"node_modules/legacy/package.json": `{"main":"./main"}`, "node_modules/legacy/main.js": "", "node_modules/legacy.js": "",
		"node_modules/@scope/pkg/package.json": `{"exports":"./index.js"}`, "node_modules/@scope/pkg/index.js": "",
	})
	type request struct {
		Specifier string `json:"specifier"`
		Loader    string `json:"loader"`
	}
	cases := []request{}
	for _, specifier := range []string{"#x", "#pattern/a", "self", "pkg", "pkg/null-array", "pkg/invalid-array", "pkg/missing", "pkg/private", "pkg/encoded", "pkg/feature/a", "pkg/query", "legacy", "legacy/", "@scope/pkg", "./rel", ".", "fs"} {
		for _, loader := range []string{"import", "require"} {
			cases = append(cases, request{specifier, loader})
		}
	}
	body, _ := json.Marshal(cases)
	// Only Node's own resolution APIs run. No inventoried module is imported,
	// required or evaluated, including the inert source-owned fixture files.
	const producer = `
import {createRequire} from 'node:module';
import {pathToFileURL,fileURLToPath} from 'node:url';
import {existsSync,statSync} from 'node:fs';
import {join,relative} from 'node:path';
const root=process.argv[1], cases=JSON.parse(process.argv[2]);
const output=cases.map(c=>{
  try {
    const entry=pathToFileURL(join(root,c.loader==='import'?'entry.mjs':'entry.cjs'));
    const result=c.loader==='import'?import.meta.resolve(c.specifier,entry.href):createRequire(entry).resolve(c.specifier);
    if(result.startsWith('node:') || result===c.specifier) return {...c,builtin:true};
    const p=c.loader==='import'?fileURLToPath(result):result;
    return {...c,path:relative(root,p).split('\\').join('/'),exists:existsSync(p)&&statSync(p).isFile()};
  } catch(e) { return {...c,error:e.code}; }
});
console.log(JSON.stringify({version:process.version,results:output}));
`
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, "--experimental-import-meta-resolve", "--input-type=module", "-e", producer, dir, string(body))
	cmd.Env = append(os.Environ(), "NODE_OPTIONS=", "NODE_PATH=")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("independent resolver: %v", err)
	}
	var observed struct {
		Version string `json:"version"`
		Results []struct {
			request
			Path    string `json:"path"`
			Exists  bool   `json:"exists"`
			Builtin bool   `json:"builtin"`
			Error   string `json:"error"`
		} `json:"results"`
	}
	if err := json.Unmarshal(out, &observed); err != nil {
		t.Fatal(err)
	}
	inputs, _, _, _, err := applicationInputs(dir)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := newApplicationResolver(inputs)
	if err != nil {
		t.Fatal(err)
	}
	if len(observed.Results) != len(cases) {
		t.Fatal("incomplete independent producer")
	}
	for _, row := range observed.Results {
		callee, source := "", "entry.mjs"
		if row.Loader == "require" {
			callee = "require"
			source = "entry.cjs"
		}
		rel := resolver.relation(source, JavaScriptFact{Kind: "module-request", Callee: callee, Value: row.Specifier})
		if row.Exists && row.Error == "" && !row.Builtin {
			if len(rel.Candidates) != 1 || rel.Candidates[0] != row.Path {
				t.Errorf("Node %s %s %s => %s, RR %+v", observed.Version, row.Loader, row.Specifier, row.Path, rel)
			}
		} else if len(rel.Candidates) != 0 {
			t.Errorf("Node refused/absent/builtin %+v; RR invented %+v", row, rel)
		}
	}
	t.Logf("independent Node %s: %d import/require resolutions", observed.Version, len(observed.Results))
}
