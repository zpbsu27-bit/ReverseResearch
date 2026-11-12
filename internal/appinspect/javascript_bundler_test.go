package appinspect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reverseresearch/internal/appinspect/testfixture"
	"strings"
	"testing"
)

const webpackBundleFixture = testfixture.JavaScriptBundlerSource

func bundleKinds(t *testing.T, source string) map[string][]JavaScriptFact {
	t.Helper()
	facts, err := javascriptFacts([]byte(source))
	if err != nil {
		t.Fatal(err)
	}
	rows := map[string][]JavaScriptFact{}
	for _, f := range facts {
		rows[f.Kind] = append(rows[f.Kind], f)
		if f.Ordinal < 0 || f.ASTNode < 1 {
			t.Fatal("identity missing")
		}
	}
	return rows
}
func TestJavaScriptBundlerWebpackBindingsAndOriginalBytes(t *testing.T) {
	rows := bundleKinds(t, webpackBundleFixture)
	if len(rows["bundle-registration-candidate"]) != 1 || len(rows["bundle-module-candidate"]) != 2 || len(rows["bundle-module-request"]) != 1 || len(rows["bundle-entry-candidate"]) != 1 || len(rows["bundle-async-chunk-candidate"]) != 2 {
		t.Fatalf("counts: %+v", rows)
	}
	if rows["bundle-module-request"][0].Value != "1" || rows["bundle-entry-candidate"][0].Value != "0" {
		t.Fatal("shadow or nested runtime call was promoted")
	}
	if len(rows["bundle-export-candidate"]) != 4 || rows["bundle-module-candidate"][0].Bundle.RequireName != "r" {
		t.Fatal("local exports/require not recovered")
	}
	for _, f := range rows["bundle-module-candidate"] {
		b := f.Bundle
		r := b.SourceRange
		if b.Framework != "webpack" || b.Runtime != "webpackChunkDemo" || b.KeyState != "static" || r == nil || b.SourceSHA256 != digest([]byte(webpackBundleFixture[r.Start:r.End])) || b.RenderAlgorithm != "tdewolff-js-render-v1" || b.RenderSHA256 == "" || f.EpistemicState != "inferred" {
			t.Fatalf("factory: %+v", f)
		}
	}
	chunks := rows["bundle-chunk"]
	if len(chunks) != 2 || chunks[0].Dynamic || !chunks[1].Dynamic {
		t.Fatal("chunk unknown state lost")
	}
}

func TestJavaScriptBundlerRspackEsbuildAndBootstrap(t *testing.T) {
	rows := bundleKinds(t, strings.ReplaceAll(webpackBundleFixture, "webpackChunkDemo", "rspackChunkDemo"))
	if rows["bundle-module-candidate"][0].Bundle.Framework != "rspack" {
		t.Fatal("Rspack not recognized")
	}
	esbuild := `var require_a=__commonJS({"src/a.js"(exports,module){module.exports={value:42}}});var require_b=__commonJS({"src/b.js"(exports,module){exports.a=require_a()}});require_b();`
	rows = bundleKinds(t, esbuild)
	if len(rows["bundle-module-candidate"]) != 2 || len(rows["bundle-module-request"]) != 1 || rows["bundle-module-request"][0].BundleTarget == nil || rows["bundle-module-request"][0].BundleTarget.ModuleKey != "src/a.js" || len(rows["bundle-entry-candidate"]) != 1 || len(rows["bundle-export-candidate"]) != 2 {
		t.Fatalf("esbuild: %+v", rows)
	}
	bootstrap := `(()=>{var factories={0:function(m,e,r){r(1)},1:function(m,e,r){e.x=1}};var cache={};function load(id){var m={exports:{}};factories[id].call(m.exports,m,m.exports,load);return m.exports}load.c=cache;load(0)})();`
	rows = bundleKinds(t, bootstrap)
	if len(rows["bundle-module-candidate"]) != 2 || len(rows["bundle-entry-candidate"]) != 1 || len(rows["bundle-runtime-cache-candidate"]) != 1 || len(rows["bundle-module-request"]) != 1 {
		t.Fatalf("bootstrap: %+v", rows)
	}
	for _, source := range []string{
		strings.Replace(bootstrap, "factories[id].call(m.exports,m,m.exports,load)", "factories[other](m,m.exports,load)", 1),
		strings.Replace(bootstrap, "load(0)", "factories=other;load(0)", 1),
		strings.Replace(bootstrap, "load(0)", "load=other;load(0)", 1),
		strings.Replace(bootstrap, "factories[id].call(m.exports,m,m.exports,load)", "factories[id].call(other,m,m.exports,load)", 1),
	} {
		if got := bundleKinds(t, source); len(got["bundle-module-candidate"]) != 0 {
			t.Fatal("non-bootstrap promoted")
		}
	}
}

func TestJavaScriptBundlerUncertaintyAndReassignedBindings(t *testing.T) {
	rows := bundleKinds(t, `self.webpackChunkX.push([[0],{1:(a,b,c)=>c(2),1:(a,b,c)=>c(dynamic),[key]:(a,b,c)=>c(3),...other,2:()=>0}]);`)
	modules := rows["bundle-module-candidate"]
	if len(modules) != 4 || modules[0].Bundle.KeyState != "ambiguous" || modules[1].Bundle.KeyState != "ambiguous" || modules[2].Bundle.KeyState != "unknown" || modules[3].Bundle.KeyState != "ambiguous" || len(rows["bundle-table-boundary"]) != 1 || !rows["bundle-module-request"][1].Dynamic {
		t.Fatalf("uncertainty: %+v", rows)
	}
	for _, assignment := range []string{"c=other", "[c]=other", "({x:c}=other)", "c++"} {
		source := `self.webpackChunkX.push([[0],{1:(a,b,c)=>{` + assignment + `;c(2)}}]);`
		rows = bundleKinds(t, source)
		if len(rows["bundle-module-request"]) != 0 || len(rows["bundle-loader-binding-unavailable"]) != 1 {
			t.Fatalf("assigned binding promoted: %s", assignment)
		}
	}
	rows = bundleKinds(t, `self.webpackChunkX.push([[0],{1:(a,b,c)=>{function c(){};c(2)}}]);`)
	if len(rows["bundle-module-request"]) != 0 {
		t.Fatal("hoisted loader replacement promoted")
	}
	rows = bundleKinds(t, `var a=__esm({"a.js"(){}});a=other;var b=__esm({"b.js"(){a()}});b();`)
	if len(rows["bundle-module-request"]) != 0 {
		t.Fatal("reassigned esbuild wrapper promoted")
	}
	rows = bundleKinds(t, `self.webpackChunkX.push([[0],{0x10:()=>0,1e2:()=>0,9007199254740993:()=>0,[dynamic]:()=>0}]);`)
	if m := rows["bundle-module-candidate"]; m[0].Bundle.ModuleKey != "16" || m[1].Bundle.ModuleKey != "100" || m[2].Bundle.KeyState != "unknown" || m[3].Bundle.KeyState != "unknown" {
		t.Fatal("numeric key rounded or guessed")
	}
	rows = bundleKinds(t, `self.webpackChunkX.push([[0],{a:()=>0,\u0061:()=>1}]);`)
	if m := rows["bundle-module-candidate"]; len(m) != 2 || m[0].Bundle.KeyState != "ambiguous" || m[1].Bundle.KeyState != "unknown" {
		t.Fatal("escaped identifier key collapsed without evidence")
	}
	rows = bundleKinds(t, `self.webpackChunkX.push([[0],[null,,(a,b,c)=>c(3),()=>0]]);`)
	if m := rows["bundle-module-candidate"]; len(m) != 2 || m[0].Bundle.ModuleKey != "2" || m[1].Bundle.ModuleKey != "3" || m[0].Bundle.KeyState != "static" {
		t.Fatal("array holes shifted factory indices")
	}
	rows = bundleKinds(t, `self.webpackChunkX.push([[0],[...other,(a,b,c)=>c(0)]]);`)
	if m := rows["bundle-module-candidate"]; len(m) != 1 || m[0].Bundle.KeyState != "unknown" {
		t.Fatal("array spread offset guessed")
	}
}

func TestJavaScriptBundlerPagingComparisonAndBudgets(t *testing.T) {
	p := input(t, "bundle.js", []byte(webpackBundleFixture))
	r, err := InspectJavaScript(p, JavaScriptOptions{PageOptions: PageOptions{Limit: 1}})
	if err != nil || len(r.Facts) != 1 || r.NextOffset == nil || r.CoverageComplete {
		t.Fatalf("page: %v %+v", err, r)
	}
	if _, err = InspectJavaScript(p, JavaScriptOptions{PageOptions: PageOptions{ExpectedSHA256: strings.Repeat("0", 64)}}); err == nil {
		t.Fatal("stale snapshot admitted")
	}
	right := input(t, "changed.js", []byte(strings.Replace(webpackBundleFixture, "42", "43", 1)))
	comparison, err := CompareJavaScript(p, right, CompareOptions{})
	if err != nil {
		t.Fatal(err)
	}
	changed := false
	for _, item := range comparison.Items {
		if strings.Contains(item.Identity, "source_sha256") && item.LeftCount != item.RightCount {
			changed = true
		}
	}
	if !changed {
		t.Fatal("factory body changes absent from comparison")
	}
	for _, source := range []string{
		strings.Repeat(`self.webpackChunkX.push([[0],{1:()=>0}]);`, 257),
		`self.webpackChunkX.push([[0],{` + strings.Repeat(`x:()=>0,`, 4097) + ` }]);`,
		`self.webpackChunkX.push([[0],{"` + strings.Repeat("x", 4097) + `":()=>0}]);`,
		webpackBundleFixture + ` function broken(`,
	} {
		bad := input(t, "bad.js", []byte(source))
		if _, err := InspectJavaScript(bad, JavaScriptOptions{PageOptions: PageOptions{Limit: 1}}); err == nil {
			t.Fatal("hidden/overbudget bundle admitted")
		}
	}
	// The same content hash fence applies to bundle source, not a normalized AST.
	if err := os.WriteFile(filepath.Clean(p), []byte(webpackBundleFixture+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectJavaScript(p, JavaScriptOptions{PageOptions: PageOptions{ExpectedSHA256: r.SHA256}}); err == nil {
		t.Fatal("source byte edit missed")
	}
}

func TestJavaScriptBundlerIndependentProducers(t *testing.T) {
	var receipt struct {
		TargetExecuted bool              `json:"targetExecuted"`
		WebpackVersion string            `json:"webpackVersion"`
		EsbuildVersion string            `json:"esbuildVersion"`
		IDs            map[string]string `json:"webpackModuleIds"`
		Outputs        map[string]struct {
			Bytes int    `json:"bytes"`
			SHA   string `json:"sha256"`
		} `json:"outputs"`
	}
	body, err := os.ReadFile("testdata/bundlers/producer.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(body, &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.TargetExecuted || receipt.WebpackVersion != "5.102.1" || receipt.EsbuildVersion != "0.25.10" {
		t.Fatal("producer provenance changed")
	}
	for _, name := range []string{"webpack.cjs", "esbuild.cjs"} {
		raw, err := os.ReadFile("testdata/bundlers/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) != receipt.Outputs[name].Bytes || digest(raw) != receipt.Outputs[name].SHA {
			t.Fatal("producer bytes changed")
		}
		rows := bundleKinds(t, string(raw))
		if len(rows["bundle-module-candidate"]) < 2 {
			t.Fatalf("producer %s: modules %+v", name, rows)
		}
		found := false
		for _, f := range rows["bundle-module-request"] {
			if name == "webpack.cjs" && f.Bundle.ModuleKey == receipt.IDs["a.cjs"] && f.Value == receipt.IDs["dep.cjs"] && !f.Dynamic {
				found = true
			}
			if name == "esbuild.cjs" && f.Bundle.ModuleKey == "a.cjs" && f.BundleTarget != nil && f.BundleTarget.ModuleKey == "dep.cjs" {
				found = true
			}
		}
		if !found {
			t.Fatalf("producer %s: a -> dep not recovered %+v", name, rows)
		}
	}
}

func TestJavaScriptBundlerASARByteIdentity(t *testing.T) {
	p := input(t, "bundle.asar", testfixture.JavaScriptBundlerASAR())
	r, err := InspectJavaScript(p, JavaScriptOptions{Entry: "bundle.js"})
	if err != nil {
		t.Fatal(err)
	}
	if r.SHA256 == r.ContentSHA256 || r.ContentSHA256 != digest([]byte(webpackBundleFixture)) {
		t.Fatal("archive/entry identities mixed")
	}
	for _, f := range r.Facts {
		if f.Kind == "bundle-module-candidate" {
			span := f.Bundle.SourceRange
			if f.Bundle.SourceSHA256 != digest([]byte(webpackBundleFixture[span.Start:span.End])) {
				t.Fatal("range was not relative to selected entry bytes")
			}
		}
	}
	graph, err := InspectApplication(p, PageOptions{})
	if err != nil || graph.TotalVirtualModules != 2 || len(graph.Modules) != 1 || len(graph.Modules[0].VirtualModules) != 2 {
		t.Fatalf("ASAR graph: %v %+v", err, graph)
	}
}

func TestApplicationBundlerCrossChunkUncertaintyAndPreview(t *testing.T) {
	root := t.TempDir()
	write := func(name, source string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("a.js", `self.webpackChunkX.push([[1],{1:(m,e,r)=>r(2)}]);`)
	write("b.js", `self.webpackChunkX.push([[2],{2:()=>0}]);`)
	r, err := InspectApplication(root, PageOptions{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if r.TotalVirtualModules != 2 || r.CoverageComplete || len(r.Modules[0].Relations) != 1 {
		t.Fatalf("cross-chunk page: %+v", r)
	}
	rel := r.Modules[0].Relations[0]
	if rel.Resolution != "bundle-module-candidate" || len(rel.Candidates) != 0 || len(rel.VirtualCandidates) != 1 || rel.VirtualCandidates[0].Path != "b.js" {
		t.Fatalf("virtual relation became file resolution: %+v", rel)
	}
	write("b.js", `self.webpackChunkX.push([[2],{2:()=>0,2:()=>1}]);`)
	r, err = InspectApplication(root, PageOptions{Limit: 1})
	if err != nil || r.Modules[0].Relations[0].Resolution != "bundle-target-ambiguous" {
		t.Fatal("duplicate key selected uniquely")
	}
	write("b.js", `self.webpackChunkX.push([[2],{2:()=>0,[unknown]:()=>1}]);`)
	r, err = InspectApplication(root, PageOptions{Limit: 1})
	if err != nil || r.Modules[0].Relations[0].Resolution != "bundle-target-ambiguous" {
		t.Fatal("computed key selected uniquely")
	}
	write("b.js", `function broken(`)
	if _, err = InspectApplication(root, PageOptions{Limit: 1}); err == nil {
		t.Fatal("hidden invalid module skipped by pagination")
	}
	write("b.js", "")
	write("a.js", `self.webpackChunkX.push([[1],{1:(m,e,r)=>{`+strings.Repeat(`r.e(2);`, 80)+`}}]);`)
	r, err = InspectApplication(root, PageOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if r.Modules[0].BundleFactCount < 80 || len(r.Modules[0].BundlePreview) != 64 || r.Modules[0].BundlePreviewComplete || r.CoverageComplete {
		t.Fatal("truncated preview reported complete")
	}
}
