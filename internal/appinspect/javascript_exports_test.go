package appinspect

import (
	"strings"
	"testing"
)

func TestJavaScriptESMBindingAndExportShapes(t *testing.T) {
	facts, err := javascriptFacts([]byte(`import defaultName, {thing as renamed, simple} from './dep.mjs'; import * as all from './other.mjs'; export {renamed as publicName}; export * as others from './third.mjs'; export const {a: named, ...rest}=source, value=1; export default function(){}; export class Demo{}`))
	if err != nil {
		t.Fatal(err)
	}
	imports, exports := map[string]JavaScriptFact{}, map[string]JavaScriptFact{}
	for _, f := range facts {
		if f.Kind == "import-binding" {
			imports[f.LocalName] = f
		}
		if f.Kind == "export-binding" {
			exports[f.ExportName] = f
		}
	}
	if len(imports) != 4 || imports["renamed"].Callee != "thing" || imports["all"].Callee != "*" || imports["defaultName"].Module != "./dep.mjs" {
		t.Fatalf("imports %+v", imports)
	}
	if exports["publicName"].LocalName != "renamed" || exports["others"].Module != "./third.mjs" || exports["default"].ValueKind != "function" || exports["Demo"].ValueKind != "class" || exports["named"].LocalName != "named" || exports["rest"].LocalName != "rest" || exports["value"].ValueKind != "literal" {
		t.Fatalf("exports %+v", exports)
	}
}
func TestJavaScriptCommonJSCandidatesRemainScopedAndDynamic(t *testing.T) {
	facts, err := javascriptFacts([]byte(`module.exports={known:()=>1,['literal']:true,[dynamic]:unknown,...other}; exports.named=function(){}; function shadow(module,exports){module.exports={local:1};exports.x=2;}`))
	if err != nil {
		t.Fatal(err)
	}
	candidates, shadowed, dynamic := 0, 0, 0
	for _, f := range facts {
		switch f.Kind {
		case "commonjs-export-candidate":
			candidates++
			if f.EpistemicState != "inferred" {
				t.Fatal("candidate upgraded")
			}
		case "shadowed-export-assignment":
			shadowed++
		case "commonjs-export-member-candidate":
			if f.Dynamic {
				dynamic++
			}
		}
	}
	if candidates != 2 || shadowed != 2 || dynamic != 2 {
		t.Fatalf("scope counts %d %d %d %+v", candidates, shadowed, dynamic, facts)
	}
}
func TestJavaScriptBindingLabelsFailWithoutPanic(t *testing.T) {
	if _, err := javascriptFacts([]byte("import {x} from '" + strings.Repeat("x", 4097) + "';")); err == nil {
		t.Fatal("overlarge import label accepted")
	}
	left := input(t, "left.js", []byte(`export const run=()=>1;`))
	right := input(t, "right.js", []byte(`export const run={};`))
	r, err := CompareJavaScript(left, right, CompareOptions{})
	if err != nil {
		t.Fatal(err)
	}
	changed := false
	for _, v := range r.Items {
		if v.LeftCount != v.RightCount {
			changed = true
		}
	}
	if !changed {
		t.Fatal("export shape comparison lost new facts")
	}
}
