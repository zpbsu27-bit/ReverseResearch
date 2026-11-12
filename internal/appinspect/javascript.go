package appinspect

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/js"
	"strings"
	"unicode/utf8"
)

const MaxJavaScriptBytes = 1 << 20

type JavaScriptOptions struct {
	PageOptions
	Entry string `json:"entry,omitempty"`
}
type JavaScriptFact struct {
	Ordinal        int               `json:"ordinal"`
	ASTNode        int               `json:"ast_node"`
	Kind           string            `json:"kind"`
	Callee         string            `json:"callee,omitempty"`
	Value          string            `json:"value,omitempty"`
	LocalName      string            `json:"local_name,omitempty"`
	ExportName     string            `json:"export_name,omitempty"`
	Module         string            `json:"module,omitempty"`
	ValueKind      string            `json:"value_kind,omitempty"`
	Dynamic        bool              `json:"dynamic"`
	Authority      string            `json:"authority"`
	EpistemicState string            `json:"epistemic_state"`
	Bundle         *JavaScriptBundle `json:"bundle,omitempty"`
	BundleTarget   *JavaScriptBundle `json:"bundle_target,omitempty"`
}
type JavaScriptReport struct {
	Path               string           `json:"path"`
	SHA256             string           `json:"sha256"`
	Entry              string           `json:"entry,omitempty"`
	ContentSHA256      string           `json:"content_sha256"`
	Parser             string           `json:"parser"`
	BundlerProfile     string           `json:"bundler_profile"`
	TotalFacts         int              `json:"total_facts"`
	Offset             int              `json:"offset"`
	Facts              []JavaScriptFact `json:"facts"`
	NextOffset         *int             `json:"next_offset,omitempty"`
	CoverageComplete   bool             `json:"coverage_complete"`
	Limitations        []string         `json:"limitations"`
	ExecutionPerformed bool             `json:"execution_performed"`
	NetworkInteraction bool             `json:"network_interaction"`
}
type jsVisitor struct {
	nodes         int
	facts         []JavaScriptFact
	err           error
	bundles       *bundlerIndex
	bundleStack   []bundleFrame
	functionDepth int
}

type bundleFrame struct {
	scope *bundleScope
	depth int
}

func (v *jsVisitor) Enter(n js.INode) js.IVisitor {
	v.nodes++
	if v.nodes > 250000 || v.err != nil {
		v.err = errors.New("JavaScript AST exceeds node limit")
		return nil
	}
	if v.bundles != nil {
		switch n.(type) {
		case *js.FuncDecl, *js.ArrowFunc, *js.MethodDecl:
			v.functionDepth++
			if scope := v.bundles.scopes[n]; scope != nil {
				v.bundleStack = append(v.bundleStack, bundleFrame{scope: scope, depth: v.functionDepth})
			}
		}
		switch n.(type) {
		case *js.CallExpr, *js.FuncDecl, *js.ArrowFunc, *js.MethodDecl:
			for _, f := range v.bundles.rows[n] {
				v.addFact(f)
			}
		}
		v.bundleFacts(n)
	}
	emit := func(kind, callee, value string, dynamic bool) {
		if len(value) > 4096 {
			v.err = errors.New("JavaScript static label exceeds 4096 bytes")
			return
		}
		if len(v.facts) >= 100000 {
			v.err = errors.New("JavaScript fact count exceeds limit")
			return
		}
		state := "observed"
		if strings.HasSuffix(kind, "-candidate") {
			state = "inferred"
		}
		var bundle *JavaScriptBundle
		if len(v.bundleStack) > 0 {
			bundle = v.bundleStack[len(v.bundleStack)-1].scope.info
		}
		v.addFact(JavaScriptFact{Kind: kind, Callee: callee, Value: value, Dynamic: dynamic, Authority: "static-ast", EpistemicState: state, Bundle: bundle})
	}
	switch x := n.(type) {
	case *js.ImportStmt:
		s, ok := jsString(js.LiteralExpr{TokenType: js.StringToken, Data: x.Module})
		emit("import", "", s, !ok)
		binding := func(local, imported string) {
			before := len(v.facts)
			emit("import-binding", imported, local, !ok)
			if len(v.facts) == before {
				return
			}
			f := &v.facts[len(v.facts)-1]
			f.LocalName = local
			f.Module = s
		}
		if x.Default != nil {
			binding(string(x.Default), "default")
		}
		for _, a := range x.List {
			if a.Binding == nil {
				continue
			}
			imported := a.Name
			if imported == nil {
				imported = a.Binding
			}
			binding(string(a.Binding), string(imported))
		}
	case *js.ExportStmt:
		module, moduleOK := "", true
		if len(x.Module) > 0 {
			s, ok := jsString(js.LiteralExpr{TokenType: js.StringToken, Data: x.Module})
			emit("re-export", "", s, !ok)
			module, moduleOK = s, ok
		}
		binding := func(local, exported, kind string, dynamic bool) {
			before := len(v.facts)
			emit("export-binding", local, exported, dynamic || !moduleOK)
			if len(v.facts) == before {
				return
			}
			f := &v.facts[len(v.facts)-1]
			f.LocalName = local
			f.ExportName = exported
			f.Module = module
			f.ValueKind = kind
		}
		for _, a := range x.List {
			if a.Binding == nil {
				continue
			}
			local := a.Name
			if local == nil {
				local = a.Binding
			}
			binding(string(local), string(a.Binding), "binding-spelling", false)
		}
		if x.Default {
			binding(jsCallee(x.Decl), "default", jsValueKind(x.Decl), false)
		} else {
			switch decl := x.Decl.(type) {
			case *js.VarDecl:
				for _, b := range decl.List {
					if err := jsBindingNames(b.Binding, 0, func(name string) { binding(name, name, jsValueKind(b.Default), false) }); err != nil {
						v.err = err
					}
				}
			case *js.FuncDecl:
				if decl.Name != nil {
					binding(string(decl.Name.Name()), string(decl.Name.Name()), "function", false)
				}
			case *js.ClassDecl:
				if decl.Name != nil {
					binding(string(decl.Name.Name()), string(decl.Name.Name()), "class", false)
				}
			}
		}
	case *js.FuncDecl:
		if x.Name != nil {
			emit("function-declaration", "", string(x.Name.Name()), false)
		}
	case *js.CallExpr:
		callee := jsCallee(x.X)
		kind := ""
		switch callee {
		case "require", "import":
			kind = "module-request"
			if variable, ok := x.X.(*js.Var); ok {
				for variable.Link != nil {
					variable = variable.Link
				}
				if variable.Decl != js.NoDecl {
					kind = "shadowed-module-call"
				}
			}
		case "ipcMain.handle", "ipcMain.on", "ipcRenderer.send", "ipcRenderer.invoke", "contextBridge.exposeInMainWorld", "electron.ipcMain.handle", "electron.ipcMain.on", "electron.ipcRenderer.send", "electron.ipcRenderer.invoke", "electron.contextBridge.exposeInMainWorld":
			kind = "electron-api-candidate"
		case "fetch":
			kind = "endpoint-candidate"
			if variable, ok := x.X.(*js.Var); ok {
				for variable.Link != nil {
					variable = variable.Link
				}
				if variable.Decl != js.NoDecl {
					kind = "shadowed-endpoint-call"
				}
			}
		}
		if kind != "" {
			s, ok := "", false
			if len(x.Args.List) > 0 && !x.Args.List[0].Rest {
				s, ok = jsString(x.Args.List[0].Value)
			}
			emit(kind, callee, s, !ok)
		}
	case *js.NewExpr:
		callee := jsCallee(x.X)
		if callee == "BrowserWindow" || callee == "electron.BrowserWindow" {
			emit("electron-window-candidate", callee, "", false)
		}
	case *js.BinaryExpr:
		if x.Op != js.EqToken {
			break
		}
		callee := jsCallee(x.X)
		if callee != "module.exports" && !strings.HasPrefix(callee, "module.exports.") && !strings.HasPrefix(callee, "exports.") {
			break
		}
		kind := "commonjs-export-candidate"
		if root := jsRootVar(x.X); root != nil {
			for root.Link != nil {
				root = root.Link
			}
			if root.Decl != js.NoDecl {
				kind = "shadowed-export-assignment"
			}
		}
		before := len(v.facts)
		emit(kind, callee, jsValueKind(x.Y), false)
		if len(v.facts) > before {
			v.facts[len(v.facts)-1].ValueKind = jsValueKind(x.Y)
		}
		if kind == "commonjs-export-candidate" && callee == "module.exports" {
			if object, ok := x.Y.(*js.ObjectExpr); ok {
				for _, p := range object.List {
					name, dynamic := "", p.Spread || p.Name == nil
					if p.Name != nil {
						if p.Name.Computed != nil {
							var literal bool
							name, literal = jsString(p.Name.Computed)
							dynamic = !literal
						} else {
							name = string(p.Name.Literal.Data)
						}
					}
					before := len(v.facts)
					emit("commonjs-export-member-candidate", callee, name, dynamic)
					if len(v.facts) > before {
						f := &v.facts[len(v.facts)-1]
						f.ExportName = name
						f.ValueKind = jsValueKind(p.Value)
					}
				}
			}
		}
	}
	return v
}
func (v *jsVisitor) Exit(n js.INode) {
	if v.bundles == nil {
		return
	}
	switch n.(type) {
	case *js.FuncDecl, *js.ArrowFunc, *js.MethodDecl:
		if size := len(v.bundleStack); size > 0 && v.bundleStack[size-1].depth == v.functionDepth {
			v.bundleStack = v.bundleStack[:size-1]
		}
		v.functionDepth--
	}
}
func (v *jsVisitor) addFact(f JavaScriptFact) {
	if v.err != nil {
		return
	}
	if f.Kind != "bundle-module-candidate" {
		f.Bundle = bundleReference(f.Bundle)
	}
	f.BundleTarget = bundleReference(f.BundleTarget)
	if len(v.facts) >= 100000 {
		v.err = errors.New("JavaScript fact count exceeds limit")
		return
	}
	for _, s := range []string{f.Value, f.Callee, f.LocalName, f.ExportName, f.Module, f.ValueKind} {
		if len(s) > 4096 {
			v.err = errors.New("JavaScript static label exceeds 4096 bytes")
			return
		}
	}
	f.Ordinal = len(v.facts)
	f.ASTNode = v.nodes
	v.facts = append(v.facts, f)
}

func jsBindingNames(b js.IBinding, depth int, emit func(string)) error {
	if depth > 128 {
		return errors.New("JavaScript export binding nesting exceeds 128")
	}
	switch x := b.(type) {
	case *js.Var:
		if x != nil {
			emit(string(x.Name()))
		}
	case *js.BindingArray:
		for _, b := range x.List {
			if err := jsBindingNames(b.Binding, depth+1, emit); err != nil {
				return err
			}
		}
		if err := jsBindingNames(x.Rest, depth+1, emit); err != nil {
			return err
		}
	case *js.BindingObject:
		for _, p := range x.List {
			if err := jsBindingNames(p.Value.Binding, depth+1, emit); err != nil {
				return err
			}
		}
		if x.Rest != nil {
			emit(string(x.Rest.Name()))
		}
	}
	return nil
}
func jsValueKind(e js.IExpr) string {
	switch e.(type) {
	case *js.FuncDecl, *js.ArrowFunc:
		return "function"
	case *js.ClassDecl:
		return "class"
	case *js.ObjectExpr:
		return "object"
	case *js.ArrayExpr:
		return "array"
	case js.LiteralExpr, *js.LiteralExpr:
		return "literal"
	case *js.Var:
		return "binding"
	case *js.CallExpr, *js.NewExpr:
		return "call-result"
	case nil:
		return "uninitialized"
	default:
		return "expression"
	}
}
func jsRootVar(e js.IExpr) *js.Var {
	switch x := e.(type) {
	case *js.Var:
		return x
	case *js.DotExpr:
		return jsRootVar(x.X)
	case *js.IndexExpr:
		return jsRootVar(x.X)
	}
	return nil
}
func jsString(expr js.IExpr) (string, bool) {
	var lit js.LiteralExpr
	switch x := expr.(type) {
	case js.LiteralExpr:
		lit = x
	case *js.LiteralExpr:
		lit = *x
	default:
		return "", false
	}
	if lit.TokenType != js.StringToken {
		return "", false
	}
	var b bytes.Buffer
	if lit.JSON(&b) != nil {
		return "", false
	}
	var text string
	if json.Unmarshal(b.Bytes(), &text) != nil {
		return "", false
	}
	return text, true
}
func jsCallee(expr js.IExpr) string {
	switch e := expr.(type) {
	case *js.Var:
		return string(e.Name())
	case *js.DotExpr:
		base := jsCallee(e.X)
		if len(base) > 256 {
			return ""
		}
		var member string
		switch x := e.Y.(type) {
		case *js.Var:
			member = string(x.Name())
		case js.LiteralExpr:
			member = string(x.Data)
		case *js.LiteralExpr:
			member = string(x.Data)
		}
		if base != "" && member != "" {
			return base + "." + member
		}
	case *js.IndexExpr:
		base := jsCallee(e.X)
		member, ok := jsString(e.Y)
		if base != "" && len(base) <= 256 && ok && member != "" && len(member) <= 256 && !strings.Contains(member, ".") {
			return base + "." + member
		}
	}
	return ""
}
func InspectJavaScript(path string, o JavaScriptOptions) (JavaScriptReport, error) {
	maxBytes := int64(MaxJavaScriptBytes)
	if o.Entry != "" {
		maxBytes = MaxArtifactBytes
	}
	body, abs, hash, err := readArtifact(path, maxBytes, o.ExpectedSHA256)
	if err != nil {
		return JavaScriptReport{}, err
	}
	content := body
	if o.Entry != "" {
		e, b, err := selectASAREntry(body, o.Entry)
		if err != nil {
			return JavaScriptReport{}, err
		}
		if !e.Available {
			return JavaScriptReport{}, errors.New(e.UnavailableReason)
		}
		content = b
	}
	facts, err := javascriptFacts(content)
	if err != nil {
		return JavaScriptReport{}, err
	}
	start, end, err := page(o.PageOptions, len(facts))
	if err != nil {
		return JavaScriptReport{}, err
	}
	r := JavaScriptReport{Path: abs, SHA256: hash, Entry: o.Entry, ContentSHA256: digest(content), Parser: "github.com/tdewolff/parse/v2/js@v2.8.16", TotalFacts: len(facts), Offset: start, Facts: facts[start:end], CoverageComplete: start == 0 && end == len(facts), Limitations: []string{"coverage applies to the declared static vocabulary only; import/export binding names retain AST token spelling", "callee spelling is not resolved module identity; Electron/endpoint/CommonJS candidates do not establish runtime calls or final exports", "dynamic values, escaped non-JSON string syntax, computed dynamic callees and aliases remain unresolved", "no TypeScript/JSX transpilation, dependency loading or target execution"}}
	r.Parser += "+rr-factory-ranges-v1"
	r.BundlerProfile = "webpack-rspack-esbuild-static-v1"
	r.Limitations = append(r.Limitations, "bundler candidates cover literal object/array module tables, recognized chunk push/helper patterns and stable standalone bootstrap dispatch; no aliases, custom loaders, binding flow or runtime feature reconstruction", "factory source ranges are zero-based UTF-8 byte offsets relative to the selected script or ASAR entry, with exclusive end; only bundle-module-candidate owns original source/render hashes; context records reference that module", "tdewolff-js-render-v1 is normalized parser rendering, not a Babel-compatible fingerprint or semantic equivalence proof; dynamic/spread/duplicate keys remain unknown or ambiguous", "256 registrations, 4096 factories, 32 MiB aggregate factory source/render work, 100000 facts and 48 KiB output; validation precedes pagination")
	if end < len(facts) {
		r.NextOffset = &end
	}
	return r, projectionLimit(r)
}

func javascriptFacts(content []byte) ([]JavaScriptFact, error) {
	if len(content) > MaxJavaScriptBytes || !utf8.Valid(content) {
		return nil, errors.New("JavaScript must be UTF-8 and at most 1 MiB")
	}
	tree, ranges, err := js.ParseWithFactoryRanges(parse.NewInput(bytes.NewReader(content)), js.Options{})
	if err != nil {
		return nil, errors.New("JavaScript syntax is malformed or unsupported by the pinned ECMAScript parser")
	}
	bundles, err := newBundlerIndex(tree, ranges, content)
	if err != nil {
		return nil, err
	}
	v := &jsVisitor{bundles: bundles}
	js.Walk(v, tree)
	if v.err != nil {
		return nil, v.err
	}
	if v.facts == nil {
		v.facts = []JavaScriptFact{}
	}
	return v.facts, nil
}
