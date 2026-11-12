package appinspect

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/tdewolff/parse/v2/js"
)

// Bundle identities are local to the selected script snapshot. Registration is
// an AST traversal ordinal, never a guessed file path or a runtime module ID.
type JavaScriptBundle struct {
	Framework       string                 `json:"framework"`
	Runtime         string                 `json:"runtime"`
	Registration    int                    `json:"registration"`
	ModuleIndex     *int                   `json:"module_index,omitempty"`
	ModuleKey       string                 `json:"module_key,omitempty"`
	KeyState        string                 `json:"key_state,omitempty"`
	SourceRange     *JavaScriptSourceRange `json:"source_range,omitempty"`
	SourceSHA256    string                 `json:"source_sha256,omitempty"`
	RenderSHA256    string                 `json:"render_sha256,omitempty"`
	RenderAlgorithm string                 `json:"render_algorithm,omitempty"`
	RequireName     string                 `json:"require_name,omitempty"`
}

type JavaScriptSourceRange struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

func bundleReference(info *JavaScriptBundle) *JavaScriptBundle {
	if info == nil {
		return nil
	}
	reference := *info
	reference.SourceRange = nil
	reference.SourceSHA256 = ""
	reference.RenderSHA256 = ""
	reference.RenderAlgorithm = ""
	return &reference
}

type bundleScope struct {
	info                     *JavaScriptBundle
	module, exports, require *js.Var
	runtime                  bool
}

type bundlerIndex struct {
	rows          map[js.INode][]JavaScriptFact
	scopes        map[js.INode]*bundleScope
	wrappers      map[*js.Var]*JavaScriptBundle
	writes        map[*js.Var]bool
	initializers  map[*js.Var][]js.IExpr
	callBindings  map[*js.CallExpr]*js.Var
	mutations     map[*js.Var]bool
	nodes         int
	visits        int
	modules       int
	registrations int
	sourceBytes   int
	renderBytes   int
	err           error
}

type bundleWalk struct{ enter func(js.INode) bool }

func (v bundleWalk) Enter(n js.INode) js.IVisitor {
	if v.enter(n) {
		return v
	}
	return nil
}
func (v bundleWalk) Exit(js.INode) {}

func bundleUnwrap(e js.IExpr) js.IExpr {
	for {
		g, ok := e.(*js.GroupExpr)
		if !ok {
			return e
		}
		e = g.X
	}
}
func bundleRoot(v *js.Var) *js.Var {
	if v == nil {
		return nil
	}
	for v.Link != nil {
		v = v.Link
	}
	return v
}
func bundleVar(e js.IExpr) *js.Var { v, _ := bundleUnwrap(e).(*js.Var); return bundleRoot(v) }
func bundleParam(p js.Params, i int) *js.Var {
	if i >= len(p.List) || p.List[i].Default != nil {
		return nil
	}
	v, _ := p.List[i].Binding.(*js.Var)
	return bundleRoot(v)
}
func bundleFunction(n js.INode) (js.Params, *js.BlockStmt, bool) {
	switch x := n.(type) {
	case *js.FuncDecl:
		return x.Params, &x.Body, true
	case *js.ArrowFunc:
		return x.Params, &x.Body, true
	case *js.MethodDecl:
		return x.Params, &x.Body, !x.Get && !x.Set
	}
	return js.Params{}, nil, false
}
func bundleMember(e js.IExpr) (js.IExpr, string, bool) {
	switch x := bundleUnwrap(e).(type) {
	case *js.DotExpr:
		if x.Optional {
			return nil, "", false
		}
		switch y := x.Y.(type) {
		case js.LiteralExpr:
			return x.X, string(y.Data), true
		case *js.LiteralExpr:
			return x.X, string(y.Data), true
		}
	case *js.IndexExpr:
		if x.Optional {
			return nil, "", false
		}
		name, ok := bundleLiteral(x.Y)
		return x.X, name, ok
	}
	return nil, "", false
}

// Restrict numeric IDs to exact non-negative integers. Larger, fractional and
// nonliteral property keys retain unknown state instead of lossy conversion.
func bundleLiteral(e js.IExpr) (string, bool) {
	e = bundleUnwrap(e)
	if s, ok := jsString(e); ok {
		return s, true
	}
	var l js.LiteralExpr
	switch x := e.(type) {
	case *js.LiteralExpr:
		l = *x
	case js.LiteralExpr:
		l = x
	default:
		return "", false
	}
	if !js.IsNumeric(l.TokenType) {
		return "", false
	}
	s := strings.ReplaceAll(string(l.Data), "_", "")
	if strings.HasSuffix(s, "n") {
		return "", false
	}
	var f float64
	var err error
	if len(s) > 2 && s[0] == '0' && strings.ContainsAny(s[1:2], "xXoObB") {
		var u uint64
		u, err = strconv.ParseUint(s[2:], map[byte]int{'x': 16, 'X': 16, 'o': 8, 'O': 8, 'b': 2, 'B': 2}[s[1]], 64)
		f = float64(u)
	} else if len(s) > 1 && s[0] == '0' && !strings.ContainsAny(s, ".eE89") {
		var u uint64
		u, err = strconv.ParseUint(s, 8, 64)
		f = float64(u)
	} else {
		f, err = strconv.ParseFloat(s, 64)
	}
	if err != nil || f < 0 || f > 9007199254740991 || math.Trunc(f) != f {
		return "", false
	}
	return strconv.FormatFloat(f, 'f', 0, 64), true
}
func bundleProperty(p js.Property) (string, bool) {
	if p.Spread {
		return "", false
	}
	name := p.Name
	if method, ok := p.Value.(*js.MethodDecl); ok {
		name = &method.Name.PropertyName
	}
	if name == nil {
		return "", false
	}
	if name.Computed != nil {
		return bundleLiteral(name.Computed)
	}
	if js.IsIdentifierName(name.Literal.TokenType) {
		if strings.ContainsRune(string(name.Literal.Data), '\\') {
			return "", false
		}
		return string(name.Literal.Data), true
	}
	return bundleLiteral(name.Literal)
}

type bundleTableSlot struct {
	key                              string
	static, spread, prototype, empty bool
	value                            js.IExpr
}
type bundleTable struct{ slots []bundleTableSlot }

func readBundleTable(e js.IExpr) *bundleTable {
	table := &bundleTable{}
	switch x := bundleUnwrap(e).(type) {
	case *js.ObjectExpr:
		for _, p := range x.List {
			key, static := bundleProperty(p)
			table.slots = append(table.slots, bundleTableSlot{key: key, static: static, spread: p.Spread, prototype: key == "__proto__" && p.Name != nil && p.Name.Computed == nil, value: bundleUnwrap(p.Value)})
		}
	case *js.ArrayExpr:
		shifted := false
		for index, p := range x.List {
			value := bundleUnwrap(p.Value)
			empty := value == nil
			if literal, ok := value.(*js.LiteralExpr); ok && literal.TokenType == js.NullToken {
				empty = true
			}
			if p.Spread {
				shifted = true
			}
			table.slots = append(table.slots, bundleTableSlot{key: strconv.Itoa(index), static: !shifted, spread: p.Spread, empty: empty, value: value})
		}
	default:
		return nil
	}
	return table
}

func newBundlerIndex(tree *js.AST, ranges js.FactoryRanges, source []byte) (*bundlerIndex, error) {
	b := &bundlerIndex{rows: map[js.INode][]JavaScriptFact{}, scopes: map[js.INode]*bundleScope{}, wrappers: map[*js.Var]*JavaScriptBundle{}, writes: map[*js.Var]bool{}, initializers: map[*js.Var][]js.IExpr{}, callBindings: map[*js.CallExpr]*js.Var{}, mutations: map[*js.Var]bool{}}
	calls := []*js.CallExpr{}
	ordinals := map[*js.CallExpr]int{}
	js.Walk(bundleWalk{func(n js.INode) bool {
		b.nodes++
		if b.nodes > 250000 {
			b.err = errors.New("JavaScript AST exceeds node limit")
			return false
		}
		switch x := n.(type) {
		case *js.CallExpr:
			calls = append(calls, x)
			ordinals[x] = b.nodes
		case *js.FuncDecl:
			if x.Name != nil && x.Name.Decl != js.ExprDecl {
				root := bundleRoot(x.Name)
				b.initializers[root] = append(b.initializers[root], nil)
				if root.Decl == js.ArgumentDecl {
					b.writes[root] = true
				}
			}
		case *js.VarDecl:
			for _, d := range x.List {
				if v, ok := d.Binding.(*js.Var); ok {
					root := bundleRoot(v)
					b.initializers[root] = append(b.initializers[root], d.Default)
				}
			}
		case *js.BinaryExpr:
			if bundleAssignment(x.Op) {
				b.markBindingWrite(x.X)
				if root := bundleVar(jsRootExpr(x.X)); root != nil && bundleVar(x.X) == nil {
					b.mutations[root] = true
				}
			}
		case *js.UnaryExpr:
			switch x.Op {
			case js.PreIncrToken, js.PostIncrToken, js.PreDecrToken, js.PostDecrToken:
				if v := bundleVar(x.X); v != nil {
					b.writes[v] = true
				}
				if root := bundleVar(jsRootExpr(x.X)); root != nil {
					b.mutations[root] = true
				}
			case js.DeleteToken:
				if root := bundleVar(jsRootExpr(x.X)); root != nil {
					b.mutations[root] = true
				}
			}
		case *js.ForInStmt:
			b.markBindingWrite(x.Init)
		case *js.ForOfStmt:
			b.markBindingWrite(x.Init)
		}
		return b.err == nil
	}}, tree)
	if b.err != nil {
		return nil, b.err
	}
	for binding, values := range b.initializers {
		if len(values) == 1 && !b.writes[binding] {
			if call, ok := bundleUnwrap(values[0]).(*js.CallExpr); ok {
				b.callBindings[call] = binding
			}
		}
	}
	for _, call := range calls {
		if call.Optional {
			continue
		}
		var table *bundleTable
		var runtimeFn js.INode
		var loader *js.Var
		framework, runtime := "", ""
		if base, member, ok := bundleMember(call.X); ok && member == "push" && len(call.Args.List) > 0 && !call.Args.List[0].Rest {
			runtime = bundleChunkRuntime(base)
			if runtime != "" {
				if args, ok := bundleUnwrap(call.Args.List[0].Value).(*js.ArrayExpr); ok && len(args.List) >= 2 && !args.List[0].Spread && !args.List[1].Spread {
					if _, ok := bundleUnwrap(args.List[0].Value).(*js.ArrayExpr); ok {
						table = readBundleTable(args.List[1].Value)
					}
					if len(args.List) > 2 && !args.List[2].Spread {
						if _, _, ok := bundleFunction(bundleUnwrap(args.List[2].Value)); ok {
							runtimeFn = bundleUnwrap(args.List[2].Value)
						}
					}
				}
				framework = "webpack"
				if strings.Contains(strings.ToLower(runtime), "rspack") {
					framework = "rspack"
				}
			}
		}
		if table == nil && len(call.Args.List) > 0 && !call.Args.List[0].Rest {
			name := jsCallee(call.X)
			if name == "__commonJS" || strings.HasSuffix(name, ".__commonJS") || name == "__esm" || strings.HasSuffix(name, ".__esm") {
				if object, ok := bundleUnwrap(call.Args.List[0].Value).(*js.ObjectExpr); ok {
					table = readBundleTable(object)
				}
				framework, runtime = "esbuild", "esbuild-commonjs"
				if strings.HasSuffix(name, "__esm") {
					runtime = "esbuild-esm"
				}
			}
		}
		if table == nil {
			table, runtimeFn, loader = b.bootstrap(call)
			if table != nil {
				framework, runtime = "webpack", fmt.Sprintf("webpack-bootstrap@ast:%d", ordinals[call])
			}
		}
		if table == nil {
			continue
		}
		b.registrations++
		if b.registrations > 256 {
			return nil, errors.New("JavaScript bundle registrations exceed 256")
		}
		info := &JavaScriptBundle{Framework: framework, Runtime: runtime, Registration: ordinals[call]}
		b.row(call, "bundle-registration-candidate", runtime, false, info)
		if framework == "webpack" || framework == "rspack" {
			if runtimeFn != nil {
				params, _, _ := bundleFunction(runtimeFn)
				if loader == nil {
					loader = bundleParam(params, 0)
				}
				b.scopes[runtimeFn] = &bundleScope{info: info, require: loader, runtime: true}
			}
			if loader == nil && runtimeFn != nil {
				b.row(call, "bundle-runtime-loader-unknown", "", true, info)
			}
			if len(call.Args.List) > 0 {
				if array, ok := bundleUnwrap(call.Args.List[0].Value).(*js.ArrayExpr); ok && len(array.List) > 0 {
					if chunks, ok := bundleUnwrap(array.List[0].Value).(*js.ArrayExpr); ok {
						for _, chunk := range chunks.List {
							value, static := bundleLiteral(chunk.Value)
							b.row(call, "bundle-chunk", value, chunk.Spread || !static, info)
						}
					}
				}
			}
		}
		counts := map[string]int{}
		uncertain := false
		for _, p := range table.slots {
			key, ok := p.key, p.static
			if !ok || p.spread || p.prototype {
				uncertain = true
			}
			if ok {
				counts[key]++
			}
		}
		for i, p := range table.slots {
			key, static := p.key, p.static
			if p.spread {
				b.row(call, "bundle-table-boundary", "spread", true, info)
				continue
			}
			if p.empty {
				b.row(call, "bundle-table-boundary", "empty-slot", false, info)
				continue
			}
			params, _, factory := bundleFunction(p.value)
			if !factory {
				b.row(call, "bundle-table-boundary", "non-factory-property", true, info)
				continue
			}
			b.modules++
			if b.modules > 4096 {
				return nil, errors.New("JavaScript bundle modules exceed 4096")
			}
			state := "static"
			if !static {
				state = "unknown"
			} else if counts[key] > 1 || uncertain {
				state = "ambiguous"
			}
			r, ok := ranges[p.value]
			if !ok || r.Start < 0 || r.End > len(source) || r.End <= r.Start {
				return nil, errors.New("JavaScript factory original source range unavailable")
			}
			b.sourceBytes += r.End - r.Start
			if b.sourceBytes > 32<<20 {
				return nil, errors.New("JavaScript factory source work exceeds 32 MiB")
			}
			writer := &bundleRenderWriter{}
			p.value.JS(writer)
			if writer.err != nil {
				return nil, writer.err
			}
			b.renderBytes += writer.text.Len()
			if b.renderBytes > 32<<20 {
				return nil, errors.New("JavaScript factory rendering work exceeds 32 MiB")
			}
			module := *info
			slot := i
			module.ModuleIndex = &slot
			module.ModuleKey = key
			module.KeyState = state
			module.SourceRange = &JavaScriptSourceRange{Start: r.Start, End: r.End}
			module.SourceSHA256 = digest(source[r.Start:r.End])
			module.RenderSHA256 = digest([]byte(writer.text.String()))
			module.RenderAlgorithm = "tdewolff-js-render-v1"
			scope := &bundleScope{info: &module}
			if framework != "esbuild" {
				scope.module, scope.exports, scope.require = bundleParam(params, 0), bundleParam(params, 1), bundleParam(params, 2)
			} else if runtime == "esbuild-commonjs" {
				scope.exports, scope.module = bundleParam(params, 0), bundleParam(params, 1)
			}
			if scope.require != nil {
				module.RequireName = string(scope.require.Name())
			}
			b.scopes[p.value] = scope
			b.row(p.value, "bundle-module-candidate", key, state != "static", &module)
			if framework == "esbuild" && len(table.slots) == 1 {
				if binding := b.callBindings[call]; binding != nil {
					b.wrappers[binding] = &module
				}
			}
		}
		if b.err != nil {
			return nil, b.err
		}
	}
	return b, b.err
}

func (b *bundlerIndex) markBindingWrite(n js.INode) {
	switch x := n.(type) {
	case *js.Var:
		b.writes[bundleRoot(x)] = true
	case *js.GroupExpr:
		b.markBindingWrite(x.X)
	case *js.ArrayExpr:
		for _, v := range x.List {
			b.markBindingWrite(v.Value)
		}
	case *js.ObjectExpr:
		for _, v := range x.List {
			b.markBindingWrite(v.Value)
		}
	case *js.BinaryExpr:
		if x.Op == js.EqToken {
			b.markBindingWrite(x.X)
		}
	case *js.VarDecl:
		for _, v := range x.List {
			if ref, ok := v.Binding.(*js.Var); ok {
				b.writes[bundleRoot(ref)] = true
			}
		}
	}
}
func bundleAssignment(op js.TokenType) bool {
	switch op {
	case js.EqToken, js.AddEqToken, js.SubEqToken, js.MulEqToken, js.DivEqToken, js.ModEqToken, js.ExpEqToken, js.BitAndEqToken, js.BitOrEqToken, js.BitXorEqToken, js.LtLtEqToken, js.GtGtEqToken, js.GtGtGtEqToken, js.AndEqToken, js.OrEqToken, js.NullishEqToken:
		return true
	}
	return false
}
func (b *bundlerIndex) row(n js.INode, kind, value string, dynamic bool, info *JavaScriptBundle) {
	if len(value) > 4096 || len(info.Runtime) > 4096 || len(info.ModuleKey) > 4096 {
		b.err = errors.New("JavaScript bundle label exceeds 4096 bytes")
		return
	}
	b.rows[n] = append(b.rows[n], JavaScriptFact{Kind: kind, Value: value, Dynamic: dynamic, Bundle: info, Authority: "static-ast", EpistemicState: "inferred"})
}

type bundleRenderWriter struct {
	text strings.Builder
	err  error
}

func (w *bundleRenderWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if w.text.Len()+len(p) > MaxJavaScriptBytes {
		w.err = errors.New("JavaScript factory rendering exceeds 1 MiB")
		return 0, w.err
	}
	return w.text.Write(p)
}

func bundleChunkRuntime(e js.IExpr) string {
	queue := []js.IExpr{e}
	for len(queue) > 0 {
		n := bundleUnwrap(queue[len(queue)-1])
		queue = queue[:len(queue)-1]
		match := func(s string) bool {
			lower := strings.ToLower(s)
			return strings.Contains(lower, "webpackchunk") || strings.Contains(lower, "rspackchunk")
		}
		if v, ok := n.(*js.Var); ok && match(string(v.Name())) {
			return string(v.Name())
		}
		if base, member, ok := bundleMember(n); ok {
			if match(member) {
				return member
			}
			queue = append(queue, base)
		}
		if binary, ok := n.(*js.BinaryExpr); ok {
			queue = append(queue, binary.Y, binary.X)
		}
	}
	return ""
}

func (b *bundlerIndex) scan(n js.INode, enter func(js.INode) bool) {
	js.Walk(bundleWalk{func(n js.INode) bool {
		b.visits++
		if b.visits > 1000000 {
			b.err = errors.New("JavaScript bootstrap analysis exceeds work limit")
			return false
		}
		return b.err == nil && enter(n)
	}}, n)
}
func (b *bundlerIndex) bootstrap(call *js.CallExpr) (*bundleTable, js.INode, *js.Var) {
	if len(call.Args.List) != 0 {
		return nil, nil, nil
	}
	callee := bundleUnwrap(call.X)
	params, body, ok := bundleFunction(callee)
	if !ok || len(params.List) != 0 || params.Rest != nil {
		return nil, nil, nil
	}
	tables := map[*js.Var]*bundleTable{}
	for _, statement := range body.List {
		decl, ok := statement.(*js.VarDecl)
		if !ok {
			continue
		}
		for _, d := range decl.List {
			v, ok := d.Binding.(*js.Var)
			if !ok {
				continue
			}
			root := bundleRoot(v)
			table := readBundleTable(d.Default)
			if table == nil || len(table.slots) == 0 || b.writes[root] || b.mutations[root] || len(b.initializers[root]) != 1 {
				continue
			}
			all := true
			factories := 0
			for _, p := range table.slots {
				if p.empty {
					continue
				}
				factories++
				if _, _, ok := bundleFunction(p.value); !ok || p.spread {
					all = false
				}
			}
			if all && factories > 0 {
				tables[root] = table
			}
		}
	}
	for _, statement := range body.List {
		loader, ok := statement.(*js.FuncDecl)
		if !ok || loader.Name == nil || len(loader.Params.List) != 1 || loader.Params.Rest != nil || b.writes[bundleRoot(loader.Name)] {
			continue
		}
		key := bundleParam(loader.Params, 0)
		if key == nil {
			continue
		}
		var selected *bundleTable
		b.scan(&loader.Body, func(n js.INode) bool {
			if _, _, function := bundleFunction(n); function {
				return false
			}
			dispatch, ok := n.(*js.CallExpr)
			if !ok || dispatch.Optional {
				return true
			}
			x := bundleUnwrap(dispatch.X)
			args := dispatch.Args.List
			if base, member, ok := bundleMember(x); ok && member == "call" {
				if len(args) == 0 {
					return true
				}
				x = bundleUnwrap(base)
				receiver := args[0]
				args = args[1:]
				if receiver.Rest || len(args) < 2 || jsCallee(receiver.Value) != jsCallee(args[1].Value) || bundleVar(jsRootExpr(receiver.Value)) != bundleVar(jsRootExpr(args[1].Value)) {
					return true
				}
			}
			index, ok := x.(*js.IndexExpr)
			if !ok || index.Optional || bundleVar(index.Y) != key {
				return true
			}
			table := tables[bundleVar(index.X)]
			if table == nil || len(args) != 3 || args[0].Rest || args[1].Rest || args[2].Rest {
				return true
			}
			module := bundleVar(args[0].Value)
			base, member, ok := bundleMember(args[1].Value)
			if module == nil || module.Decl == js.NoDecl || !ok || member != "exports" || bundleVar(base) != module || bundleVar(args[2].Value) != bundleRoot(loader.Name) {
				return true
			}
			if selected == nil || selected == table {
				selected = table
			} else {
				selected = nil
				b.err = errors.New("JavaScript bootstrap dispatch is ambiguous")
			}
			return true
		})
		if selected != nil {
			return selected, callee, bundleRoot(loader.Name)
		}
	}
	return nil, nil, nil
}

func jsRootExpr(e js.IExpr) js.IExpr {
	for {
		if base, _, ok := bundleMember(e); ok {
			e = base
		} else {
			return e
		}
	}
}

func (v *jsVisitor) bundleFacts(n js.INode) {
	var frame bundleFrame
	if len(v.bundleStack) > 0 {
		frame = v.bundleStack[len(v.bundleStack)-1]
	}
	scope := frame.scope
	emit := func(kind, value string, dynamic bool) {
		if scope == nil {
			return
		}
		v.addFact(JavaScriptFact{Kind: kind, Value: value, Dynamic: dynamic, Bundle: scope.info, Authority: "static-ast", EpistemicState: "inferred"})
	}
	if call, ok := n.(*js.CallExpr); ok && !call.Optional {
		if target := v.bundles.wrappers[bundleVar(call.X)]; target != nil {
			info := target
			kind := "bundle-entry-candidate"
			if scope != nil {
				info = scope.info
				kind = "bundle-module-request"
			}
			v.addFact(JavaScriptFact{Kind: kind, Value: target.ModuleKey, Callee: jsCallee(call.X), ValueKind: "esbuild-wrapper-binding", Bundle: info, BundleTarget: target, Authority: "static-ast", EpistemicState: "inferred"})
		}
		if scope == nil || scope.require == nil {
			return
		}
		binding := bundleVar(call.X)
		base, member, hasMember := bundleMember(call.X)
		if binding != scope.require && (!hasMember || bundleVar(base) != scope.require) {
			return
		}
		if v.bundles.writes[scope.require] {
			emit("bundle-loader-binding-unavailable", "assigned-loader", true)
			return
		}
		value, static := "", false
		if len(call.Args.List) > 0 && !call.Args.List[0].Rest {
			value, static = bundleLiteral(call.Args.List[0].Value)
		}
		if binding == scope.require {
			if scope.runtime && frame.depth != v.functionDepth {
				return
			}
			kind := "bundle-module-request"
			if scope.runtime {
				kind = "bundle-entry-candidate"
			}
			emit(kind, value, !static)
		} else if member == "e" {
			emit("bundle-async-chunk-candidate", value, !static)
		} else if member == "d" && scope.exports != nil && !v.bundles.writes[scope.exports] && len(call.Args.List) == 2 && !call.Args.List[0].Rest && !call.Args.List[1].Rest && bundleVar(call.Args.List[0].Value) == scope.exports {
			if object, ok := bundleUnwrap(call.Args.List[1].Value).(*js.ObjectExpr); ok {
				for _, p := range object.List {
					name, static := bundleProperty(p)
					before := len(v.facts)
					emit("bundle-export-candidate", name, !static)
					if len(v.facts) > before {
						f := &v.facts[len(v.facts)-1]
						f.ExportName = name
						f.ValueKind = "webpack-getter-declaration"
					}
				}
			}
		}
	}
	assignment, ok := n.(*js.BinaryExpr)
	if !ok || assignment.Op != js.EqToken || scope == nil {
		return
	}
	base, member, static := bundleAccess(assignment.X)
	if base == nil {
		return
	}
	if scope.require != nil && !v.bundles.writes[scope.require] && bundleVar(base) == scope.require && static && member == "c" {
		emit("bundle-runtime-cache-candidate", "loader-cache-property-assignment", false)
	}
	if scope.module != nil && !v.bundles.writes[scope.module] && bundleVar(base) == scope.module && static && member == "exports" {
		emit("bundle-export-object-candidate", "*", false)
		if object, ok := bundleUnwrap(assignment.Y).(*js.ObjectExpr); ok {
			for _, p := range object.List {
				name, ok := bundleProperty(p)
				before := len(v.facts)
				emit("bundle-export-candidate", name, !ok)
				if len(v.facts) > before {
					f := &v.facts[len(v.facts)-1]
					f.ExportName = name
					f.ValueKind = jsValueKind(p.Value)
				}
			}
		}
		return
	}
	matched := scope.exports != nil && !v.bundles.writes[scope.exports] && bundleVar(base) == scope.exports
	if module, property, ok := bundleMember(base); ok && property == "exports" && scope.module != nil && !v.bundles.writes[scope.module] && bundleVar(module) == scope.module {
		matched = true
	}
	if matched {
		before := len(v.facts)
		emit("bundle-export-candidate", member, !static)
		if len(v.facts) > before {
			f := &v.facts[len(v.facts)-1]
			f.ExportName = member
			f.ValueKind = jsValueKind(assignment.Y)
		}
	}
}

func bundleAccess(e js.IExpr) (js.IExpr, string, bool) {
	if index, ok := bundleUnwrap(e).(*js.IndexExpr); ok && !index.Optional {
		name, static := bundleLiteral(index.Y)
		return index.X, name, static
	}
	return bundleMember(e)
}
