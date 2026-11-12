package appinspect

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/url"
	"path"
	"reverseresearch/internal/recordio"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// This resolver only consults the existing captured application inventory.
// It never probes the host filesystem, invokes Node or creates durable state.
type applicationResolver struct {
	files    map[string]applicationInput
	packages map[string]*applicationPackage
}

type applicationPackage struct {
	input  applicationInput
	fields map[string]json.RawMessage
}

type packageField struct {
	key   string
	value json.RawMessage
}
type applicationPathResult struct{ state, candidate, reason, target string }
type applicationLookup struct {
	owner  *applicationResolver
	loader string
	used   map[string]ApplicationPackageReference
}

func newApplicationResolver(inputs []applicationInput) (*applicationResolver, error) {
	r := &applicationResolver{files: map[string]applicationInput{}, packages: map[string]*applicationPackage{}}
	for _, input := range inputs {
		r.files[input.name] = input
		if path.Base(input.name) != "package.json" || input.kind == "directory" {
			continue
		}
		p := &applicationPackage{input: input}
		if input.reason == "" {
			if err := recordio.DecodeJSON(input.content, &p.fields); err != nil || p.fields == nil {
				return nil, errors.New("a selected package.json is malformed, non-object, non-UTF8, duplicate-keyed or exceeds JSON nesting limits")
			}
		}
		r.packages[input.name] = p
	}
	return r, nil
}

func (r *applicationResolver) relation(source string, f JavaScriptFact) ModuleRelation {
	loader := "import"
	if f.Callee == "require" {
		loader = "require"
	}
	rel := ModuleRelation{ASTNode: f.ASTNode, Kind: f.Kind, Specifier: f.Value, Loader: loader, Candidates: []string{}}
	if f.Dynamic {
		rel.Resolution = "dynamic"
		return rel
	}
	lookup := &applicationLookup{owner: r, loader: loader, used: map[string]ApplicationPackageReference{}}
	result := lookup.resolve(source, f.Value)
	rel.Resolution, rel.Reason, rel.Target = result.state, result.reason, result.target
	if result.candidate != "" {
		rel.Candidates = append(rel.Candidates, result.candidate)
	}
	for _, ref := range lookup.used {
		rel.Packages = append(rel.Packages, ref)
	}
	sort.Slice(rel.Packages, func(i, j int) bool { return rel.Packages[i].Path < rel.Packages[j].Path })
	return rel
}

func appPathFailure(state, reason string) applicationPathResult {
	return applicationPathResult{state: state, reason: reason}
}

func (l *applicationLookup) metadata(dir string) *applicationPackage {
	p := l.owner.packages[path.Join(dir, "package.json")]
	if p != nil {
		l.used[p.input.name] = ApplicationPackageReference{Path: p.input.name, SHA256: p.input.hash, Available: p.input.reason == ""}
	}
	return p
}

func (l *applicationLookup) nearestPackage(source string) *applicationPackage {
	for dir := path.Dir(source); ; dir = path.Dir(dir) {
		if path.Base(dir) == "node_modules" {
			return nil
		}
		if p := l.metadata(dir); p != nil {
			return p
		}
		if dir == "." {
			return nil
		}
	}
}

func (l *applicationLookup) boundary(name string) bool {
	for p := name; p != "."; p = path.Dir(p) {
		if input, ok := l.owner.files[p]; ok && input.reason != "" {
			return true
		}
	}
	return false
}

func (l *applicationLookup) file(name string) applicationPathResult {
	if l.boundary(name) {
		return appPathFailure("unavailable", "an inventoried symlink, unpacked or unavailable path is not followed")
	}
	if input, ok := l.owner.files[name]; ok && input.kind != "directory" {
		return applicationPathResult{state: "admitted-path-candidate", candidate: name}
	}
	return appPathFailure("not-found", "no selected file exists at the exact logical path")
}

func (l *applicationLookup) files(names ...string) applicationPathResult {
	for _, name := range names {
		r := l.file(name)
		if r.state != "not-found" {
			return r
		}
	}
	return appPathFailure("not-found", "no selected file exists in the loader's ordered lookup")
}

func (l *applicationLookup) cjsFile(name string) applicationPathResult {
	// Suffixing the admitted root would name a sibling outside the snapshot,
	// not a file such as root/..js inside it.
	if name == "." {
		return l.file(name)
	}
	return l.files(name, name+".js", name+".json", name+".node")
}
func (l *applicationLookup) index(dir string) applicationPathResult {
	return l.files(path.Join(dir, "index.js"), path.Join(dir, "index.json"), path.Join(dir, "index.node"))
}

func confinedApplicationPath(base, value string) (string, error) {
	if value == "" || strings.ContainsAny(value, "\\:\x00") || strings.IndexFunc(value, unicode.IsControl) >= 0 || path.IsAbs(value) {
		return "", errors.New("non-canonical logical path")
	}
	p := path.Join(base, value)
	if p == ".." || strings.HasPrefix(p, "../") {
		return "", errors.New("path escapes the admitted root")
	}
	if p != "." {
		if _, err := safeArchivePath(p); err != nil {
			return "", err
		}
	}
	return p, nil
}

// URL suffixes are preserved on the relation; only the path identifies bytes.
func applicationURLPath(value string) (string, error) {
	u, err := url.Parse(value)
	if err != nil || u.IsAbs() || u.Host != "" {
		return "", errors.New("unsupported module URL")
	}
	escaped := strings.ToLower(u.EscapedPath())
	if strings.Contains(escaped, "%2f") || strings.Contains(escaped, "%5c") {
		return "", errors.New("encoded path separator")
	}
	return u.Path, nil
}

func (l *applicationLookup) directory(dir string) (applicationPathResult, bool) {
	if l.boundary(dir) {
		return appPathFailure("unavailable", "directory boundary is not followed"), true
	}
	p := l.metadata(dir)
	if p != nil && p.input.reason != "" {
		return appPathFailure("unavailable", "package metadata is unavailable"), true
	}
	if p != nil {
		main := p.fields["main"]
		if len(main) != 0 && string(main) != "null" {
			var entry string
			if err := json.Unmarshal(main, &entry); err != nil {
				return appPathFailure("invalid-package-config", "package main must be a string in this static profile"), true
			}
			if entry != "" {
				name, err := confinedApplicationPath(dir, entry)
				if err != nil {
					return appPathFailure("outside-admitted-root", "package main is outside the admitted logical path profile"), true
				}
				result := l.cjsFile(name)
				if result.state == "not-found" {
					result = l.index(name)
				}
				if result.state == "not-found" {
					result = l.index(dir)
				}
				return result, true
			}
		}
	}
	return l.index(dir), false
}

func packageHasExports(p *applicationPackage) bool {
	return p != nil && len(p.fields["exports"]) != 0 && !bytes.Equal(bytes.TrimSpace(p.fields["exports"]), []byte("null"))
}

func (l *applicationLookup) resolve(source, specifier string) applicationPathResult {
	if specifier == "" || strings.Contains(specifier, "\\") || strings.IndexFunc(specifier, unicode.IsControl) >= 0 {
		return appPathFailure("rejected", "empty, backslash or control-character module specifier")
	}
	if strings.HasPrefix(specifier, "#") {
		if specifier == "#" || strings.HasPrefix(specifier, "#/") {
			return appPathFailure("rejected", "invalid private import specifier")
		}
		p := l.nearestPackage(source)
		if p == nil {
			return appPathFailure("package-map-unmatched", "no selected enclosing package imports map")
		}
		return l.packageMap(p, "imports", specifier)
	}
	if strings.HasPrefix(specifier, "./") || strings.HasPrefix(specifier, "../") || specifier == "." || specifier == ".." {
		value := specifier
		if l.loader == "import" {
			var err error
			value, err = applicationURLPath(specifier)
			if err != nil {
				return appPathFailure("rejected", "relative module URL is not admitted")
			}
		}
		name, err := confinedApplicationPath(path.Dir(source), value)
		if err != nil {
			return appPathFailure("outside-admitted-root", "relative path escapes or is outside the admitted logical path profile")
		}
		if l.loader == "import" {
			return l.file(name)
		}
		if strings.HasSuffix(specifier, "/") {
			result, _ := l.directory(name)
			return result
		}
		r := l.cjsFile(name)
		if r.state == "not-found" {
			r, _ = l.directory(name)
		}
		return r
	}
	if path.IsAbs(specifier) {
		return appPathFailure("outside-admitted-root", "absolute filesystem module paths are not followed")
	}
	if strings.Contains(specifier, ":") {
		return appPathFailure("external-or-unresolved", "URL and node namespace bindings are not loaded")
	}
	if isApplicationNodeBuiltin(specifier) {
		return appPathFailure("external-or-unresolved", "Node built-in binding is outside the artifact inventory")
	}
	name, subpath, ok := applicationPackageRequest(specifier)
	if !ok {
		return appPathFailure("rejected", "invalid package name or subpath")
	}
	if p := l.nearestPackage(source); p != nil {
		if p.input.reason != "" {
			return appPathFailure("unavailable", "enclosing package metadata is unavailable")
		}
		var self string
		_ = json.Unmarshal(p.fields["name"], &self)
		if self == name && packageHasExports(p) {
			return l.packageMap(p, "exports", subpath)
		}
	}
	for dir := path.Dir(source); ; dir = path.Dir(dir) {
		if path.Base(dir) != "node_modules" {
			base := path.Join(dir, "node_modules", name)
			if l.boundary(base) {
				return appPathFailure("unavailable", "installed package directory is an unavailable boundary")
			}
			p := l.metadata(base)
			if p != nil && p.input.reason != "" {
				return appPathFailure("unavailable", "installed package metadata is unavailable")
			}
			if packageHasExports(p) {
				return l.packageMap(p, "exports", subpath)
			}
			if l.loader == "require" {
				candidate := base
				if subpath != "." {
					candidate = path.Join(base, subpath)
				}
				r := appPathFailure("not-found", "directory-only request")
				if !strings.HasSuffix(specifier, "/") {
					r = l.cjsFile(candidate)
				}
				if r.state != "not-found" {
					return r
				}
				r, stop := l.directory(candidate)
				if r.state != "not-found" || stop {
					return r
				}
			} else if input, exists := l.owner.files[base]; exists && input.kind == "directory" {
				if subpath == "." {
					r, _ := l.directory(base)
					return r
				}
				value, err := applicationURLPath(subpath)
				if err != nil {
					return appPathFailure("rejected", "legacy ESM subpath URL is not admitted")
				}
				candidate, err := confinedApplicationPath(base, value)
				if err != nil {
					return appPathFailure("outside-admitted-root", "legacy ESM subpath escapes the admitted root")
				}
				return l.file(candidate)
			}
		}
		if dir == "." {
			break
		}
	}
	return appPathFailure("external-or-unresolved", "no matching installed package is available inside the selected root")
}

func applicationPackageRequest(specifier string) (string, string, bool) {
	parts := strings.Split(specifier, "/")
	n := 1
	if strings.HasPrefix(specifier, "@") {
		n = 2
	}
	if len(parts) < n {
		return "", "", false
	}
	for index, segment := range parts {
		if (segment == "" && !(index == len(parts)-1 && index >= n)) || segment == "." || segment == ".." {
			return "", "", false
		}
	}
	name := strings.Join(parts[:n], "/")
	if strings.HasPrefix(name, ".") || strings.ContainsAny(name, "%*") || name == "@" {
		return "", "", false
	}
	subpath := "."
	if len(parts) > n {
		subpath += "/" + strings.Join(parts[n:], "/")
	}
	return name, subpath, true
}

// The full JSON was validated by recordio. Token iteration here preserves
// declaration order solely for package condition selection, unlike a Go map.
func orderedPackageFields(raw json.RawMessage) ([]packageField, bool) {
	d := json.NewDecoder(bytes.NewReader(raw))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return nil, false
	}
	fields := []packageField{}
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return nil, false
		}
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return nil, false
		}
		fields = append(fields, packageField{key: key.(string), value: value})
	}
	return fields, true
}

func (l *applicationLookup) packageMap(p *applicationPackage, kind, key string) applicationPathResult {
	if p.input.reason != "" {
		return appPathFailure("unavailable", "selected package metadata is unavailable")
	}
	raw := p.fields[kind]
	if len(raw) == 0 {
		return appPathFailure("package-map-unmatched", "package map is absent")
	}
	fields, object := orderedPackageFields(raw)
	if kind == "exports" && object {
		dots, conditions := false, false
		for _, field := range fields {
			if strings.HasPrefix(field.key, ".") {
				dots = true
			} else {
				conditions = true
			}
		}
		if dots && conditions {
			return appPathFailure("invalid-package-config", "exports mixes subpaths and condition keys")
		}
		if !dots {
			if key != "." {
				return appPathFailure("package-map-unmatched", "exports root target does not expose this subpath")
			}
			return l.finishPackageTarget(p, kind, l.selectTarget(raw, kind, "", 0))
		}
	} else if kind == "exports" {
		if key != "." {
			return appPathFailure("package-map-unmatched", "exports root target does not expose this subpath")
		}
		return l.finishPackageTarget(p, kind, l.selectTarget(raw, kind, "", 0))
	} else if !object {
		return appPathFailure("package-map-unmatched", "imports is not an object map")
	}
	if strings.HasSuffix(key, "/") {
		return appPathFailure("rejected", "trailing slash package-map specifier is not admitted")
	}
	for _, field := range fields {
		if field.key == key && !strings.Contains(key, "*") {
			return l.finishPackageTarget(p, kind, l.selectTarget(field.value, kind, "", 0))
		}
	}
	// Node chooses the longest pattern prefix, then the longest complete key.
	sort.SliceStable(fields, func(i, j int) bool {
		a, b := strings.Index(fields[i].key, "*"), strings.Index(fields[j].key, "*")
		if a != b {
			return a > b
		}
		return len(fields[i].key) > len(fields[j].key)
	})
	for _, field := range fields {
		if strings.Count(field.key, "*") != 1 {
			continue
		}
		index := strings.Index(field.key, "*")
		prefix, suffix := field.key[:index], field.key[index+1:]
		if strings.HasPrefix(key, prefix) && strings.HasSuffix(key, suffix) && len(key) > len(prefix) && len(key) >= len(field.key) {
			match := key[len(prefix) : len(key)-len(suffix)]
			if !validPackageSegments(match) {
				return appPathFailure("rejected", "package pattern contains a forbidden segment")
			}
			return l.finishPackageTarget(p, kind, l.selectTarget(field.value, kind, match, 0))
		}
	}
	return appPathFailure("package-map-unmatched", "no exact or matching pattern key; no file/index fallback is permitted")
}

func validPackageSegments(value string) bool {
	for _, segment := range strings.FieldsFunc(value, func(r rune) bool { return r == '/' || r == '\\' }) {
		decoded, err := url.PathUnescape(segment)
		if err != nil || decoded == "." || decoded == ".." || strings.EqualFold(decoded, "node_modules") {
			return false
		}
	}
	return true
}

func (l *applicationLookup) selectTarget(raw json.RawMessage, kind, match string, depth int) applicationPathResult {
	if depth > 128 {
		return appPathFailure("invalid-package-config", "package target nesting exceeds budget")
	}
	raw = bytes.TrimSpace(raw)
	if bytes.Equal(raw, []byte("null")) {
		return appPathFailure("package-map-blocked", "explicit null target")
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		if !strings.HasPrefix(text, "./") {
			if kind == "imports" && text != "" && !strings.HasPrefix(text, "../") && !path.IsAbs(text) && !strings.Contains(text, ":") {
				return applicationPathResult{state: "unsupported-import-target", target: strings.ReplaceAll(text, "*", match), reason: "recursive/private and external-package targets are not recursively resolved"}
			}
			return appPathFailure("invalid-package-target", "package file targets must start with ./")
		}
		if !validPackageSegments(text[2:]) {
			return appPathFailure("invalid-package-target", "package target contains a forbidden segment")
		}
		if match != "" {
			text = strings.ReplaceAll(text, "*", match)
		}
		return applicationPathResult{state: "selected-package-target", target: text}
	}
	if len(raw) > 0 && raw[0] == '[' {
		var array []json.RawMessage
		_ = json.Unmarshal(raw, &array)
		last := appPathFailure("package-map-blocked", "empty target array or no selected fallback")
		for _, entry := range array {
			r := l.selectTarget(entry, kind, match, depth+1)
			if r.state == "package-map-unmatched" {
				continue
			}
			if r.state == "invalid-package-target" || r.state == "package-map-blocked" {
				last = r
				continue
			}
			return r
		}
		return last
	}
	if fields, ok := orderedPackageFields(raw); ok {
		for _, field := range fields {
			if number, err := strconv.ParseUint(field.key, 10, 32); err == nil && number < 0xffffffff && strconv.FormatUint(number, 10) == field.key {
				return appPathFailure("invalid-package-config", "numeric package condition key")
			}
		}
		for _, field := range fields {
			if field.key != "node" && field.key != "node-addons" && field.key != "module-sync" && field.key != "default" && field.key != l.loader {
				continue
			}
			r := l.selectTarget(field.value, kind, match, depth+1)
			if r.state != "package-map-unmatched" {
				return r
			}
		}
		return appPathFailure("package-map-unmatched", "no active default Node condition")
	}
	return appPathFailure("invalid-package-target", "target is not a string, object, array or null")
}

func (l *applicationLookup) finishPackageTarget(p *applicationPackage, kind string, selected applicationPathResult) applicationPathResult {
	if selected.state != "selected-package-target" {
		return selected
	}
	value, err := applicationURLPath(selected.target)
	if err != nil {
		return applicationPathResult{state: "rejected", target: selected.target, reason: "selected target URL has an encoded separator or unsupported syntax; no array file fallback"}
	}
	name, err := confinedApplicationPath(path.Dir(p.input.name), value)
	if err != nil {
		return applicationPathResult{state: "outside-admitted-root", target: selected.target, reason: "selected target escapes the admitted root"}
	}
	result := l.file(name)
	result.target = selected.target
	return result
}

// Node v24.19.0 builtinModules observation; explicit node: names are handled
// separately. This fixed profile does not require a Node runtime in production.
func isApplicationNodeBuiltin(name string) bool {
	if strings.ContainsRune(name, ' ') {
		return false
	}
	const names = " _http_agent _http_client _http_common _http_incoming _http_outgoing _http_server _stream_duplex _stream_passthrough _stream_readable _stream_transform _stream_wrap _stream_writable _tls_common _tls_wrap assert assert/strict async_hooks buffer child_process cluster console constants crypto dgram diagnostics_channel dns dns/promises domain events fs fs/promises http http2 https inspector inspector/promises module net os path path/posix path/win32 perf_hooks process punycode querystring readline readline/promises repl stream stream/consumers stream/promises stream/web string_decoder sys timers timers/promises tls trace_events tty url util util/types v8 vm wasi worker_threads zlib "
	return strings.Contains(names, " "+name+" ")
}
