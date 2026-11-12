package appinspect

import "strings"

type ApplicationVirtualModule struct {
	Path         string `json:"path"`
	Framework    string `json:"framework"`
	Runtime      string `json:"runtime"`
	Registration int    `json:"registration"`
	ModuleIndex  int    `json:"module_index"`
	ModuleKey    string `json:"module_key"`
	KeyState     string `json:"key_state"`
	SourceSHA256 string `json:"source_sha256"`
}

func applicationVirtualModule(path string, b *JavaScriptBundle) ApplicationVirtualModule {
	return ApplicationVirtualModule{Path: path, Framework: b.Framework, Runtime: b.Runtime, Registration: b.Registration, ModuleIndex: *b.ModuleIndex, ModuleKey: b.ModuleKey, KeyState: b.KeyState, SourceSHA256: b.SourceSHA256}
}

type applicationBundleRuntime struct{ framework, runtime, path string }
type applicationBundleKey struct {
	runtime applicationBundleRuntime
	key     string
}
type applicationBundleSlot struct {
	path               string
	registration, slot int
}
type applicationBundleIndex struct {
	keys      map[applicationBundleKey][]ApplicationVirtualModule
	uncertain map[applicationBundleRuntime]bool
	slots     map[applicationBundleSlot]ApplicationVirtualModule
}

func applicationBundleRuntimeKey(path, framework, runtime string) applicationBundleRuntime {
	if !strings.HasPrefix(runtime, "webpack-bootstrap@ast:") {
		path = ""
	}
	return applicationBundleRuntime{framework, runtime, path}
}
func newApplicationBundleIndex(modules []ApplicationVirtualModule) *applicationBundleIndex {
	i := &applicationBundleIndex{keys: map[applicationBundleKey][]ApplicationVirtualModule{}, uncertain: map[applicationBundleRuntime]bool{}, slots: map[applicationBundleSlot]ApplicationVirtualModule{}}
	for _, m := range modules {
		runtime := applicationBundleRuntimeKey(m.Path, m.Framework, m.Runtime)
		if m.KeyState != "static" {
			i.uncertain[runtime] = true
		}
		if m.KeyState != "unknown" {
			k := applicationBundleKey{runtime, m.ModuleKey}
			i.keys[k] = append(i.keys[k], m)
		}
		i.slots[applicationBundleSlot{m.Path, m.Registration, m.ModuleIndex}] = m
	}
	return i
}
func (i *applicationBundleIndex) relation(path string, f JavaScriptFact) ModuleRelation {
	r := ModuleRelation{ASTNode: f.ASTNode, Kind: f.Kind, Specifier: f.Value, Resolution: "bundle-target-unavailable", Candidates: []string{}, Loader: "bundler-static", Bundle: f.Bundle}
	if f.Dynamic {
		r.Resolution = "bundle-target-dynamic"
		r.Reason = "module key is not an exact supported literal"
		return r
	}
	uncertain := false
	if f.BundleTarget != nil {
		if target, ok := i.slots[applicationBundleSlot{path, f.BundleTarget.Registration, *f.BundleTarget.ModuleIndex}]; ok {
			r.VirtualCandidates = append(r.VirtualCandidates, target)
			uncertain = target.KeyState != "static"
		}
	} else {
		runtime := applicationBundleRuntimeKey(path, f.Bundle.Framework, f.Bundle.Runtime)
		uncertain = i.uncertain[runtime]
		r.VirtualCandidates = i.keys[applicationBundleKey{runtime, f.Value}]
	}
	if uncertain || len(r.VirtualCandidates) > 1 {
		r.Resolution = "bundle-target-ambiguous"
		r.Reason = "duplicate, unknown or spread module-table keys prevent unique static selection"
	} else if len(r.VirtualCandidates) == 1 {
		r.Resolution = "bundle-module-candidate"
		r.Reason = "literal table or wrapper-binding candidate; no module dispatch or execution observed"
	} else {
		r.Reason = "module factory not present in the selected snapshot; it may be in an unloaded chunk or external runtime"
	}
	return r
}
