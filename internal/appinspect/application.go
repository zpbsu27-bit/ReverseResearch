package appinspect

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"reverseresearch/internal/recordio"
	"sort"
	"strings"
)

type ModuleRelation struct {
	ASTNode           int                           `json:"ast_node"`
	Kind              string                        `json:"kind"`
	Specifier         string                        `json:"specifier"`
	Resolution        string                        `json:"resolution"`
	Candidates        []string                      `json:"candidates"`
	Loader            string                        `json:"loader"`
	Reason            string                        `json:"reason,omitempty"`
	Target            string                        `json:"selected_target,omitempty"`
	Packages          []ApplicationPackageReference `json:"package_metadata,omitempty"`
	Bundle            *JavaScriptBundle             `json:"bundle,omitempty"`
	VirtualCandidates []ApplicationVirtualModule    `json:"virtual_candidates,omitempty"`
}

type ApplicationPackageReference struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256,omitempty"`
	Available bool   `json:"available"`
}
type ApplicationModule struct {
	Path                  string                     `json:"path"`
	SHA256                string                     `json:"sha256"`
	Available             bool                       `json:"available"`
	UnavailableReason     string                     `json:"unavailable_reason,omitempty"`
	FactCount             int                        `json:"fact_count"`
	Relations             []ModuleRelation           `json:"relations"`
	ElectronCandidates    int                        `json:"electron_candidates"`
	EndpointCandidates    int                        `json:"endpoint_candidates"`
	ImportBindings        int                        `json:"import_bindings"`
	ExportFacts           int                        `json:"export_facts"`
	ExportPreview         []JavaScriptFact           `json:"export_preview,omitempty"`
	ExportPreviewComplete bool                       `json:"export_preview_complete"`
	VirtualModules        []ApplicationVirtualModule `json:"virtual_modules,omitempty"`
	BundleFactCount       int                        `json:"bundle_fact_count"`
	BundlePreview         []JavaScriptFact           `json:"bundle_preview,omitempty"`
	BundlePreviewComplete bool                       `json:"bundle_preview_complete"`
}
type ApplicationReport struct {
	Path                string              `json:"path"`
	SHA256              string              `json:"sha256"`
	IdentityKind        string              `json:"identity_kind"`
	TotalModules        int                 `json:"total_modules"`
	TotalVirtualModules int                 `json:"total_virtual_modules"`
	SelectedInputs      int                 `json:"selected_inputs"`
	PackageManifests    int                 `json:"package_manifests"`
	ResolutionProfile   string              `json:"resolution_profile"`
	BundlerProfile      string              `json:"bundler_profile"`
	Offset              int                 `json:"offset"`
	Modules             []ApplicationModule `json:"modules"`
	NextOffset          *int                `json:"next_offset,omitempty"`
	CoverageComplete    bool                `json:"coverage_complete"`
	EvidenceAuthority   string              `json:"evidence_authority"`
	ExecutionPerformed  bool                `json:"execution_performed"`
	NetworkInteraction  bool                `json:"network_interaction"`
	Limitations         []string            `json:"limitations"`
}
type applicationInput struct {
	name, hash, reason, kind string
	content                  []byte
}

func jsExtension(name string) bool {
	switch strings.ToLower(path.Ext(name)) {
	case ".js", ".mjs", ".cjs":
		return true
	}
	return false
}

func applicationKind(name string) string {
	if jsExtension(name) {
		return "javascript"
	}
	switch path.Ext(name) {
	case ".json":
		return "json"
	case ".node":
		return "native-addon"
	}
	return ""
}

func applicationInputs(root string) ([]applicationInput, string, string, string, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, "", "", "", err
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return nil, "", "", "", err
	}
	items := []applicationInput{}
	bytesRead := 0
	fileCount, directoryCount, nameBytes := 0, 0, 0
	add := func(v applicationInput) error {
		if _, err := safeArchivePath(v.name); err != nil {
			return err
		}
		nameBytes += len(v.name)
		if v.kind == "directory" || v.kind == "boundary" {
			directoryCount++
		} else {
			fileCount++
		}
		if fileCount > 2048 || directoryCount > 8192 || nameBytes > 1<<20 {
			return errors.New("application selected file/path-boundary/name budget exceeded")
		}
		bytesRead += len(v.content)
		if bytesRead > 32<<20 {
			return errors.New("application selected bytes exceed 32 MiB")
		}
		items = append(items, v)
		return nil
	}
	if info.Mode().IsRegular() {
		body, abs, hash, err := readArtifact(abs, MaxArtifactBytes, "")
		if err != nil {
			return nil, "", "", "", err
		}
		entries, err := parseASAR(body)
		if err != nil {
			return nil, "", "", "", err
		}
		for _, e := range entries {
			kind := applicationKind(e.Path)
			if e.Kind == "directory" {
				kind = "directory"
			}
			if kind == "" {
				kind = "boundary"
			}
			v := applicationInput{name: e.Path, reason: e.UnavailableReason, kind: kind}
			if kind == "boundary" && v.reason == "" {
				v.reason = "file bytes are outside the selected JS/JSON/native-addon profile"
			}
			if e.Available && kind != "directory" && kind != "boundary" {
				if e.Size > MaxJavaScriptBytes {
					return nil, "", "", "", errors.New("selected application entry exceeds 1 MiB")
				}
				v.content = body[e.ByteOffset : e.ByteOffset+e.Size]
				v.hash = digest(v.content)
			}
			if err := add(v); err != nil {
				return nil, "", "", "", err
			}
		}
		return items, abs, hash, "asar-sha256", nil
	}
	if !info.IsDir() {
		return nil, "", "", "", errors.New("application must be a regular ASAR or real directory")
	}
	visited := 0
	err = filepath.WalkDir(abs, func(p string, e fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		visited++
		if visited > 100000 {
			return errors.New("application tree visit limit exceeded")
		}
		rel, err := filepath.Rel(abs, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if e.IsDir() {
			if p != abs {
				switch e.Name() {
				case ".git", ".tmp":
					return filepath.SkipDir
				}
			}
			if p == abs {
				return nil
			}
			return add(applicationInput{name: rel, kind: "directory"})
		}
		kind := applicationKind(rel)
		if kind == "" {
			kind = "boundary"
		}
		item := applicationInput{name: rel, kind: kind}
		if e.Type()&os.ModeSymlink != 0 {
			item.reason = "symlink paths are not followed"
		} else if kind == "boundary" {
			item.reason = "file bytes are outside the selected JS/JSON/native-addon profile"
		} else {
			content, _, hash, err := readArtifact(p, MaxJavaScriptBytes, "")
			if err != nil {
				return err
			}
			item.content = content
			item.hash = hash
		}
		return add(item)
	})
	if err != nil {
		return nil, "", "", "", err
	}
	sort.Slice(items, func(i, j int) bool { return items[i].name < items[j].name })
	manifest := [][4]string{}
	for _, i := range items {
		manifest = append(manifest, [4]string{i.kind, i.name, i.hash, i.reason})
	}
	body, _ := json.Marshal(manifest)
	return items, abs, digest(body), "selected-javascript-package-inventory-sha256", nil
}

func InspectApplication(root string, o PageOptions) (ApplicationReport, error) {
	inputs, abs, hash, identity, err := applicationInputs(root)
	if err != nil {
		return ApplicationReport{}, err
	}
	if err := recordio.CheckExpectedSHA256(hash, o.ExpectedSHA256); err != nil {
		return ApplicationReport{}, err
	}
	resolver, err := newApplicationResolver(inputs)
	if err != nil {
		return ApplicationReport{}, err
	}
	analyses := map[string][]JavaScriptFact{}
	virtual := []ApplicationVirtualModule{}
	for _, i := range inputs {
		if i.kind != "javascript" || i.reason != "" {
			continue
		}
		facts, err := javascriptFacts(i.content)
		if err != nil {
			return ApplicationReport{}, errors.New("a selected JavaScript module is malformed, unsupported or exceeds analysis budgets")
		}
		analyses[i.name] = facts
		for _, f := range facts {
			if f.Kind == "bundle-module-candidate" {
				virtual = append(virtual, applicationVirtualModule(i.name, f.Bundle))
				if len(virtual) > 8192 {
					return ApplicationReport{}, errors.New("application virtual modules exceed 8192")
				}
			}
		}
	}
	virtualIndex := newApplicationBundleIndex(virtual)
	modules := []ApplicationModule{}
	for _, i := range inputs {
		if i.kind != "javascript" {
			continue
		}
		m := ApplicationModule{Path: i.name, SHA256: i.hash, Available: i.reason == "", UnavailableReason: i.reason, Relations: []ModuleRelation{}}
		if i.reason == "" {
			facts := analyses[i.name]
			m.FactCount = len(facts)
			m.ExportPreviewComplete = true
			m.BundlePreviewComplete = true
			for _, f := range facts {
				if strings.HasPrefix(f.Kind, "bundle-") {
					m.BundleFactCount++
					if len(m.BundlePreview) < 64 {
						m.BundlePreview = append(m.BundlePreview, f)
					} else {
						m.BundlePreviewComplete = false
					}
				}
				switch f.Kind {
				case "bundle-module-candidate":
					m.VirtualModules = append(m.VirtualModules, applicationVirtualModule(i.name, f.Bundle))
				case "bundle-module-request", "bundle-entry-candidate":
					m.Relations = append(m.Relations, virtualIndex.relation(i.name, f))
				case "import", "re-export", "module-request":
					m.Relations = append(m.Relations, resolver.relation(i.name, f))
				case "electron-api-candidate", "electron-window-candidate":
					m.ElectronCandidates++
				case "endpoint-candidate":
					m.EndpointCandidates++
				case "import-binding":
					m.ImportBindings++
				case "export-binding", "commonjs-export-candidate", "commonjs-export-member-candidate", "shadowed-export-assignment", "bundle-export-candidate", "bundle-export-object-candidate":
					m.ExportFacts++
					if len(m.ExportPreview) < 20 {
						m.ExportPreview = append(m.ExportPreview, f)
					} else {
						m.ExportPreviewComplete = false
					}
				}
			}
		}
		modules = append(modules, m)
	}
	start, end, err := page(o, len(modules))
	if err != nil {
		return ApplicationReport{}, err
	}
	r := ApplicationReport{Path: abs, SHA256: hash, IdentityKind: identity, TotalModules: len(modules), SelectedInputs: len(inputs), PackageManifests: len(resolver.packages), ResolutionProfile: "node-24.19-default-static-path-candidates", Offset: start, Modules: modules[start:end], CoverageComplete: start == 0 && end == len(modules), EvidenceAuthority: "static-artifact-inventory", Limitations: []string{"selected JS/JSON/native-addon bytes and directory/unread-file/link boundaries; .git/.tmp directories omitted; 2048 selected files, 8192 path boundaries, 1 MiB per file and 32 MiB selected bytes", "case-sensitive logical paths and Node default conditions node/node-addons/module-sync/import or require/default; custom loaders, bundler/tsconfig aliases, recursive or external imports targets remain unresolved", "path candidates do not establish module loading, execution, exports compatibility or native-addon ABI; original specifiers and selected targets retain URL suffixes", "directory SHA covers selected relative paths/content/kinds/availability, not unread file bytes; all selected JS/package metadata are validated before paging; no dependency downloads or target execution"}}
	for _, m := range r.Modules {
		if m.Available && (!m.ExportPreviewComplete || !m.BundlePreviewComplete) {
			r.CoverageComplete = false
		}
	}
	r.TotalVirtualModules = len(virtual)
	r.BundlerProfile = "webpack-rspack-esbuild-static-v1"
	r.Limitations = append(r.Limitations, "bundler object/array factories and internal module requests use typed virtual-module candidates rather than Node file paths; 8192 virtual modules per application; matching runtime spelling across chunks does not prove shared runtime identity", "bundle previews are limited to 64 facts per file; request app_javascript_inspect for paged full facts; graphs over the existing 48 KiB output limit fail closed")
	if end < len(modules) {
		r.NextOffset = &end
	}
	// Detect both file changes and additions/removals while composing the graph.
	_, _, final, _, err := applicationInputs(root)
	if err != nil {
		return r, err
	}
	if final != hash {
		return r, errors.New("application changed during static projection")
	}
	return r, projectionLimit(r)
}
