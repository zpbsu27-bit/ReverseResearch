package appinspect

import (
	"errors"
	"path"
	"sort"
	"strings"
)

type PackageOptions struct {
	PageOptions
	Family        string `json:"family"`
	View          string `json:"view,omitempty"`
	ResourceIndex *int   `json:"resource_index,omitempty"`
}
type PackageComponent struct {
	Entry             ZIPEntry `json:"entry"`
	Role              string   `json:"role"`
	BundlePath        string   `json:"bundle_path,omitempty"`
	RuntimeHint       string   `json:"runtime_hint,omitempty"`
	RoleBasis         string   `json:"role_basis"`
	ContentSHA256     string   `json:"content_sha256,omitempty"`
	ContentVerified   bool     `json:"content_verified"`
	UnavailableReason string   `json:"unavailable_reason,omitempty"`
}
type PackageBundle struct {
	Path                      string   `json:"path"`
	ParentPath                string   `json:"parent_path,omitempty"`
	Role                      string   `json:"role"`
	Layout                    string   `json:"layout"`
	InfoPlist                 *string  `json:"info_plist"`
	InfoStatus                string   `json:"info_status"`
	ExecutableCandidates      []string `json:"executable_candidates"`
	TotalExecutableCandidates int      `json:"total_executable_candidates"`
	RuntimeHints              []string `json:"runtime_hints"`
	Basis                     string   `json:"basis"`
	deep                      bool
	versions                  map[string]bool
}
type PackageReport struct {
	Path                      string                  `json:"path"`
	SHA256                    string                  `json:"sha256"`
	Family                    string                  `json:"family"`
	PackageKind               string                  `json:"package_kind"`
	PackagingModelHint        string                  `json:"packaging_model_hint"`
	View                      string                  `json:"view"`
	TotalEntries              int                     `json:"total_entries"`
	TotalComponents           int                     `json:"total_components"`
	TotalBundles              int                     `json:"total_bundles"`
	Offset                    int                     `json:"offset"`
	Components                []PackageComponent      `json:"components,omitempty"`
	Bundles                   []PackageBundle         `json:"bundles,omitempty"`
	Manifest                  *AndroidManifestReport  `json:"manifest,omitempty"`
	Resources                 *AndroidResourcesReport `json:"resources,omitempty"`
	InspectedEntry            *ZIPEntry               `json:"inspected_entry,omitempty"`
	ContentSHA256             string                  `json:"content_sha256,omitempty"`
	ContentVerified           bool                    `json:"content_verified"`
	NextOffset                *int                    `json:"next_offset,omitempty"`
	ArchiveDirectoryValidated bool                    `json:"archive_directory_validated"`
	CoverageComplete          bool                    `json:"coverage_complete"`
	ExecutionPerformed        bool                    `json:"execution_performed"`
	EvidenceAuthority         string                  `json:"evidence_authority"`
	Limitations               []string                `json:"limitations"`
}

func bundleRole(segment string) string {
	for _, v := range []struct{ suffix, role string }{{".app", "application"}, {".appex", "app-extension"}, {".framework", "framework"}, {".xpc", "xpc-service"}, {".systemextension", "system-extension"}, {".dext", "driver-extension"}, {".plugin", "plug-in"}, {".bundle", "bundle"}} {
		if strings.HasSuffix(segment, v.suffix) {
			return v.role
		}
	}
	return ""
}
func frameworkHint(segment string) string {
	switch segment {
	case "React.framework", "ReactNative.framework", "hermes.framework":
		return "react-native"
	case "Flutter.framework":
		return "flutter"
	case "UnityFramework.framework":
		return "unity"
	}
	return ""
}

func InspectPackage(p string, o PackageOptions) (PackageReport, error) {
	if o.Family != "apple" && o.Family != "harmony" && o.Family != "android" {
		return PackageReport{}, errors.New("package family must be apple, harmony or android")
	}
	if o.View == "" {
		o.View = "components"
	}
	if o.Family == "android" {
		if o.View != "components" && o.View != "manifest" && o.View != "resources" && o.View != "resource-values" {
			return PackageReport{}, errors.New("Android view must be components, manifest, resources or resource-values")
		}
		if (o.View == "resource-values") != (o.ResourceIndex != nil) {
			return PackageReport{}, errors.New("resource-values requires resource_index; other views do not accept it")
		}
		if o.Offset > 0 && o.ExpectedSHA256 == "" {
			return PackageReport{}, errors.New("subsequent Android pages require expected_sha256")
		}
	} else if o.ResourceIndex != nil || o.View != "components" && o.View != "bundles" {
		return PackageReport{}, errors.New("package view must be components or bundles")
	}
	if o.Family == "harmony" && o.View == "bundles" {
		return PackageReport{}, errors.New("bundle anatomy view is defined for Apple packages only")
	}
	body, abs, hash, err := readArtifact(p, MaxArtifactBytes, o.ExpectedSHA256)
	if err != nil {
		return PackageReport{}, err
	}
	files, entries, err := parseZIP(body)
	if err != nil {
		return PackageReport{}, err
	}
	if o.Family == "android" {
		return inspectAndroidPackageSnapshot(abs, hash, files, entries, o)
	}
	r := PackageReport{Path: abs, SHA256: hash, Family: o.Family, PackageKind: "zip", PackagingModelHint: "unknown", View: o.View, TotalEntries: len(entries), ArchiveDirectoryValidated: true, EvidenceAuthority: "archive-content-and-path-conventions", Limitations: []string{"all directory paths/ranges are validated; only returned available components are decompressed and CRC checked", "path/runtime-family hints and executable candidates are declarations, not observed loading or native bindings", "no extraction, nested package recursion, app install, class instantiation, target execution or signature/entitlement verification", "absence beyond the admitted inventory is unknown; no second durable application graph or Case completion owner"}}
	if o.Family == "harmony" {
		switch strings.ToLower(path.Ext(abs)) {
		case ".hap":
			r.PackageKind = "harmony-hap"
		case ".hsp":
			r.PackageKind = "harmony-hsp"
		case ".app":
			r.PackageKind = "harmony-app-pack"
		default:
			return r, errors.New("Harmony profile requires a ZIP-backed .hap, .hsp or .app; .har is ambiguous")
		}
		r.Limitations = append(r.Limitations, "Stage/FA are root-manifest path hints only; module/ability/permission/dependency semantics and Ark bytecode versions remain unknown")
	} else if strings.EqualFold(path.Ext(abs), ".ipa") {
		r.PackageKind = "ipa"
	}
	components := []PackageComponent{}
	indices := []int{}
	bundleMap := map[string]*PackageBundle{}
	paths := map[string]ZIPEntry{}
	for _, e := range entries {
		paths[strings.TrimSuffix(e.Path, "/")] = e
	}
	for i, e := range entries {
		c := PackageComponent{Entry: e, Role: "resource", RoleBasis: "path-convention", UnavailableReason: e.UnavailableReason}
		name := strings.TrimSuffix(e.Path, "/")
		parts := strings.Split(name, "/")
		base := path.Base(name)
		if o.Family == "harmony" {
			switch {
			case name == "module.json" || name == "config.json" || base == "pack.info":
				c.Role = "manifest"
			case strings.HasSuffix(name, ".abc"):
				c.Role = "ark-bytecode"
				c.RuntimeHint = "ark"
			case strings.HasPrefix(name, "libs/") && len(parts) >= 3 && strings.HasSuffix(name, ".so"):
				c.Role = "native-library"
				c.RuntimeHint = "native"
			case jsExtension(name):
				c.Role = "javascript"
				c.RuntimeHint = "javascript"
			case strings.HasPrefix(name, "META-INF/"):
				c.Role = "signing-metadata"
			case strings.HasSuffix(name, ".hap") || strings.HasSuffix(name, ".hsp"):
				c.Role = "child-package"
			}
		} else {
			parent := ""
			bundleParts := parts[:len(parts)-1]
			if e.Kind == "directory" {
				bundleParts = parts
			}
			for j, part := range bundleParts {
				role := bundleRole(part)
				if role == "" {
					continue
				}
				root := strings.Join(parts[:j+1], "/")
				b := bundleMap[root]
				if b == nil {
					if len(bundleMap) >= 1024 {
						return r, errors.New("Apple bundle count exceeds 1024")
					}
					b = &PackageBundle{Path: root, ParentPath: parent, Role: role, Layout: "shallow", InfoStatus: "missing-or-unavailable", ExecutableCandidates: []string{}, RuntimeHints: []string{}, Basis: "path-convention", versions: map[string]bool{}}
					bundleMap[root] = b
				}
				relative := parts[j+1:]
				if len(relative) > 0 && relative[0] == "Contents" {
					b.deep = true
				}
				if len(relative) > 1 && relative[0] == "Versions" && relative[1] != "Current" && e.Kind != "link-or-special" {
					b.versions[relative[1]] = true
				}
				if len(relative) == 3 && relative[0] == "Contents" && relative[1] == "MacOS" && e.Available {
					b.TotalExecutableCandidates++
					if len(b.ExecutableCandidates) < 50 {
						b.ExecutableCandidates = append(b.ExecutableCandidates, name)
					}
				}
				parent = root
				c.BundlePath = root
				if hint := frameworkHint(part); hint != "" {
					c.RuntimeHint = hint
					found := false
					for _, s := range b.RuntimeHints {
						found = found || s == hint
					}
					if !found {
						b.RuntimeHints = append(b.RuntimeHints, hint)
					}
				}
			}
			switch {
			case base == "Info.plist":
				c.Role = "info-plist"
			case strings.Contains(name, "/_CodeSignature/") || base == "embedded.mobileprovision" || base == "CodeResources":
				c.Role = "signing-metadata"
			case jsExtension(name) || strings.HasSuffix(name, ".jsbundle"):
				c.Role = "javascript"
				if c.RuntimeHint == "" {
					c.RuntimeHint = "javascript"
				}
			case strings.HasSuffix(name, ".dylib") || strings.HasSuffix(name, ".so") || strings.Contains(name, "/Contents/MacOS/"):
				c.Role = "native-candidate"
			case strings.HasSuffix(name, ".nib") || strings.HasSuffix(name, ".storyboardc"):
				c.Role = "interface-builder"
			case base == "Assets.car":
				c.Role = "asset-catalog"
			}
		}
		if e.Kind == "directory" {
			continue
		}
		if e.Available && e.Size > 16<<20 {
			c.UnavailableReason = "content exceeds 16 MiB selected-member limit"
		}
		components = append(components, c)
		indices = append(indices, i)
	}
	if o.Family == "harmony" {
		_, stage := paths["module.json"]
		_, fa := paths["config.json"]
		switch {
		case stage && fa:
			r.PackagingModelHint = "mixed-stage-fa-paths"
		case stage:
			r.PackagingModelHint = "stage-path"
		case fa:
			r.PackagingModelHint = "fa-path"
		}
	}
	bundles := []PackageBundle{}
	for root, b := range bundleMap {
		versions, deep := b.versions, b.deep
		candidate := root + "/Info.plist"
		if deep {
			b.Layout = "macos-deep"
			candidate = root + "/Contents/Info.plist"
		} else if len(versions) > 0 && b.Role == "framework" {
			b.Layout = "versioned-framework"
			candidate = ""
			b.InfoStatus = "ambiguous-version-selection"
			if len(versions) == 1 {
				for version := range versions {
					candidate = root + "/Versions/" + version + "/Resources/Info.plist"
				}
			}
		}
		if e, ok := paths[candidate]; candidate != "" && ok && e.Available {
			b.InfoPlist = &candidate
			b.InfoStatus = "path-candidate"
		}
		if b.Role == "application" && strings.Contains(root, "/Contents/Library/LoginItems/") {
			b.Role = "login-item"
		} else if b.Role == "application" && strings.Contains(root, "/Contents/Helpers/") {
			b.Role = "helper-application"
		} else if b.Role == "application" && b.ParentPath != "" {
			b.Role = "nested-application"
		}
		sort.Strings(b.ExecutableCandidates)
		sort.Strings(b.RuntimeHints)
		bundles = append(bundles, *b)
	}
	sort.Slice(bundles, func(i, j int) bool { return bundles[i].Path < bundles[j].Path })
	r.TotalBundles = len(bundles)
	r.TotalComponents = len(components)
	if len(bundles) > 1024 {
		return r, errors.New("Apple bundle count exceeds 1024")
	}
	total := len(components)
	if o.View == "bundles" {
		total = len(bundles)
	}
	start, end, err := page(o.PageOptions, total)
	if err != nil {
		return r, err
	}
	r.Offset = start
	r.CoverageComplete = start == 0 && end == total
	if o.View == "bundles" {
		r.Bundles = bundles[start:end]
		for _, b := range r.Bundles {
			if b.TotalExecutableCandidates > len(b.ExecutableCandidates) {
				r.CoverageComplete = false
			}
		}
		r.Limitations = append(r.Limitations, "bundle view uses inventory path conventions only; plist values and CFBundleExecutable are not interpreted")
	} else {
		budget := uint64(0)
		for j := start; j < end; j++ {
			c := components[j]
			if c.Entry.Available && c.UnavailableReason == "" {
				budget += c.Entry.Size
				if budget > 32<<20 {
					return r, errors.New("package page decompression exceeds 32 MiB; reduce limit")
				}
				content, err := readZIPContent(files[indices[j]], c.Entry, 16<<20)
				if err != nil {
					return r, err
				}
				c.ContentSHA256 = digest(content)
				c.ContentVerified = true
			} else {
				r.CoverageComplete = false
			}
			r.Components = append(r.Components, c)
		}
	}
	if end < total {
		r.NextOffset = &end
	}
	return r, projectionLimit(r)
}
