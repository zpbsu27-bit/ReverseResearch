package appinspect

import (
	"archive/zip"
	"errors"
	"path"
	"strconv"
	"strings"
)

func androidComponent(e ZIPEntry) PackageComponent {
	c := PackageComponent{Entry: e, Role: "resource", RoleBasis: "path-convention", UnavailableReason: e.UnavailableReason}
	parts := strings.Split(e.Path, "/")
	switch {
	case e.Path == "AndroidManifest.xml":
		c.Role = "android-manifest"
	case e.Path == "resources.arsc":
		c.Role = "compiled-resources"
	case len(parts) == 1 && strings.HasPrefix(e.Path, "classes") && strings.HasSuffix(e.Path, ".dex"):
		suffix := strings.TrimSuffix(strings.TrimPrefix(e.Path, "classes"), ".dex")
		n, err := strconv.Atoi(suffix)
		if suffix == "" || err == nil && n >= 2 && strconv.Itoa(n) == suffix {
			c.Role = "dalvik-bytecode"
			c.RuntimeHint = "dalvik-art"
		}
	case len(parts) == 3 && parts[0] == "lib" && strings.HasSuffix(parts[2], ".so"):
		c.Role = "native-library"
		c.RuntimeHint = "native"
	case strings.HasPrefix(e.Path, "assets/"):
		c.Role = "asset"
	case strings.HasPrefix(e.Path, "META-INF/"):
		c.Role = "signing-metadata"
	case strings.HasPrefix(e.Path, "res/"):
		c.Role = "android-resource"
	}
	return c
}

func inspectAndroidPackageSnapshot(abs, hash string, files []*zip.File, entries []ZIPEntry, o PackageOptions) (PackageReport, error) {
	r := PackageReport{Path: abs, SHA256: hash, Family: "android", PackageKind: "android-apk", PackagingModelHint: "apk-member; split relationship unverified", View: o.View, TotalEntries: len(entries), ArchiveDirectoryValidated: true, EvidenceAuthority: "archive bytes and Android static declarations", Limitations: []string{"APK member names/layouts and manifest/resource/DEX declarations are not runtime bindings", "one APK may be a split member; installation-set identity and signing compatibility are unverified", "no extraction, installation, signing, resource inflation, target execution or second durable application graph"}}
	if !strings.EqualFold(path.Ext(abs), ".apk") {
		return r, errors.New("Android package profile requires one ZIP-backed .apk")
	}
	manifestFound := false
	components := []PackageComponent{}
	indices := []int{}
	for i, e := range entries {
		if e.Path == "AndroidManifest.xml" {
			manifestFound = true
		}
		if e.Kind != "directory" {
			components = append(components, androidComponent(e))
			indices = append(indices, i)
		}
	}
	if !manifestFound {
		return r, errors.New("APK has no exact root AndroidManifest.xml entry")
	}
	r.TotalComponents = len(components)
	if o.View == "components" {
		start, end, err := page(o.PageOptions, len(components))
		if err != nil {
			return r, err
		}
		r.Offset = start
		r.CoverageComplete = start == 0 && end == len(components)
		budget := uint64(0)
		for i := start; i < end; i++ {
			c := components[i]
			if c.Entry.Available && c.Entry.Size <= 16<<20 {
				budget += c.Entry.Size
				if budget > 32<<20 {
					return r, errors.New("APK component page decompression exceeds 32 MiB")
				}
				v, err := readZIPContent(files[indices[i]], c.Entry, 16<<20)
				if err != nil {
					return r, err
				}
				c.ContentSHA256 = digest(v)
				c.ContentVerified = true
			} else {
				r.CoverageComplete = false
				if c.Entry.Available {
					c.UnavailableReason = "content exceeds 16 MiB selected component limit"
				}
			}
			r.Components = append(r.Components, c)
		}
		if end < len(components) {
			r.NextOffset = &end
		}
		return r, projectionLimit(r)
	}
	member := "AndroidManifest.xml"
	limit := 16 << 20
	if o.View == "resources" || o.View == "resource-values" {
		member = "resources.arsc"
		limit = MaxArtifactBytes
	}
	found := -1
	for i, e := range entries {
		if e.Path == member {
			found = i
			break
		}
	}
	if found < 0 {
		return r, errors.New("requested APK metadata member is missing")
	}
	v, err := readZIPContent(files[found], entries[found], limit)
	if err != nil {
		return r, err
	}
	entry := entries[found]
	r.InspectedEntry = &entry
	r.ContentSHA256 = digest(v)
	r.ContentVerified = true
	if o.View == "manifest" {
		m, err := inspectAndroidManifest(v, o.PageOptions)
		if err != nil {
			return r, err
		}
		r.Manifest = &m
		r.Offset = m.Offset
		r.NextOffset = m.NextOffset
		r.CoverageComplete = m.CoverageComplete
	} else {
		resources, err := inspectAndroidResources(v, o.PageOptions, o.ResourceIndex)
		if err != nil {
			return r, err
		}
		r.Resources = &resources
		r.Offset = resources.Offset
		r.NextOffset = resources.NextOffset
		r.CoverageComplete = resources.CoverageComplete
	}
	return r, projectionLimit(r)
}
