package appinspect

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"reverseresearch/internal/appinspect/testfixture"
)

func TestAndroidPackageManifestAndCompiledResources(t *testing.T) {
	p := packageVector(t, "app.apk", map[string][]byte{"AndroidManifest.xml": testfixture.AndroidManifest(), "resources.arsc": testfixture.AndroidResources(0, false), "classes2.dex": testfixture.DEX(), "lib/arm64-v8a/libdemo.so": []byte("inert native declaration")})
	r, err := InspectPackage(p, PackageOptions{Family: "android", View: "manifest"})
	if err != nil {
		t.Fatal(err)
	}
	m := r.Manifest
	if m.PackageName == nil || *m.PackageName != "rrfixture.demo" || m.TotalElements != 4 || m.PermissionDeclarations != 1 || m.ComponentDeclarations != 1 || r.ExecutionPerformed || !r.ContentVerified || m.EffectivePermissionsVerified {
		t.Fatalf("manifest: %+v", m)
	}
	a := m.Elements[3].Attributes
	if a[0].Typed.String.Text == nil || *a[0].Typed.String.Text != "rrfixture.demo.Main" || a[1].Typed.Type != 0x12 || a[1].Typed.Data != 0 {
		t.Fatalf("typed declarations lost: %+v", a)
	}
	resources, err := InspectPackage(p, PackageOptions{Family: "android", View: "resources"})
	if err != nil {
		t.Fatal(err)
	}
	s := resources.Resources
	if s.TotalResourceConfigurations != 2 || s.Resources[0].ID != 0x7f010000 || s.Resources[0].KeyName == nil || *s.Resources[0].KeyName != "title" || s.Resources[0].Value.String.Text == nil || *s.Resources[0].Value.String.Text != "hello" || s.Resources[1].TotalMappings != 1 || s.EffectiveValuesResolved {
		t.Fatalf("resources: %+v", s)
	}
	i := 1
	detail, err := InspectPackage(p, PackageOptions{Family: "android", View: "resource-values", ResourceIndex: &i})
	if err != nil || len(detail.Resources.Mappings) != 1 || detail.Resources.Mappings[0].Value.Data != 7 {
		t.Fatalf("bag: %+v %v", detail.Resources, err)
	}
	components, err := InspectPackage(p, PackageOptions{Family: "android"})
	if err != nil {
		t.Fatal(err)
	}
	roles := map[string]bool{}
	for _, c := range components.Components {
		roles[c.Role] = true
	}
	if !roles["android-manifest"] || !roles["compiled-resources"] || !roles["dalvik-bytecode"] || !roles["native-library"] {
		t.Fatal(roles)
	}
	if _, err := InspectPackage(p, PackageOptions{Family: "android", View: "manifest", PageOptions: PageOptions{Offset: 1}}); err == nil {
		t.Fatal("unfenced Android page accepted")
	}
	if _, err := InspectPackage(p, PackageOptions{Family: "android", View: "manifest", PageOptions: PageOptions{ExpectedSHA256: strings.Repeat("0", 64)}}); err == nil {
		t.Fatal("stale Android SHA accepted")
	}
}

func TestAndroidResourceOffsetAndCompactVariants(t *testing.T) {
	for _, flags := range []uint8{0, 1, 2} {
		for _, compact := range []bool{false, true} {
			v := testfixture.AndroidResources(flags, compact)
			r, err := inspectAndroidResources(v, PageOptions{}, nil)
			if err != nil {
				t.Fatalf("flags=%d compact=%v: %v", flags, compact, err)
			}
			if len(r.Resources) != 2 || r.Resources[0].Compact != compact || r.Resources[0].Value.String.Text == nil || *r.Resources[0].Value.String.Text != "hello" {
				t.Fatal(r)
			}
		}
	}
}

func TestAndroidManifestPlainXMLAndEntityBoundary(t *testing.T) {
	good := []byte(`<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="demo"><uses-permission android:name="android.permission.INTERNET"/><application><activity android:name="demo.😀"/></application></manifest>`)
	r, err := inspectAndroidManifest(good, PageOptions{})
	if err != nil || r.TotalElements != 4 || r.PermissionDeclarations != 1 || r.ComponentDeclarations != 1 {
		t.Fatalf("plain XML: %+v %v", r, err)
	}
	for _, raw := range []string{`<!DOCTYPE manifest [<!ENTITY remote SYSTEM "http://example.invalid/secret">]><manifest/>`, `<manifest/><manifest/>`, `<manifest><application></manifest>`, `<manifest package="a" package="b"/>`} {
		if _, err := inspectAndroidManifest([]byte(raw), PageOptions{Limit: 1}); err == nil {
			t.Fatalf("invalid XML accepted: %s", raw)
		}
	}
}

func TestAndroidRejectsMalformedHiddenMetadata(t *testing.T) {
	base := testfixture.AndroidManifest()
	pool, _ := androidChunkAt(base, 8)
	for _, test := range []struct {
		name   string
		mutate func([]byte)
	}{
		{"pool-count", func(b []byte) { binary.LittleEndian.PutUint32(b[16:], 0xffffffff) }},
		{"hidden-string-range", func(b []byte) { binary.LittleEndian.PutUint32(b[8+28+11*4:], 0xffffffff) }},
		{"root-range", func(b []byte) { binary.LittleEndian.PutUint32(b[4:], uint32(len(b)+4)) }},
		{"last-end-tag", func(b []byte) { at := len(b) - 24 - 24; binary.LittleEndian.PutUint32(b[at+20:], 3) }},
		{"utf8-length", func(b []byte) { b[pool.start+int(u32(pool.body[20:]))] = 99 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			b := bytes.Clone(base)
			test.mutate(b)
			if _, err := inspectAndroidManifest(b, PageOptions{Limit: 1}); err == nil {
				t.Fatal("hidden malformed manifest accepted")
			}
		})
	}
	arsc := testfixture.AndroidResources(0, false)
	global, _ := androidChunkAt(arsc, 12)
	pkg, _ := androidChunkAt(arsc, 12+global.size)
	typAt := 0
	for at := pkg.header; at < pkg.size; {
		c, _ := androidChunkAt(pkg.body, at)
		if c.kind == 0x201 {
			typAt = pkg.start + at
			break
		}
		at += c.size
	}
	for _, test := range []struct {
		name   string
		mutate func([]byte)
	}{
		{"package-count", func(b []byte) { binary.LittleEndian.PutUint32(b[8:], 9) }},
		{"key-pool-offset", func(b []byte) { binary.LittleEndian.PutUint32(b[pkg.start+276:], 0xffffffff) }},
		{"type-offset-overflow", func(b []byte) { binary.LittleEndian.PutUint32(b[pkg.start+284:], 255) }},
		{"entry-offset-overflow", func(b []byte) { binary.LittleEndian.PutUint32(b[typAt+28:], 0xfffffffc) }},
		{"hidden-bag-string-reference", func(b []byte) {
			start := int(u32(b[typAt+16:]))
			at := typAt + start + 16
			b[at+23] = 3
			binary.LittleEndian.PutUint32(b[at+24:], 99)
		}},
		{"config-size", func(b []byte) { binary.LittleEndian.PutUint32(b[typAt+20:], 0xffffffff) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			b := bytes.Clone(arsc)
			test.mutate(b)
			if _, err := inspectAndroidResources(b, PageOptions{Limit: 1}, nil); err == nil {
				t.Fatal("hidden malformed resource data accepted")
			}
		})
	}
}

func TestAndroidTypeSpecConfigurationCount(t *testing.T) {
	b := testfixture.AndroidResources(0, false)
	global, _ := androidChunkAt(b, 12)
	pkg, _ := androidChunkAt(b, 12+global.size)
	specAt := 0
	for at := pkg.header; at < pkg.size; {
		c, err := androidChunkAt(pkg.body, at)
		if err != nil {
			t.Fatal(err)
		}
		if c.kind == 0x202 {
			specAt = pkg.start + at
			break
		}
		at += c.size
	}
	if specAt == 0 {
		t.Fatal("fixture has no type spec")
	}
	for _, count := range []uint16{0, 1, 2} {
		binary.LittleEndian.PutUint16(b[specAt+10:], count)
		r, err := inspectAndroidResources(b, PageOptions{Limit: 1}, nil)
		if count < 2 && (err != nil || r.TotalResourceConfigurations != 2) {
			t.Fatalf("valid typesCount=%d: %v", count, err)
		}
		if count == 2 && err == nil {
			t.Fatal("mismatched typesCount accepted behind first page")
		}
	}
}

func FuzzAndroidBinaryMetadataDoesNotPanic(f *testing.F) {
	f.Add(testfixture.AndroidManifest())
	f.Add(testfixture.AndroidResources(2, true))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 2<<20 {
			return
		}
		_, _ = inspectAndroidManifest(b, PageOptions{Limit: 1})
		_, _ = inspectAndroidResources(b, PageOptions{Limit: 1}, nil)
	})
}
