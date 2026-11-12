package appinspect

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func packageVector(t *testing.T, name string, members map[string][]byte) string {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	names := []string{}
	for name := range members {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(members[name]); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, buf.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}
func TestHarmonyPackageIsInertVerifiedZIPProjection(t *testing.T) {
	p := packageVector(t, "entry.hap", map[string][]byte{"module.json": []byte(`{"module":{"name":"entry"}}`), "ets/modules.abc": []byte("not-decoded-Ark"), "libs/arm64-v8a/libapp.so": []byte("native-candidate"), "assets/entry/resources/rawfile/config.txt": []byte("configuration"), "META-INF/signature": []byte("not-verified")})
	r, err := InspectPackage(p, PackageOptions{Family: "harmony"})
	if err != nil {
		t.Fatal(err)
	}
	if r.PackageKind != "harmony-hap" || r.PackagingModelHint != "stage-path" || r.TotalComponents != 5 || r.ExecutionPerformed || !r.CoverageComplete {
		t.Fatalf("HAP %+v", r)
	}
	roles := map[string]int{}
	for _, c := range r.Components {
		roles[c.Role]++
		if !c.ContentVerified || len(c.ContentSHA256) != 64 || c.RoleBasis != "path-convention" {
			t.Fatalf("component %+v", c)
		}
	}
	if roles["ark-bytecode"] != 1 || roles["native-library"] != 1 || roles["manifest"] != 1 || roles["signing-metadata"] != 1 {
		t.Fatal(roles)
	}
	if _, err := InspectPackage(p, PackageOptions{Family: "harmony", PageOptions: PageOptions{ExpectedSHA256: strings.Repeat("0", 64)}}); err == nil {
		t.Fatal("stale admitted")
	}
	app := packageVector(t, "distribution.app", map[string][]byte{"entry.hap": []byte("child-not-opened"), "other.hsp": []byte("child-not-opened"), "pack.info": []byte("opaque")})
	r, err = InspectPackage(app, PackageOptions{Family: "harmony"})
	if err != nil || r.PackageKind != "harmony-app-pack" || r.PackagingModelHint != "unknown" || r.Components[0].Role != "child-package" {
		t.Fatalf("AppPack %+v %v", r, err)
	}
	ambiguous := packageVector(t, "archive.har", map[string][]byte{"config.json": {}})
	if _, err := InspectPackage(ambiguous, PackageOptions{Family: "harmony"}); err == nil {
		t.Fatal("ambiguous HAR suffix admitted")
	}
}
func TestApplePackageKeepsBundleScopesAndFrameworkHintsExact(t *testing.T) {
	p := packageVector(t, "apps.ipa", map[string][]byte{
		"Payload/Main.app/Info.plist": []byte("opaque-plist"), "Payload/Main.app/main.js": []byte("js"), "Payload/Main.app/Frameworks/React.framework/React": []byte("native"), "Payload/Main.app/Frameworks/Preact.framework/Preact": []byte("native"), "Payload/Main.app/Frameworks/App.framework/App": []byte("native"), "Payload/Other.app/Info.plist": []byte("other"), "Payload/Other.app/main.js": []byte("otherjs"), "extras/loose.js": []byte("unrooted"), "Empty.app/": {},
	})
	r, err := InspectPackage(p, PackageOptions{Family: "apple"})
	if err != nil {
		t.Fatal(err)
	}
	if r.PackageKind != "ipa" || r.TotalBundles != 6 {
		t.Fatalf("Apple %+v", r)
	}
	for _, c := range r.Components {
		if c.Entry.Path == "extras/loose.js" && c.BundlePath != "" {
			t.Fatal("unrooted component attributed to app")
		}
		if strings.HasPrefix(c.Entry.Path, "Payload/Other.app/") && c.BundlePath != "Payload/Other.app" {
			t.Fatal("cross bundle association")
		}
		if strings.Contains(c.Entry.Path, "Preact.framework") || strings.Contains(c.Entry.Path, "App.framework") {
			if c.RuntimeHint != "" {
				t.Fatal("substring/generic App framework false family")
			}
		}
	}
	b, err := InspectPackage(p, PackageOptions{Family: "apple", View: "bundles"})
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range b.Bundles {
		if x.Path == "Payload/Main.app" && (x.InfoPlist == nil || *x.InfoPlist != "Payload/Main.app/Info.plist") {
			t.Fatal("shallow info candidate")
		}
		if strings.HasSuffix(x.Path, "React.framework") && (len(x.RuntimeHints) != 1 || x.RuntimeHints[0] != "react-native") {
			t.Fatal("exact framework hint lost")
		}
		if x.Path == "Empty.app" && x.InfoPlist != nil {
			t.Fatal("empty bundle info invented")
		}
	}
}
func TestAppleVersionedFrameworkAndDeepExecutableCandidates(t *testing.T) {
	p := packageVector(t, "Mac.zip", map[string][]byte{"Mac.app/Contents/Info.plist": []byte("info"), "Mac.app/Contents/MacOS/Main": []byte("program"), "Mac.app/Contents/Frameworks/Foo.framework/Versions/A/Resources/Info.plist": []byte("a"), "Mac.app/Contents/Frameworks/Foo.framework/Versions/B/Resources/Info.plist": []byte("b")})
	r, err := InspectPackage(p, PackageOptions{Family: "apple", View: "bundles"})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Bundles) != 2 {
		t.Fatal(r)
	}
	for _, b := range r.Bundles {
		if b.Role == "application" && (b.Layout != "macos-deep" || b.TotalExecutableCandidates != 1 || b.InfoPlist == nil) {
			t.Fatal(b)
		}
		if b.Role == "framework" && (b.Layout != "versioned-framework" || b.InfoPlist != nil || b.InfoStatus != "ambiguous-version-selection") {
			t.Fatal(b)
		}
	}
}
func TestPackageHiddenPathsAndSelectedCRCFailClosed(t *testing.T) {
	p := packageVector(t, "bad.hap", map[string][]byte{"module.json": {}, "z/../../outside": {}})
	if _, err := InspectPackage(p, PackageOptions{Family: "harmony", PageOptions: PageOptions{Limit: 1}}); err == nil {
		t.Fatal("hidden unsafe path admitted")
	}
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, _ := w.CreateHeader(&zip.FileHeader{Name: "module.json", Method: zip.Store})
	f.Write([]byte("valid"))
	w.Close()
	b := buf.Bytes()
	bodyIndex := bytes.Index(b, []byte("valid"))
	b[bodyIndex] ^= 1
	p = input(t, "bad-crc.hap", b)
	if _, err := InspectPackage(p, PackageOptions{Family: "harmony"}); err == nil {
		t.Fatal("selected CRC corruption admitted")
	}
}
