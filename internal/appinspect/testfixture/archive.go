package testfixture

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"slices"
)

func TAR() []byte {
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	_ = w.WriteHeader(&tar.Header{Name: "app/main.txt", Mode: 0600, Size: 3})
	_, _ = w.Write([]byte("abc"))
	_ = w.Close()
	return b.Bytes()
}

func HarmonyZIP() []byte {
	return ZIPFiles(map[string][]byte{"module.json": []byte("inert fixture bytes"), "ets/modules.abc": []byte("inert fixture bytes"), "libs/arm64-v8a/libapp.so": []byte("inert fixture bytes")})
}

func ZIPFiles(entries map[string][]byte) []byte {
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		f, _ := w.Create(name)
		_, _ = f.Write(entries[name])
	}
	_ = w.Close()
	return b.Bytes()
}

func AndroidZIP() []byte {
	return ZIPFiles(map[string][]byte{"AndroidManifest.xml": AndroidManifest(), "resources.arsc": AndroidResources(0, false), "classes.dex": DEX()})
}
