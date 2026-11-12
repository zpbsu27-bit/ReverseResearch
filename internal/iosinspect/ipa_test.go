package iosinspect

import (
	"archive/zip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestInspectIPA(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.ipa")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	z := zip.NewWriter(f)
	w, _ := z.Create("Payload/Demo.app/Info.plist")
	w.Write([]byte("plist"))
	w, _ = z.Create("Payload/Demo.app/Demo")
	w.Write([]byte{0xcf, 0xfa, 0xed, 0xfe, 1, 2, 3})
	z.Close()
	f.Close()
	r, err := InspectIPA(p)
	if err != nil {
		t.Fatal(err)
	}
	if !r.ReadOnly || len(r.AppRoots) != 1 || len(r.MachO) != 1 {
		t.Fatalf("report=%+v", r)
	}
}

func TestInspectIPAContextHonorsCancellation(t *testing.T) {
	p := filepath.Join(t.TempDir(), "cancel.ipa")
	if err := os.WriteFile(p, []byte("not-used"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := InspectIPAContext(ctx, p); !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v want context.Canceled", err)
	}
}
