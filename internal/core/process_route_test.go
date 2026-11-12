package core

import (
	"errors"
	"testing"

	"reverseresearch/internal/debugroute"
	"reverseresearch/internal/processcontrol"
	"reverseresearch/internal/targetidentity"
)

func TestDebugRouteForIdentityReturnsReadOnlyPreview(t *testing.T) {
	identity := processcontrol.Identity{
		PID: 4242,
		Key: "process-key",
		Image: targetidentity.Identity{
			Path:   `C:\test\target.exe`,
			Format: "pe",
			PE:     &targetidentity.PEIdentity{Machine: "amd64", Bits: 64},
		},
	}
	got, err := debugRouteForIdentity(identity)
	if err != nil {
		t.Fatal(err)
	}
	if got.PID != identity.PID || got.ProcessKey != identity.Key || got.Executable != identity.Image.Path {
		t.Fatalf("identity fields=%+v", got)
	}
	if got.Format != "pe" || got.Machine != "amd64" || got.Bits != 64 ||
		got.Architecture != "x86-64" || got.Backend != "x64dbg" || got.PublicModule != "x32dbg" {
		t.Fatalf("route=%+v", got)
	}
	if got.AttachPerformed {
		t.Fatal("route preview must not report an attach")
	}
}

func TestDebugRouteForIdentityRejectsUnsupportedImage(t *testing.T) {
	_, err := debugRouteForIdentity(processcontrol.Identity{
		PID:   4242,
		Key:   "process-key",
		Image: targetidentity.Identity{Format: "binary"},
	})
	if !errors.Is(err, debugroute.ErrUnsupported) {
		t.Fatalf("err=%v want unsupported route", err)
	}
}
