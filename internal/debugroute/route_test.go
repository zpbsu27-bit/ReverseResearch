package debugroute

import (
	"errors"
	"testing"

	"reverseresearch/internal/targetidentity"
)

func image(bits int, machine string) targetidentity.Identity {
	return targetidentity.Identity{
		Format: "pe",
		PE:     &targetidentity.PEIdentity{Bits: bits, Machine: machine},
	}
}

func TestForImageRoutesSupportedArchitectures(t *testing.T) {
	x86, err := ForImage(image(32, "i386"))
	if err != nil {
		t.Fatal(err)
	}
	if x86.Architecture != "x86" || x86.Bits != 32 || x86.Backend != "x32dbg" || x86.PublicModule != "x32dbg" {
		t.Fatalf("x86=%+v", x86)
	}
	x64, err := ForImage(image(64, "amd64"))
	if err != nil {
		t.Fatal(err)
	}
	if x64.Architecture != "x86-64" || x64.Bits != 64 || x64.Backend != "x64dbg" || x64.PublicModule != "x32dbg" {
		t.Fatalf("x64=%+v", x64)
	}
}

func TestForImageRejectsUnsupportedOrInconsistentTargets(t *testing.T) {
	for _, candidate := range []targetidentity.Identity{
		{},
		image(64, "arm64"),
		image(32, "amd64"),
		image(64, "i386"),
	} {
		if _, err := ForImage(candidate); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("candidate=%+v err=%v", candidate, err)
		}
	}
}
