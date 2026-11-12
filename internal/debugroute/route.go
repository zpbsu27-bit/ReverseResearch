package debugroute

import (
	"errors"
	"fmt"
	"strings"

	"reverseresearch/internal/targetidentity"
)

var ErrUnsupported = errors.New("debugger target architecture is unsupported")

type Route struct {
	Architecture string `json:"architecture"`
	Bits         int    `json:"bits"`
	Backend      string `json:"backend"`
	PublicModule string `json:"public_module"`
}

func ForImage(image targetidentity.Identity) (Route, error) {
	if image.PE == nil {
		return Route{}, fmt.Errorf("%w: target is not a PE image", ErrUnsupported)
	}
	machine := strings.ToLower(strings.TrimSpace(image.PE.Machine))
	switch {
	case image.PE.Bits == 32 && machine == "i386":
		return Route{
			Architecture: "x86",
			Bits:         32,
			Backend:      "x32dbg",
			PublicModule: "x32dbg",
		}, nil
	case image.PE.Bits == 64 && machine == "amd64":
		return Route{
			Architecture: "x86-64",
			Bits:         64,
			Backend:      "x64dbg",
			PublicModule: "x32dbg",
		}, nil
	default:
		return Route{}, fmt.Errorf(
			"%w: PE machine=%s bits=%d; supported routes are i386/32 -> x32dbg and amd64/64 -> x64dbg",
			ErrUnsupported, image.PE.Machine, image.PE.Bits,
		)
	}
}
