package modules

import (
	"reverseresearch/internal/debugroute"
	"reverseresearch/internal/processcontrol"
)

var ErrXDBGArchitectureUnsupported = debugroute.ErrUnsupported

func xdbgBitsFromLease(lease processcontrol.Lease) (int, error) {
	route, err := debugroute.ForImage(lease.Identity.Image)
	if err != nil {
		return 0, err
	}
	return route.Bits, nil
}

func xdbgArchitectureName(bits int) string {
	switch bits {
	case 32:
		return "x86"
	case 64:
		return "x86-64"
	default:
		return ""
	}
}
