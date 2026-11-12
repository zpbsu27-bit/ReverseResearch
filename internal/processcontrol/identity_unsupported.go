//go:build !windows

package processcontrol

func Inspect(pid uint32) (Identity, error) {
	return Identity{}, ErrUnsupported
}
