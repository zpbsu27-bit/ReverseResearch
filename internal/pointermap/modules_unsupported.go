//go:build !windows

package pointermap

func snapshotModules(uint32) ([]Module, error) {
	return nil, ErrUnsupported
}
