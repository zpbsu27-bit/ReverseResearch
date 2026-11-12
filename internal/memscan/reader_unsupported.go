//go:build !windows

package memscan

func openProcessMemory(uint32) (processMemory, error) {
	return nil, ErrUnsupported
}
