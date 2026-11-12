//go:build !windows

package modules

func moduleEvidenceForAddress(uint32, uint64) (X32WriteWatchModule, error) {
	return X32WriteWatchModule{}, nil
}
