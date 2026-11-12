//go:build !windows

package securefile

import "os"

func RestrictFile(path string) error {
	return os.Chmod(path, 0o600)
}

func RestrictDir(path string) error {
	return os.Chmod(path, 0o700)
}
