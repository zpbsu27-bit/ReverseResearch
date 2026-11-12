//go:build !windows && !unix

package recordio

import (
	"errors"
	"os"
)

func tryLock(*os.File) (bool, error) {
	return false, errors.New("record locking is unsupported on this platform")
}
func unlock(*os.File) error { return nil }
