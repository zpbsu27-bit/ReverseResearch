package targetidentity

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// CaptureFile owns byte-snapshot currentness for static artifact readers. It
// does not parse a container, persist identity or evaluate target content.
func CaptureFile(path string, limit int64) ([]byte, string, string, error) {
	if limit < 1 || limit > 1<<30 {
		return nil, "", "", errors.New("artifact read limit must be 1..1 GiB")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, "", "", err
	}
	admitted, err := os.Lstat(abs)
	if err != nil {
		return nil, "", "", err
	}
	if !admitted.Mode().IsRegular() {
		return nil, "", "", errors.New("artifact must be a regular file without a final symlink")
	}
	file, err := os.Open(abs)
	if err != nil {
		return nil, "", "", err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		return nil, "", "", err
	}
	if !before.Mode().IsRegular() {
		return nil, "", "", errors.New("artifact must be a regular file")
	}
	if !os.SameFile(admitted, before) || admitted.Size() != before.Size() || !admitted.ModTime().Equal(before.ModTime()) {
		return nil, "", "", errors.New("artifact changed before capture")
	}
	if before.Size() > limit {
		return nil, "", "", fmt.Errorf("artifact exceeds %d byte limit", limit)
	}
	body, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, "", "", err
	}
	if int64(len(body)) > limit {
		return nil, "", "", errors.New("artifact grew beyond byte limit")
	}
	if err = validateCurrentFile(abs, file, before); err != nil {
		return nil, "", "", err
	}
	// Re-read the same handle without allocating a second body.
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return nil, "", "", err
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(file, limit+1))
	if err != nil {
		return nil, "", "", err
	}
	sum := sha256.Sum256(body)
	hash := hex.EncodeToString(sum[:])
	if n != int64(len(body)) || hex.EncodeToString(h.Sum(nil)) != hash {
		return nil, "", "", errors.New("artifact content changed during capture")
	}
	if err = validateCurrentFile(abs, file, before); err != nil {
		return nil, "", "", err
	}
	current, err := os.Lstat(abs)
	if err != nil {
		return nil, "", "", err
	}
	if !current.Mode().IsRegular() || !os.SameFile(admitted, current) || admitted.Size() != current.Size() || !admitted.ModTime().Equal(current.ModTime()) {
		return nil, "", "", errors.New("artifact changed during capture")
	}
	return body, filepath.Clean(abs), hash, nil
}
