package casebook

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

var errSourceChanged = errors.New("evidence source changed while hashing")

// The hash and size come from the same open regular file. Check its identity,
// size and modification time again before accepting the binding. This detects
// normal concurrent edits/replacements, not hostile timestamp restoration.
func fingerprintSource(path string) (digest string, size int64, err error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, fmt.Errorf("open evidence source: %w", err)
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	before, err := file.Stat()
	if err != nil {
		return "", 0, err
	}
	if !before.Mode().IsRegular() {
		return "", 0, errors.New("evidence source must be a regular file")
	}
	hash := sha256.New()
	count, err := io.Copy(hash, file)
	if err != nil {
		return "", 0, fmt.Errorf("hash evidence source: %w", err)
	}
	after, err := file.Stat()
	if err != nil {
		return "", 0, err
	}
	current, err := os.Stat(path)
	if err != nil {
		return "", 0, fmt.Errorf("%w: %v", errSourceChanged, err)
	}
	if !os.SameFile(before, after) || !os.SameFile(after, current) ||
		before.Size() != count || after.Size() != count || current.Size() != count ||
		!before.ModTime().Equal(after.ModTime()) || !after.ModTime().Equal(current.ModTime()) {
		return "", 0, errSourceChanged
	}
	return hex.EncodeToString(hash.Sum(nil)), count, nil
}
