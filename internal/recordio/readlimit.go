package recordio

import (
	"fmt"
	"io"
	"os"
)

// ReadFileLimit reads a local durable record without allowing a corrupt or
// legacy oversized file to allocate an unbounded byte slice before decode.
func ReadFileLimit(path string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("read limit must be positive")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > maxBytes {
		return nil, fmt.Errorf("record %s exceeds size limit: %d > %d", path, info.Size(), maxBytes)
	}
	body, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("record %s grew beyond size limit while reading: %d > %d", path, len(body), maxBytes)
	}
	return body, nil
}
