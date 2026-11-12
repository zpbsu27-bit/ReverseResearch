// Package appinspect owns bounded static application-format inspection. It
// never evaluates, loads, extracts or starts an inspected target.
package appinspect

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reverseresearch/internal/recordio"
	"reverseresearch/internal/targetidentity"
)

const MaxArtifactBytes = 128 << 20

func projectionLimit(value any) error {
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(body) > 48<<10 {
		return errors.New("projection exceeds 48 KiB output limit; request a smaller page")
	}
	return nil
}

func digest(body []byte) string { v := sha256.Sum256(body); return hex.EncodeToString(v[:]) }
func readArtifact(path string, maxBytes int64, expected string) ([]byte, string, string, error) {
	body, abs, hash, err := targetidentity.CaptureFile(path, maxBytes)
	if err != nil {
		return nil, "", "", err
	}
	if err = recordio.CheckExpectedSHA256(hash, expected); err != nil {
		return nil, "", "", err
	}
	return body, abs, hash, nil
}

type PageOptions struct {
	Offset         int    `json:"offset"`
	Limit          int    `json:"limit"`
	ExpectedSHA256 string `json:"expected_sha256,omitempty"`
}

func page(o PageOptions, total int) (int, int, error) {
	if o.Limit == 0 {
		o.Limit = 50
	}
	if o.Offset < 0 || o.Offset > total || o.Limit < 1 || o.Limit > 200 {
		return 0, 0, errors.New("offset must be within inventory; limit must be 1..200")
	}
	return o.Offset, min(total, o.Offset+o.Limit), nil
}
