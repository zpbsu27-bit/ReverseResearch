package recordio

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// Validate the entire artifact before projecting a page. encoding/json alone
// accepts duplicate keys, which can give different readers different facts.
func DecodeJSON(body []byte, out any) error {
	if !utf8.Valid(body) {
		return errors.New("JSON artifact must be valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := checkJSONValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("JSON artifact contains trailing data")
	}
	return json.Unmarshal(body, out)
}

func checkJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 128 {
		return errors.New("JSON nesting exceeds 128 levels")
	}
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("invalid JSON artifact: %w", err)
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return errors.New("invalid JSON object key")
			}
			name, ok := key.(string)
			if !ok {
				return errors.New("JSON object key must be a string")
			}
			if _, exists := seen[name]; exists {
				// Do not echo a key that could itself contain a credential.
				return errors.New("duplicate JSON object key")
			}
			seen[name] = struct{}{}
			if err := checkJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := checkJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	_, err = decoder.Token()
	return err
}

func CheckExpectedSHA256(actual, expected string) error {
	expected = strings.TrimSpace(expected)
	if expected != "" && !strings.EqualFold(actual, expected) {
		return errors.New("artifact SHA-256 differs from expected_sha256; restart pagination with the current artifact")
	}
	return nil
}
