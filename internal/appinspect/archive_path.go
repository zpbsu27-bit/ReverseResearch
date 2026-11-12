package appinspect

import (
	"errors"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"
)

func safeArchivePath(raw string) (string, error) {
	name := strings.TrimSuffix(raw, "/")
	if name == "" || len(name) > 4096 || !utf8.ValidString(name) || path.IsAbs(name) || path.Clean(name) != name || name == ".." || strings.HasPrefix(name, "../") || strings.ContainsAny(name, "\\:") || strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return "", errors.New("archive entry path is unsafe")
	}
	return name, nil
}
