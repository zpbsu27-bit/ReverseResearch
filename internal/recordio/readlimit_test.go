package recordio

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadFileLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "record.json")
	if err := os.WriteFile(path, []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	body, err := ReadFileLimit(path, 5)
	if err != nil || string(body) != "12345" {
		t.Fatalf("body=%q err=%v", body, err)
	}
	if _, err := ReadFileLimit(path, 4); err == nil {
		t.Fatal("oversized record was accepted")
	}
}
