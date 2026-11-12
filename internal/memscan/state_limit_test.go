package memscan

import (
	"bytes"
	"testing"
)

func TestStateLimitWriterStopsBeforeDurableLimit(t *testing.T) {
	var inner bytes.Buffer
	writer := &stateLimitWriter{inner: &inner, limit: 10}
	for _, chunk := range []string{"12345", "67890"} {
		if _, err := writer.Write([]byte(chunk)); err != nil {
			t.Fatalf("chunk within limit failed: %v", err)
		}
	}
	if _, err := writer.Write([]byte("1")); err == nil {
		t.Fatal("a write that would exceed the durable limit must fail before publishing")
	}
	if inner.Len() != 10 {
		t.Fatalf("accepted bytes=%d want 10", inner.Len())
	}
}
