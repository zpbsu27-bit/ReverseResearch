package appinspect

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tarVector(t *testing.T, names ...string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	for _, name := range names {
		if err := w.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: 3}); err != nil {
			t.Fatal(err)
		}
		w.Write([]byte("abc"))
	}
	w.WriteHeader(&tar.Header{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "../../outside"})
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
func tarInput(t *testing.T, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "sample.tar")
	if err := os.WriteFile(p, b, 0600); err != nil {
		t.Fatal(err)
	}
	return p
}
func TestTARAndGzipReadOnlyPages(t *testing.T) {
	b := tarVector(t, "app/a.txt", "app/b.txt")
	var compressed bytes.Buffer
	g := gzip.NewWriter(&compressed)
	g.Write(b)
	g.Close()
	for _, body := range [][]byte{b, compressed.Bytes()} {
		p := tarInput(t, body)
		r, err := InspectTAR(p, PageOptions{Limit: 1})
		if err != nil {
			t.Fatal(err)
		}
		if r.TotalEntries != 3 || r.NextOffset == nil || r.ExecutionPerformed || r.DecodedSHA256 != digest(b) {
			t.Fatalf("TAR %+v", r)
		}
		v, err := ReadTAR(p, EntryReadOptions{Entry: "app/a.txt", Offset: 1, Limit: 1, ExpectedSHA256: r.SHA256})
		if err != nil || v.DataBase64 != base64.StdEncoding.EncodeToString([]byte("b")) || v.ContentSHA256 != digest([]byte("abc")) || v.NextOffset == nil {
			t.Fatalf("read %+v %v", v, err)
		}
		link, err := ReadTAR(p, EntryReadOptions{Entry: "link"})
		if err != nil || link.Entry.Available || link.Entry.LinkName != "../../outside" {
			t.Fatalf("link %+v %v", link, err)
		}
		if _, err := InspectTAR(p, PageOptions{ExpectedSHA256: strings.Repeat("0", 64)}); err == nil {
			t.Fatal("stale TAR accepted")
		}
	}
}
func TestTARChecksHiddenMembersAndCarrier(t *testing.T) {
	for name, body := range map[string][]byte{"hidden-path": tarVector(t, "safe", "../unsafe"), "duplicate": tarVector(t, "same", "same"), "missing-end": tarVector(t, "safe")[:1536], "partial-record": append(tarVector(t, "safe"), 1), "trailing-data": append(tarVector(t, "safe"), make([]byte, 512)...)} {
		if name == "trailing-data" {
			body[len(body)-1] = 1
		}
		t.Run(name, func(t *testing.T) {
			if _, err := InspectTAR(tarInput(t, body), PageOptions{Limit: 1}); err == nil {
				t.Fatal("malformed TAR accepted")
			}
		})
	}
	var compressed bytes.Buffer
	g := gzip.NewWriter(&compressed)
	g.Write(tarVector(t, "safe"))
	g.Close()
	b := append([]byte{}, compressed.Bytes()...)
	b[len(b)-8] ^= 1
	if _, err := InspectTAR(tarInput(t, b), PageOptions{}); err == nil {
		t.Fatal("gzip CRC corruption accepted")
	}
}

func TestTARGzipDecodedBudgetIsEnforced(t *testing.T) {
	var compressed bytes.Buffer
	z, err := gzip.NewWriterLevel(&compressed, gzip.BestSpeed)
	if err != nil {
		t.Fatal(err)
	}
	block := make([]byte, 32768)
	for written := 0; written < MaxArtifactBytes+len(block); written += len(block) {
		if _, err := z.Write(block); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectTAR(tarInput(t, compressed.Bytes()), PageOptions{}); err == nil || !strings.Contains(err.Error(), "decoded limit") {
		t.Fatalf("gzip bomb error %v", err)
	}
}
