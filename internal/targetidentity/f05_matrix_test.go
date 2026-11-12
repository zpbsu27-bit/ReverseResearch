package targetidentity

import (
	"os"
	"runtime"
	"testing"
	"time"
)

func TestInspectCurrentExecutableCovers64BitPE(t *testing.T) {
	if runtime.GOOS != "windows" || runtime.GOARCH != "amd64" {
		t.Skip("64-bit PE runtime check is Windows amd64 specific")
	}
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Inspect(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Format != "pe" || got.PE == nil {
		t.Fatalf("current executable is not reported as PE: %+v", got)
	}
	if got.PE.Bits != 64 || got.PE.Machine != "amd64" {
		t.Fatalf("PE identity=%+v want 64-bit amd64", got.PE)
	}
	if got.PE.ImageBase == 0 || len(got.PE.Sections) == 0 {
		t.Fatalf("incomplete 64-bit PE identity: %+v", got.PE)
	}
}

func TestInspectMalformedAndTruncatedPEStayBinary(t *testing.T) {
	cases := map[string][]byte{
		"truncated-mz":  {'M', 'Z', 0x90},
		"bad-pe-offset": append([]byte{'M', 'Z'}, make([]byte, 62)...),
		"invalid-pe-signature": func() []byte {
			body := make([]byte, 256)
			body[0], body[1] = 'M', 'Z'
			body[0x3c] = 0x80
			copy(body[0x80:], []byte("NOPE"))
			return body
		}(),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			path := t.TempDir() + string(os.PathSeparator) + "sample.exe"
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := Inspect(path)
			if err != nil {
				t.Fatal(err)
			}
			if got.Format != "binary" || got.PE != nil {
				t.Fatalf("malformed input was promoted to PE: %+v", got)
			}
			if got.Size != int64(len(body)) || len(got.SHA256) != 64 {
				t.Fatalf("incomplete binary identity: %+v", got)
			}
		})
	}
}

func TestInspectRejectsFileChangeDuringInspection(t *testing.T) {
	dir := t.TempDir()
	path := dir + string(os.PathSeparator) + "sample.bin"
	if err := os.WriteFile(path, []byte("first-version"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := inspect(path, func() {
		if writeErr := os.WriteFile(path, []byte("other-version"), 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
		future := time.Now().Add(2 * time.Second)
		if timeErr := os.Chtimes(path, future, future); timeErr != nil {
			t.Fatal(timeErr)
		}
	})
	if err == nil {
		t.Fatal("file change during inspection was accepted")
	}
}
