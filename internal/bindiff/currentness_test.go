package bindiff

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// The test binary doubles as a deterministic radiff2 stand-in. It modifies only
// a test-owned temporary target and never starts a debugger or analysis session.
func TestMain(m *testing.M) {
	if mode := os.Getenv("RR_DIFF_BOUNDED_HELPER"); mode != "" {
		switch mode {
		case "stdout":
			fmt.Print(strings.Repeat("x", (8<<20)+1))
		case "stderr":
			fmt.Fprint(os.Stderr, strings.Repeat("x", (64<<10)+1))
		case "wait":
			time.Sleep(10 * time.Second)
		}
		os.Exit(0)
	}
	if target := os.Getenv("RR_DIFF_CURRENTNESS_HELPER"); target != "" {
		if err := os.WriteFile(target, []byte("new!"), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if slices.Contains(os.Args, "-AA") {
			fmt.Print(`[]`)
		} else {
			fmt.Print(`{"files":[],"changes":[]}`)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestDiffRejectsTargetDriftDuringAnalysis(t *testing.T) {
	for _, mode := range []string{"quick", "functions"} {
		t.Run(mode, func(t *testing.T) {
			target := filepath.Join(t.TempDir(), "sample.bin")
			if err := os.WriteFile(target, []byte("old!"), 0o600); err != nil {
				t.Fatal(err)
			}
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			a, err := New(exe)
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv("RR_DIFF_CURRENTNESS_HELPER", target)
			if mode == "quick" {
				_, err = a.Quick(context.Background(), target, target)
			} else {
				_, err = a.Functions(context.Background(), target, target, 70)
			}
			if err == nil {
				t.Fatal("analysis result accepted after the target changed")
			}
		})
	}
}
