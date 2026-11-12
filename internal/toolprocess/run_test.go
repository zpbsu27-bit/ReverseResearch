package toolprocess

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestStaticToolProcessHelper(t *testing.T) {
	if len(os.Args) == 0 {
		return
	}
	switch os.Args[len(os.Args)-1] {
	case "rr-static-overflow":
		fmt.Fprint(os.Stdout, strings.Repeat("a", 256<<10))
		fmt.Fprint(os.Stderr, strings.Repeat("b", 256<<10))
		os.Exit(0)
	case "rr-static-wait":
		time.Sleep(time.Minute)
		os.Exit(0)
	}
}

func TestRunnerBoundsAndCancelsOwnedChild(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	result := Run(context.Background(), exe, []string{"-test.run=^TestStaticToolProcessHelper$", "--", "rr-static-overflow"}, 17, 11, "")
	if result.Err != nil || result.ExitCode != 0 || !result.Truncated || string(result.Stdout) != strings.Repeat("a", 17) || string(result.Stderr) != strings.Repeat("b", 11) {
		t.Fatalf("unexpected bounded output: %+v", result)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	result = Run(ctx, exe, []string{"-test.run=^TestStaticToolProcessHelper$", "--", "rr-static-wait"}, 17, 11, "")
	if result.Err == nil || ctx.Err() == nil || time.Since(start) > 3*time.Second {
		t.Fatalf("child cancellation failed: %+v", result)
	}
}
