package main

import (
	"bytes"
	"context"
	"testing"
)

func TestAndroidRecoveryCLISelectorAndCallerCancellation(t *testing.T) {
	root, _ := isolatedCLIRoot(t)
	for _, args := range [][]string{
		{"app", "android-recover", "not-opened", "--view", "method", "--class-name", "demo.C"},
		{"app", "android-recover", "not-opened", "--view", "classes", "--overload-index", "0"},
		{"app", "android-recover", "not-opened", "--offset", "1"},
		{"app", "android-recover", "not-opened", "--limit", "16385"},
	} {
		var out, errout bytes.Buffer
		if err := runMain(context.Background(), root, args, &out, &errout); err == nil || out.Len() != 0 {
			t.Fatalf("rejected recovery emitted success: %v %v", args, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, errout bytes.Buffer
	if err := runMain(ctx, root, []string{"app", "android-recover", "not-opened"}, &out, &errout); err == nil || out.Len() != 0 {
		t.Fatalf("CLI lost caller cancellation: %v", err)
	}
}
