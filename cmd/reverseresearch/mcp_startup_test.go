package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMCPDefaultEntrypointUsesProjectRootAndOriginalService(t *testing.T) {
	root, _ := isolatedCLIRoot(t)
	program := filepath.Join(root, "dist", "ReverseResearch-MCP.exe")
	resolved := rootFromExecutable(program)
	if resolved != root {
		t.Fatalf("dist root %q want %q", resolved, root)
	}
	args := startupArguments(program, nil)
	// Use an OS-assigned loopback port in an isolated source/config workspace;
	// cancellation exercises the original Runtime and backend shutdown owners.
	args = append(args, "--listen", "127.0.0.1:0")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var out, errout bytes.Buffer
	if err := runMain(ctx, resolved, args, &out, &errout); err != nil {
		t.Fatalf("default entrypoint startup/shutdown %v", err)
	}
	if strings.Contains(out.String(), "Usage:") {
		t.Fatal("MCP default entrypoint fell back to help")
	}
	var help bytes.Buffer
	if err := runMain(context.Background(), root, startupArguments(program, []string{"--help"}), &help, &errout); err != nil || !strings.Contains(help.String(), "ReverseResearch serve") {
		t.Fatalf("explicit help %v %s", err, help.String())
	}
	var generic bytes.Buffer
	if err := runMain(context.Background(), root, startupArguments(filepath.Join(root, "ReverseResearch.exe"), nil), &generic, &errout); err != nil || !strings.Contains(generic.String(), "ReverseResearch serve") {
		t.Fatalf("generic CLI help %v", err)
	}
}
