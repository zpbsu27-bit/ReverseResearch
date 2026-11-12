package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestValidateLoopbackListen(t *testing.T) {
	for _, value := range []string{"127.0.0.1:19100", "[::1]:19100", "localhost:19100"} {
		if err := validateLoopbackListen(value); err != nil {
			t.Fatalf("%s: %v", value, err)
		}
	}
	for _, value := range []string{":19100", "0.0.0.0:19100", "[::]:19100", "192.168.1.20:19100", "example.com:19100"} {
		if err := validateLoopbackListen(value); err == nil {
			t.Fatalf("%s unexpectedly accepted", value)
		}
	}
}

func TestMainEntryWithoutArgsPrintsHelpInsteadOfServing(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := runMain(context.Background(), t.TempDir(), nil, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "Usage:") {
		t.Fatalf("stdout=%q", stdout.String())
	}
	for _, forbidden := range []string{"Starting Secure MCP Tunnel", "Local endpoint ready"} {
		if strings.Contains(stdout.String(), forbidden) || strings.Contains(stderr.String(), forbidden) {
			t.Fatalf("no-argument main entry started a service: stdout=%q stderr=%q", stdout.String(), stderr.String())
		}
	}
}
