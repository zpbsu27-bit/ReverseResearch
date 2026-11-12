package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"reverseresearch/internal/appinspect"
	"reverseresearch/internal/appinspect/testfixture"
)

func TestAndroidPackageCLIUsesCanonicalReportsAndExplicitSelectors(t *testing.T) {
	root, _ := isolatedCLIRoot(t)
	p := filepath.Join(t.TempDir(), "offline.apk")
	if err := os.WriteFile(p, testfixture.AndroidZIP(), 0600); err != nil {
		t.Fatal(err)
	}
	for _, view := range []string{"manifest", "resources", "resource-values"} {
		args := []string{"app", "package", p, "--family", "android", "--view", view, "--limit", "1"}
		opts := appinspect.PackageOptions{Family: "android", View: view, PageOptions: appinspect.PageOptions{Limit: 1}}
		if view == "resource-values" {
			i := 1
			opts.ResourceIndex = &i
			args = append(args, "--resource-index", "1")
		}
		var out, errout bytes.Buffer
		if err := runMain(context.Background(), root, args, &out, &errout); err != nil {
			t.Fatal(err)
		}
		var actual appinspect.PackageReport
		if err := json.Unmarshal(out.Bytes(), &actual); err != nil {
			t.Fatal(err)
		}
		want, err := appinspect.InspectPackage(p, opts)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(actual, want) || actual.ExecutionPerformed {
			t.Fatalf("CLI package projection differs for %s", view)
		}
	}
	for _, flags := range [][]string{
		{"--view", "resources", "--resource-index", "0"},
		{"--view", "resource-values"},
		{"--view", "resource-values", "--resource-index", "99"},
		{"--view", "manifest", "--offset", "1"},
		{"--unknown", "true"},
	} {
		args := append([]string{"app", "package", p, "--family", "android"}, flags...)
		var out, errout bytes.Buffer
		if err := runMain(context.Background(), root, args, &out, &errout); err == nil || out.Len() != 0 {
			t.Fatalf("CLI failure contract lost: %v %v", args, err)
		}
	}
}
