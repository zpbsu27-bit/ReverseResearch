package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"reverseresearch/internal/appinspect"
	"reverseresearch/internal/appinspect/testfixture"
)

func TestEVMCLIUsesCanonicalInterfaceAndResultPages(t *testing.T) {
	root, _ := isolatedCLIRoot(t)
	path := filepath.Join(t.TempDir(), "code.raw")
	if err := os.WriteFile(path, testfixture.EVMInterfaceProbe(), 0600); err != nil {
		t.Fatal(err)
	}
	call := func(args []string) appinspect.EVMReport {
		t.Helper()
		var out, errout bytes.Buffer
		if err := runMain(context.Background(), root, args, &out, &errout); err != nil {
			t.Fatalf("%v: %v %s", args, err, errout.String())
		}
		var result appinspect.EVMReport
		if err := json.Unmarshal(out.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.View != "instructions" && bytes.Contains(out.Bytes(), []byte(`"total_instructions"`)) {
			t.Fatal("interface falsely advertised linear decode")
		}
		return result
	}
	r := call([]string{"app", "evm", path, "--encoding", "raw", "--view", "interface"})
	if r.Interface == nil || r.Interface.TotalFunctions != 1 || r.Interface.FunctionPage.Functions[0].Selector != "0xfae7ab82" || r.ExecutionPerformed {
		t.Fatalf("CLI interface lost: %+v", r)
	}
	p := call([]string{"app", "evm", path, "--encoding", "raw", "--view", "interface-bytes", "--limit", "13", "--offset", "1", "--expected-sha256", r.SHA256, "--expected-result-sha256", r.Interface.ResultSHA256})
	data, err := base64.StdEncoding.DecodeString(p.Result.Base64)
	if err != nil || len(data) != 13 || p.Result.Offset != 1 || p.Result.NextOffset == nil || *p.Result.NextOffset != 14 || p.Interface.ResultSHA256 != r.Interface.ResultSHA256 {
		t.Fatalf("CLI byte page lost: %+v %v", p, err)
	}
	for _, args := range [][]string{
		{"app", "evm", path, "--encoding", "raw", "--view", "interface", "--limit", "201"},
		{"app", "evm", path, "--encoding", "raw", "--view", "interface-bytes", "--offset", "1"},
		{"app", "evm", path, "--encoding", "raw", "--view", "interface", "--expected-result-sha256", strings.Repeat("0", 64)},
		{"app", "evm", path, "--encoding", "raw", "--view", "unknown"},
	} {
		var out, errout bytes.Buffer
		if err := runMain(context.Background(), root, args, &out, &errout); err == nil || out.Len() != 0 {
			t.Fatalf("CLI failure published a result: %v %v %s", args, err, out.String())
		}
	}
}
