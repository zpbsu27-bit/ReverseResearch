package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"reverseresearch/internal/appinspect"
	"reverseresearch/internal/appinspect/testfixture"
)

func TestDEXCLIReportsReferenceScopeAndRespectsExplicitByteLimit(t *testing.T) {
	root, _ := isolatedCLIRoot(t)
	p := filepath.Join(t.TempDir(), "classes.dex")
	if err := os.WriteFile(p, testfixture.DEX(), 0600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		args []string
		raw  bool
	}{
		{[]string{"app", "dex", p, "--view", "methods"}, false},
		{[]string{"app", "dex", p, "--view", "string-bytes", "--string-index", "10", "--limit", "1"}, true},
	} {
		var out, errout bytes.Buffer
		if err := runMain(context.Background(), root, test.args, &out, &errout); err != nil {
			t.Fatal(err)
		}
		var r appinspect.DEXReport
		if err := json.Unmarshal(out.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		if test.raw {
			if r.ReadBytes != 1 || r.DataBase64 != "AQ==" {
				t.Fatalf("explicit byte limit lost: %+v", r)
			}
		} else if r.DefinedMethods != 3 || r.TotalMethods != 4 || r.Methods[3].Defined || r.ExecutionPerformed {
			t.Fatalf("reference/definition scope drift: %+v", r)
		}
	}
	for _, args := range [][]string{{"app", "dex", p, "--view", "methods", "--string-index", "0"}, {"app", "dex", p, "--view", "string-bytes"}, {"app", "dex", p, "--view", "classes", "--offset", "1"}} {
		var out, errout bytes.Buffer
		if err := runMain(context.Background(), root, args, &out, &errout); err == nil || out.Len() != 0 {
			t.Fatalf("CLI failure contract lost: %v %v %s", args, err, out.String())
		}
	}
	for _, view := range []string{"instructions", "cfg", "edges"} {
		var out, errout bytes.Buffer
		if err := runMain(context.Background(), root, []string{"app", "dex", p, "--view", view, "--method-index", "2"}, &out, &errout); err != nil {
			t.Fatal(err)
		}
		var code appinspect.DEXReport
		if err := json.Unmarshal(out.Bytes(), &code); err != nil {
			t.Fatal(err)
		}
		if !code.CodeAvailable || code.Method == nil || code.Method.Index != 2 || code.Method.Descriptor != "()I" || code.TotalInstructions != 2 || code.ExecutionPerformed {
			t.Fatalf("CLI code identity lost: %+v", code)
		}
	}
}
