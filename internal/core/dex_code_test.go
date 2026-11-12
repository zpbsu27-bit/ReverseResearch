package core

import (
	"os"
	"path/filepath"
	"testing"

	"reverseresearch/internal/appinspect"
	"reverseresearch/internal/appinspect/testfixture"
)

func TestDEXCoreUsesCanonicalInstructionSnapshot(t *testing.T) {
	root, _ := isolatedCoreRoot(t)
	service, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "classes.dex")
	if err := os.WriteFile(p, testfixture.DEX(), 0600); err != nil {
		t.Fatal(err)
	}
	i := 2
	r, err := service.InspectDEX(p, appinspect.DEXOptions{View: "instructions", MethodIndex: &i})
	if err != nil || !r.CodeAvailable || r.Method.Descriptor != "()I" || r.Instructions[0].Mnemonic != "const/4" || *r.Instructions[0].Literal != 7 || r.ExecutionPerformed {
		t.Fatalf("Core projection differs: %+v %v", r, err)
	}
}
