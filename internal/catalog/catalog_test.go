package catalog

import (
	"strings"
	"testing"
)

func TestVerifiedManifestCountsAndPrefixes(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
		count  int
	}{
		{"x32dbg", "x32dbg_", 80},
		{"ghidra", "ghidra_", 33},
		{"r2", "r2_", 10},
	}
	seen := map[string]bool{}
	for _, tc := range tests {
		tools, err := Load(tc.name, tc.prefix)
		if err != nil {
			t.Fatal(err)
		}
		if len(tools) != tc.count {
			t.Fatalf("%s tool count=%d want=%d", tc.name, len(tools), tc.count)
		}
		for _, tool := range tools {
			if !strings.HasPrefix(tool.Name, tc.prefix) {
				t.Fatalf("%s tool %q lost prefix %q", tc.name, tool.Name, tc.prefix)
			}
			if seen[tool.Name] {
				t.Fatalf("duplicate public tool %q", tool.Name)
			}
			seen[tool.Name] = true
		}
	}
	if len(seen) != 123 {
		t.Fatalf("total proxied tools=%d want=123", len(seen))
	}
}
