package domainpack

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProjectDomainPacksLoadAndBindSpecialists(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	registry, err := Load(root, filepath.Join(root, "config", "domain-packs.json"))
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]string{
		"malware-analysis":    "malware",
		"blue-detection":      "blue-detection",
		"purple-validation":   "purple-validation",
		"linux-native":        "linux-native",
		"vuln-research":       "vuln-research",
		"nday-research":       "vuln-research",
		"dfir-forensics":      "dfir",
		"traffic-protocol":    "protocol",
		"source-code-audit":   "code-audit",
		"supply-chain":        "code-audit",
		"network-assessment":  "redteam",
		"pentest-network":     "redteam",
		"adversary-emulation": "adversary-emulation",
		"identity-ad":         "identity-ad",
		"cloud-security":      "cloud",
		"container-k8s":       "container-k8s",
		"ios":                 "ios",
		"firmware-iot":        "firmware",
		"cti-analysis":        "cti-hunting",
		"threat-hunting":      "cti-hunting",
	}
	for routeID, packID := range tests {
		pack, ok := registry.ForRoute(routeID)
		if !ok || pack.ID != packID {
			t.Fatalf("route %s pack=%+v ok=%v want=%s", routeID, pack, ok, packID)
		}
		if pack.Skill.Role != "specialist" || pack.Skill.OwnsRouting {
			t.Fatalf("invalid specialist contract: %+v", pack.Skill)
		}
	}
}

func TestDomainPackRejectsRoutingOwnerSkill(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	body, err := os.ReadFile(filepath.Join(root, "config", "domain-packs.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg Config
	if err := json.Unmarshal(body, &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Packs) == 0 {
		t.Fatal("project domain-pack config is empty")
	}
	cfg.Packs[0].Skill.OwnsRouting = true
	broken, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "domain-packs.json")
	if err := os.WriteFile(path, broken, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(root, path); err == nil || !strings.Contains(err.Error(), "owns_routing=false") {
		t.Fatalf("err=%v", err)
	}
}

func TestValidateSkillAcceptsCRLFFrontmatter(t *testing.T) {
	root := t.TempDir()
	relative := filepath.ToSlash(filepath.Join("skills", "fixture", "SKILL.md"))
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	body := "---\r\nname: fixture\r\ndescription: CRLF checkout fixture\r\n---\r\n\r\n# Fixture\r\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateSkill(root, relative); err != nil {
		t.Fatalf("CRLF skill frontmatter rejected: %v", err)
	}
}
