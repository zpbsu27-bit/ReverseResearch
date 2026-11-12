package playbook

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProjectPlaybooksLoadAndRouteSpecialistDomains(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	registry, err := Load(root, filepath.Join(root, "config", "playbooks.json"))
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]string{
		"native-static":       "windows-native",
		"dynamic-debug":       "windows-native",
		"dotnet":              "windows-native",
		"crypto-obfuscation":  "windows-native",
		"android":             "android",
		"android-static":      "android-static",
		"js-web":              "js-web",
		"web-security":        "js-web",
		"traffic-protocol":    "protocol-reverse",
		"malware-analysis":    "malware-analysis",
		"blue-detection":      "blue-detection",
		"purple-validation":   "purple-validation",
		"linux-native":        "linux-native",
		"vuln-research":       "vuln-research",
		"nday-research":       "vuln-research",
		"dfir-forensics":      "dfir-forensics",
		"source-code-audit":   "source-code-audit",
		"supply-chain":        "source-code-audit",
		"network-assessment":  "network-assessment",
		"pentest-network":     "network-assessment",
		"identity-ad":         "identity-ad",
		"cloud-security":      "cloud-security",
		"container-k8s":       "container-k8s",
		"adversary-emulation": "adversary-emulation",
		"ios":                 "ios-security",
		"firmware-iot":        "firmware-iot",
		"cti-analysis":        "cti-analysis",
		"threat-hunting":      "threat-hunting",
	}
	for routeID, expected := range tests {
		value, ok := registry.ForRoute(routeID)
		if !ok || value.ID != expected {
			t.Fatalf("route %s playbook=%+v ok=%v want=%s", routeID, value, ok, expected)
		}
		if len(value.Gates) < 4 || len(value.Done) < 4 || value.SkillPath == "" || value.ReferencePath == "" {
			t.Fatalf("route %s playbook incomplete: %+v", routeID, value)
		}
	}
}

func TestPlaybookRejectsUnknownCanonicalRoute(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	body, err := os.ReadFile(filepath.Join(root, "config", "playbooks.json"))
	if err != nil {
		t.Fatal(err)
	}
	broken := strings.Replace(string(body), `"native-static"`, `"route-that-does-not-exist"`, 1)
	path := filepath.Join(t.TempDir(), "playbooks.json")
	if err := os.WriteFile(path, []byte(broken), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(root, path); err == nil || !strings.Contains(err.Error(), "unknown canonical route") {
		t.Fatalf("err=%v", err)
	}
}

func TestUnknownRouteDoesNotForceFitPlaybook(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	registry, err := Load(root, filepath.Join(root, "config", "playbooks.json"))
	if err != nil {
		t.Fatal(err)
	}
	if value, ok := registry.ForRoute("unclassified"); ok {
		t.Fatalf("unclassified fallback must not be force-fit into a playbook: %+v", value)
	}
}
