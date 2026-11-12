package core

import "testing"

func TestPrepareSelectsP2InfrastructureAndIntelPacks(t *testing.T) {
	root, _ := isolatedCoreRoot(t)
	service, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct{ task, route, playbook, pack, skill string }{
		{"analyze this Active Directory BloodHound identity graph and domain trust attack path", "identity-ad", "identity-ad", "identity-ad", "skills/seep-identity/SKILL.md"},
		{"review this AWS cloud IAM inventory and resource exposure graph", "cloud-security", "cloud-security", "cloud", "skills/seep-cloud/SKILL.md"},
		{"analyze this Kubernetes RBAC cluster inventory and container image security", "container-k8s", "container-k8s", "container-k8s", "skills/seep-cloud/SKILL.md"},
		{"perform an authorized network assessment from this service inventory", "network-assessment", "network-assessment", "redteam", "skills/seep-redteam/SKILL.md"},
		{"prepare ATT&CK adversary emulation with telemetry and retest", "adversary-emulation", "adversary-emulation", "adversary-emulation", "skills/seep-redteam/SKILL.md"},
		{"import this STIX bundle and correlate IOC campaign relationships", "cti-analysis", "cti-analysis", "cti-hunting", "skills/seep-cti/SKILL.md"},
		{"build a threat hunting hypothesis using Sysmon telemetry and Sigma", "threat-hunting", "threat-hunting", "cti-hunting", "skills/seep-cti/SKILL.md"},
		{"inventory this iOS IPA Mach-O frameworks and provisioning metadata", "ios", "ios-security", "ios", "skills/seep-mobile/SKILL.md"},
		{"triage this IoT firmware image and plan isolated QEMU emulation", "firmware-iot", "firmware-iot", "firmware", "skills/seep-firmware/SKILL.md"},
	}
	for _, tc := range tests {
		got, err := service.Prepare(tc.task)
		if err != nil {
			t.Fatalf("%s: %v", tc.task, err)
		}
		if got.Route.Route.ID != tc.route || got.Playbook == nil || got.Playbook.ID != tc.playbook ||
			got.DomainPack == nil || got.DomainPack.ID != tc.pack || got.DomainPack.Skill.Path != tc.skill ||
			got.DomainPack.Skill.OwnsRouting {
			t.Fatalf("%s prepare=%+v", tc.task, got)
		}
	}
}
