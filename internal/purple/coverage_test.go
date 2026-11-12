package purple

import (
	"testing"

	"reverseresearch/internal/casebook"
)

func TestCoverageClassifiesCoveredAndGapsWithoutInventingRuntimeProof(t *testing.T) {
	value := casebook.Case{
		ID: "case_x",
		TTPs: []casebook.TTP{
			{ID: "ttp_a", Technique: "T1053", Tactic: "Persistence"},
			{ID: "ttp_b", Technique: "T1055", Tactic: "Defense Evasion"},
			{ID: "ttp_c", Technique: "T1071", Tactic: "Command and Control"},
		},
		Detections: []casebook.Detection{
			{ID: "d_a", Technique: "T1053", Validated: true, TelemetryAvailable: true},
			{ID: "d_b", Technique: "T1055", Validated: true, TelemetryAvailable: false},
		},
		Mitigations: []casebook.Mitigation{{ID: "m_a", Technique: "T1053", Summary: "policy"}},
		Retests:     []casebook.Retest{{ID: "r_a", SubjectType: "detection", SubjectID: "d_a", Status: "passed"}},
	}
	result := BuildCoverage(value)
	if result.TotalTechniques != 3 || result.CoveredTechniques != 1 || result.UncoveredTechniques != 2 || result.Complete {
		t.Fatalf("result=%+v", result)
	}
	byTechnique := map[string]TechniqueCoverage{}
	for _, item := range result.Techniques {
		byTechnique[item.Technique] = item
	}
	if !byTechnique["T1053"].Covered || byTechnique["T1053"].Gap != "covered" {
		t.Fatalf("T1053=%+v", byTechnique["T1053"])
	}
	if byTechnique["T1055"].Gap != "telemetry_unavailable" {
		t.Fatalf("T1055=%+v", byTechnique["T1055"])
	}
	if byTechnique["T1071"].Gap != "no_detection" {
		t.Fatalf("T1071=%+v", byTechnique["T1071"])
	}
}
