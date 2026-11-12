package purple

import (
	"sort"
	"strings"

	"reverseresearch/internal/casebook"
)

type TechniqueCoverage struct {
	Technique           string   `json:"technique"`
	Tactics             []string `json:"tactics,omitempty"`
	TTPIDs              []string `json:"ttp_ids"`
	FindingIDs          []string `json:"finding_ids,omitempty"`
	DetectionIDs        []string `json:"detection_ids,omitempty"`
	ValidatedDetections []string `json:"validated_detection_ids,omitempty"`
	MitigationIDs       []string `json:"mitigation_ids,omitempty"`
	RetestIDs           []string `json:"retest_ids,omitempty"`
	Gap                 string   `json:"gap"`
	GapReason           string   `json:"gap_reason"`
	Covered             bool     `json:"covered"`
}

type Coverage struct {
	CaseID              string              `json:"case_id"`
	Techniques          []TechniqueCoverage `json:"techniques"`
	TotalTechniques     int                 `json:"total_techniques"`
	CoveredTechniques   int                 `json:"covered_techniques"`
	UncoveredTechniques int                 `json:"uncovered_techniques"`
	Complete            bool                `json:"complete"`
}

func BuildCoverage(value casebook.Case) Coverage {
	techniques := map[string]*TechniqueCoverage{}
	for _, ttp := range value.TTPs {
		key := normalizeTechnique(ttp.Technique)
		if key == "" {
			continue
		}
		item := techniques[key]
		if item == nil {
			item = &TechniqueCoverage{Technique: key}
			techniques[key] = item
		}
		item.TTPIDs = appendUnique(item.TTPIDs, ttp.ID)
		item.FindingsIDsMerge(ttp.FindingIDs)
		if tactic := strings.TrimSpace(ttp.Tactic); tactic != "" {
			item.Tactics = appendUnique(item.Tactics, tactic)
		}
	}
	for _, detection := range value.Detections {
		key := normalizeTechnique(detection.Technique)
		item := techniques[key]
		if item == nil {
			continue
		}
		item.DetectionIDs = appendUnique(item.DetectionIDs, detection.ID)
		if detection.Validated {
			item.ValidatedDetections = appendUnique(item.ValidatedDetections, detection.ID)
		}
	}
	for _, mitigation := range value.Mitigations {
		key := normalizeTechnique(mitigation.Technique)
		item := techniques[key]
		if item == nil {
			continue
		}
		item.MitigationIDs = appendUnique(item.MitigationIDs, mitigation.ID)
	}
	for _, item := range techniques {
		latestRetest := map[string]casebook.Retest{}
		for _, retest := range value.Retests {
			for _, detectionID := range item.DetectionIDs {
				if retest.SubjectID == detectionID && strings.EqualFold(strings.TrimSpace(retest.SubjectType), "detection") {
					latestRetest[detectionID] = retest
				}
			}
		}
		for _, detectionID := range item.DetectionIDs {
			if retest, ok := latestRetest[detectionID]; ok {
				item.RetestIDs = appendUnique(item.RetestIDs, retest.ID)
			}
		}
		classify(item, value.Detections, latestRetest)
		sort.Strings(item.Tactics)
		sort.Strings(item.TTPIDs)
		sort.Strings(item.FindingIDs)
		sort.Strings(item.DetectionIDs)
		sort.Strings(item.ValidatedDetections)
		sort.Strings(item.MitigationIDs)
		sort.Strings(item.RetestIDs)
	}
	keys := make([]string, 0, len(techniques))
	for key := range techniques {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := Coverage{CaseID: value.ID, Techniques: make([]TechniqueCoverage, 0, len(keys))}
	for _, key := range keys {
		item := *techniques[key]
		result.Techniques = append(result.Techniques, item)
		if item.Covered {
			result.CoveredTechniques++
		}
	}
	result.TotalTechniques = len(result.Techniques)
	result.UncoveredTechniques = result.TotalTechniques - result.CoveredTechniques
	result.Complete = result.TotalTechniques > 0 && result.UncoveredTechniques == 0
	return result
}

func classify(item *TechniqueCoverage, detections []casebook.Detection, retests map[string]casebook.Retest) {
	if len(item.DetectionIDs) == 0 {
		item.Gap = "no_detection"
		item.GapReason = "no Detection is linked to this ATT&CK technique"
		return
	}
	hasValidated := false
	hasTelemetry := false
	hasRetest := false
	hasPassedRetest := false
	hasFailedRetest := false
	for _, detection := range detections {
		if normalizeTechnique(detection.Technique) != item.Technique {
			continue
		}
		hasValidated = hasValidated || detection.Validated
		hasTelemetry = hasTelemetry || detection.TelemetryAvailable
		if retest, ok := retests[detection.ID]; ok {
			hasRetest = true
			status := strings.ToLower(strings.TrimSpace(retest.Status))
			hasPassedRetest = hasPassedRetest || status == "passed"
			hasFailedRetest = hasFailedRetest || status == "failed"
		}
		if detection.Validated && detection.TelemetryAvailable {
			if retest, ok := retests[detection.ID]; ok && strings.EqualFold(strings.TrimSpace(retest.Status), "passed") {
				item.Covered = true
				item.Gap = "covered"
				item.GapReason = "validated detection has available telemetry and an evidence-backed passing retest"
				return
			}
		}
	}
	switch {
	case !hasValidated:
		item.Gap = "detection_unvalidated"
		item.GapReason = "detections exist but none passed canonical validation"
	case !hasTelemetry:
		item.Gap = "telemetry_unavailable"
		item.GapReason = "validated detection exists but required telemetry is not recorded as available"
	case !hasRetest:
		item.Gap = "retest_missing"
		item.GapReason = "validated detection and telemetry exist but no evidence-backed detection retest is recorded"
	case hasFailedRetest && !hasPassedRetest:
		item.Gap = "retest_failed"
		item.GapReason = "latest linked retest evidence records failure"
	default:
		item.Gap = "coverage_unresolved"
		item.GapReason = "available records do not prove a passing validated detection retest"
	}
}

func normalizeTechnique(value string) string {
	return strings.ToUpper(strings.TrimSpace(value))
}

func appendUnique(values []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return values
	}
	for _, current := range values {
		if current == value {
			return values
		}
	}
	return append(values, value)
}

func (c *TechniqueCoverage) FindingsIDsMerge(values []string) {
	for _, value := range values {
		c.FindingIDs = appendUnique(c.FindingIDs, value)
	}
}
