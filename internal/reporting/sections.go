package reporting

import (
	"errors"
	"sort"
	"strings"
)

var allowedSections = map[string]bool{
	"summary":         true,
	"targets":         true,
	"artifacts":       true,
	"observations":    true,
	"hypotheses":      true,
	"findings":        true,
	"paths":           true,
	"vulnerabilities": true,
	"evidence":        true,
	"iocs":            true,
	"ttps":            true,
	"detections":      true,
	"mitigations":     true,
	"retests":         true,
	"reports":         true,
	"roles":           true,
	"workitems":       true,
	"timeline":        true,
}

func NormalizeSections(values []string) ([]string, error) {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			part = strings.ToLower(strings.TrimSpace(part))
			if part == "" {
				continue
			}
			if !allowedSections[part] {
				return nil, errors.New("unknown report section " + part)
			}
			if !seen[part] {
				seen[part] = true
				out = append(out, part)
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

func FilterSections(doc Document, sections []string) (Document, error) {
	normalized, err := NormalizeSections(sections)
	if err != nil {
		return Document{}, err
	}
	if len(normalized) == 0 {
		return doc, nil
	}
	doc.Sections = normalized
	keep := map[string]bool{}
	for _, s := range normalized {
		keep[s] = true
	}
	if !keep["summary"] {
		doc.Summary = Summary{}
	}
	if !keep["targets"] {
		doc.Targets = nil
	}
	if !keep["artifacts"] {
		doc.Artifacts = nil
	}
	if !keep["observations"] {
		doc.Observations = nil
	}
	if !keep["hypotheses"] {
		doc.Hypotheses = nil
	}
	if !keep["findings"] {
		doc.Findings = nil
	}
	if !keep["paths"] {
		doc.Paths = nil
	}
	if !keep["vulnerabilities"] {
		doc.Vulnerabilities = nil
	}
	if !keep["evidence"] {
		doc.Evidence = nil
	}
	if !keep["iocs"] {
		doc.IOCs = nil
	}
	if !keep["ttps"] {
		doc.TTPs = nil
	}
	if !keep["detections"] {
		doc.Detections = nil
	}
	if !keep["mitigations"] {
		doc.Mitigations = nil
	}
	if !keep["retests"] {
		doc.Retests = nil
	}
	if !keep["reports"] {
		doc.Reports = nil
	}
	if !keep["roles"] {
		doc.Roles = nil
	}
	if !keep["workitems"] {
		doc.WorkItems = nil
	}
	if !keep["timeline"] {
		doc.Timeline = nil
	}
	refreshProjectionIdentity(&doc)
	return doc, nil
}

func (d Document) Includes(section string) bool {
	if len(d.Sections) == 0 {
		return true
	}
	section = strings.ToLower(strings.TrimSpace(section))
	for _, s := range d.Sections {
		if s == section {
			return true
		}
	}
	return false
}
