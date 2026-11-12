package reporting

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"sort"
	"strings"
	"time"

	"reverseresearch/internal/casebook"
)

const (
	TemplateVersion = 1
	RendererVersion = 1
)

type Document struct {
	SchemaVersion    int                       `json:"schema_version"`
	TemplateID       string                    `json:"template_id"`
	TemplateVersion  int                       `json:"template_version"`
	RendererVersion  int                       `json:"renderer_version"`
	ProjectionSHA256 string                    `json:"projection_sha256"`
	Profile          string                    `json:"profile"`
	Classification   string                    `json:"classification"`
	CaseID           string                    `json:"case_id"`
	CaseSHA256       string                    `json:"case_sha256"`
	Title            string                    `json:"title"`
	Route            string                    `json:"route,omitempty"`
	EngagementID     string                    `json:"engagement_id,omitempty"`
	GeneratedUTC     string                    `json:"generated_utc"`
	Sections         []string                  `json:"sections,omitempty"`
	Summary          Summary                   `json:"summary"`
	Targets          []casebook.Target         `json:"targets,omitempty"`
	Artifacts        []casebook.Artifact       `json:"artifacts,omitempty"`
	Observations     []casebook.Observation    `json:"observations,omitempty"`
	Hypotheses       []casebook.Hypothesis     `json:"hypotheses,omitempty"`
	Paths            []casebook.ResearchPath   `json:"paths,omitempty"`
	Vulnerabilities  []casebook.Vulnerability  `json:"vulnerabilities,omitempty"`
	Findings         []casebook.Finding        `json:"findings,omitempty"`
	Evidence         []EvidenceRef             `json:"evidence,omitempty"`
	IOCs             []casebook.IOC            `json:"iocs,omitempty"`
	TTPs             []casebook.TTP            `json:"ttps,omitempty"`
	Detections       []casebook.Detection      `json:"detections,omitempty"`
	Mitigations      []casebook.Mitigation     `json:"mitigations,omitempty"`
	Retests          []casebook.Retest         `json:"retests,omitempty"`
	Reports          []casebook.Report         `json:"reports,omitempty"`
	Roles            []casebook.RoleAssignment `json:"roles,omitempty"`
	WorkItems        []casebook.WorkItem       `json:"workitems,omitempty"`
	Timeline         []casebook.TimelineEntry  `json:"timeline,omitempty"`
}
type Summary struct {
	Targets             int `json:"targets"`
	Findings            int `json:"findings"`
	Observed            int `json:"observed"`
	Inferred            int `json:"inferred"`
	Unverified          int `json:"unverified"`
	Evidence            int `json:"evidence"`
	Detections          int `json:"detections"`
	ValidatedDetections int `json:"validated_detections"`
	Retests             int `json:"retests"`
	Artifacts           int `json:"artifacts"`
	Hypotheses          int `json:"hypotheses"`
	AttackPaths         int `json:"attack_paths"`
	TTPs                int `json:"ttps"`
	Reports             int `json:"reports"`
	OpenWorkItems       int `json:"open_workitems"`
}
type EvidenceRef struct {
	ID           string `json:"id"`
	Summary      string `json:"summary"`
	Kind         string `json:"kind,omitempty"`
	SourceSHA256 string `json:"source_sha256,omitempty"`
	ObservedAt   string `json:"observed_at,omitempty"`
}

func Build(c casebook.Case, caseSHA, profile, classification string) (Document, error) {
	caseSHA = strings.ToLower(strings.TrimSpace(caseSHA))
	profile = strings.ToLower(strings.TrimSpace(profile))
	classification = strings.TrimSpace(classification)
	if len(caseSHA) != 64 {
		return Document{}, errors.New("case_sha256 must be 64 hexadecimal characters")
	}
	if _, err := hex.DecodeString(caseSHA); err != nil {
		return Document{}, errors.New("case_sha256 must be hexadecimal")
	}
	switch profile {
	case "reverse", "vulnerability", "red-team", "blue-detection", "malware", "dfir", "general":
	default:
		return Document{}, fmt.Errorf("unsupported report profile %q", profile)
	}
	if classification == "" {
		classification = "internal"
	}
	doc := Document{SchemaVersion: 1, TemplateID: "builtin/" + profile, TemplateVersion: TemplateVersion, RendererVersion: RendererVersion, Profile: profile, Classification: classification, CaseID: c.ID, CaseSHA256: caseSHA, Title: c.Title, Route: c.Route, EngagementID: c.EngagementID, GeneratedUTC: time.Now().UTC().Format(time.RFC3339Nano), Targets: c.Targets, Artifacts: c.Artifacts, Observations: c.Observations, Hypotheses: c.Hypotheses, Paths: c.Paths, Vulnerabilities: c.Vulnerabilities, Findings: c.Findings, IOCs: c.IOCs, TTPs: c.TTPs, Detections: c.Detections, Mitigations: c.Mitigations, Retests: c.Retests, Reports: c.Reports, Roles: c.Roles, WorkItems: c.WorkItems, Timeline: c.Timeline}
	for _, e := range c.Evidence {
		doc.Evidence = append(doc.Evidence, EvidenceRef{ID: e.ID, Summary: e.Summary, Kind: e.Kind, SourceSHA256: e.SourceSHA256, ObservedAt: e.ObservedAt})
	}
	doc.Summary.Targets = len(c.Targets)
	doc.Summary.Findings = len(c.Findings)
	doc.Summary.Evidence = len(c.Evidence)
	doc.Summary.Detections = len(c.Detections)
	doc.Summary.Retests = len(c.Retests)
	doc.Summary.Artifacts = len(c.Artifacts)
	doc.Summary.Hypotheses = len(c.Hypotheses)
	doc.Summary.AttackPaths = len(c.Paths)
	doc.Summary.TTPs = len(c.TTPs)
	doc.Summary.Reports = len(c.Reports)
	for _, item := range c.WorkItems {
		if item.Status != "done" && item.Status != "cancelled" {
			doc.Summary.OpenWorkItems++
		}
	}
	for _, f := range c.Findings {
		switch strings.ToLower(f.Strength) {
		case "observed":
			doc.Summary.Observed++
		case "inferred":
			doc.Summary.Inferred++
		default:
			doc.Summary.Unverified++
		}
	}
	for _, d := range c.Detections {
		if d.Validated {
			doc.Summary.ValidatedDetections++
		}
	}
	refreshProjectionIdentity(&doc)
	return doc, nil
}

func refreshProjectionIdentity(doc *Document) {
	copyDoc := *doc
	copyDoc.GeneratedUTC = ""
	copyDoc.ProjectionSHA256 = ""
	body, _ := json.Marshal(copyDoc)
	sum := sha256.Sum256(body)
	doc.ProjectionSHA256 = hex.EncodeToString(sum[:])
}

func Render(doc Document, format string) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "json":
		b, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			return nil, err
		}
		return append(b, '\n'), nil
	case "markdown", "md":
		return renderMarkdown(doc), nil
	case "html":
		return renderHTML(doc), nil
	case "sarif":
		return renderSARIF(doc)
	case "stix":
		return renderSTIX(doc)
	default:
		return nil, fmt.Errorf("unsupported report format %q", format)
	}
}
func renderMarkdown(d Document) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "# %s\n\n", d.Title)
	fmt.Fprintf(&b, "- Profile: %s\n- Classification: %s\n- Template: %s v%d\n- Renderer: v%d\n- Projection SHA-256: %s\n- Case: %s\n- Case SHA-256: %s\n", d.Profile, d.Classification, d.TemplateID, d.TemplateVersion, d.RendererVersion, d.ProjectionSHA256, d.CaseID, d.CaseSHA256)
	if d.EngagementID != "" {
		fmt.Fprintf(&b, "- Engagement: %s\n", d.EngagementID)
	}
	if d.Includes("summary") {
		fmt.Fprintf(&b, "\n## Summary\n\nTargets: %d; Findings: %d (observed %d, inferred %d, unverified %d); Evidence: %d; Validated detections: %d/%d; Retests: %d.\n", d.Summary.Targets, d.Summary.Findings, d.Summary.Observed, d.Summary.Inferred, d.Summary.Unverified, d.Summary.Evidence, d.Summary.ValidatedDetections, d.Summary.Detections, d.Summary.Retests)
	}
	if d.Includes("findings") {
		fmt.Fprintln(&b, "\n## Findings")
		if len(d.Findings) == 0 {
			fmt.Fprintln(&b, "\nNo findings recorded.")
		}
		for _, f := range d.Findings {
			fmt.Fprintf(&b, "\n### %s\n\n- ID: %s\n- Strength: %s\n- Severity: %s\n\n%s\n", f.Title, f.ID, f.Strength, f.Severity, f.Conclusion)
		}
	}
	if d.Includes("evidence") {
		fmt.Fprintln(&b, "\n## Evidence")
		if len(d.Evidence) == 0 {
			fmt.Fprintln(&b, "\nNo evidence recorded.")
		}
		for _, e := range d.Evidence {
			fmt.Fprintf(&b, "\n- %s 鈥?%s", e.ID, e.Summary)
			if e.SourceSHA256 != "" {
				fmt.Fprintf(&b, " (sha256:%s)", e.SourceSHA256)
			}
			fmt.Fprintln(&b)
		}
	}
	return b.Bytes()
}
func renderHTML(d Document) []byte {
	md := string(renderMarkdown(d))
	return []byte("<!doctype html><html><head><meta charset=\"utf-8\"><title>" + html.EscapeString(d.Title) + "</title></head><body><pre>" + html.EscapeString(md) + "</pre></body></html>\n")
}
func renderSARIF(d Document) ([]byte, error) {
	type result struct {
		RuleID     string            `json:"ruleId,omitempty"`
		Level      string            `json:"level,omitempty"`
		Message    map[string]string `json:"message"`
		Properties map[string]any    `json:"properties,omitempty"`
	}
	results := []result{}
	for _, f := range d.Findings {
		rule := f.Category
		if len(f.CWE) > 0 {
			rule = f.CWE[0]
		}
		if rule == "" {
			rule = "ReverseResearch.Finding"
		}
		level := "warning"
		switch strings.ToLower(f.Severity) {
		case "critical", "high":
			level = "error"
		case "informational", "info":
			level = "note"
		}
		results = append(results, result{RuleID: rule, Level: level, Message: map[string]string{"text": f.Title + ": " + f.Conclusion}, Properties: map[string]any{"finding_id": f.ID, "strength": f.Strength, "evidence_ids": f.EvidenceIDs}})
	}
	root := map[string]any{"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": []any{map[string]any{"tool": map[string]any{"driver": map[string]any{"name": "ReverseResearch", "informationUri": "project:ReverseResearch"}}, "results": results}}}
	b, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
func renderSTIX(d Document) ([]byte, error) {
	objects := []any{}
	for _, ioc := range d.IOCs {
		pattern := fmt.Sprintf("[%s:value = '%s']", strings.ReplaceAll(ioc.Type, "-", "_"), strings.ReplaceAll(ioc.Value, "'", "\\'"))
		objects = append(objects, map[string]any{"type": "indicator", "spec_version": "2.1", "id": stableSTIXID("indicator", d.CaseID+ioc.ID), "created": d.GeneratedUTC, "modified": d.GeneratedUTC, "pattern_type": "stix", "pattern": pattern, "valid_from": d.GeneratedUTC})
	}
	for _, f := range d.Findings {
		objects = append(objects, map[string]any{"type": "vulnerability", "spec_version": "2.1", "id": stableSTIXID("vulnerability", d.CaseID+f.ID), "created": d.GeneratedUTC, "modified": d.GeneratedUTC, "name": f.Title, "description": f.Conclusion})
	}
	for _, t := range d.TTPs {
		objects = append(objects, map[string]any{"type": "attack-pattern", "spec_version": "2.1", "id": stableSTIXID("attack-pattern", d.CaseID+t.ID), "created": d.GeneratedUTC, "modified": d.GeneratedUTC, "name": t.Technique, "external_references": []any{map[string]any{"source_name": "mitre-attack", "external_id": t.Technique}}})
	}
	root := map[string]any{"type": "bundle", "id": stableSTIXID("bundle", d.CaseID+d.CaseSHA256), "objects": objects}
	b, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
func stableSTIXID(kind, seed string) string {
	sum := sha256.Sum256([]byte(seed))
	h := hex.EncodeToString(sum[:16])
	return kind + "--" + h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}
func SupportedFormats() []string {
	v := []string{"html", "json", "markdown", "sarif", "stix"}
	sort.Strings(v)
	return v
}
