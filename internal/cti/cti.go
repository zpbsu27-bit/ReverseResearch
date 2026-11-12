package cti

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"reverseresearch/internal/targetidentity"
)

const DefaultMaxBytes int64 = 64 << 20
const DefaultMaxObjects = 50000

type Object struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Name     string `json:"name,omitempty"`
	Created  string `json:"created,omitempty"`
	Modified string `json:"modified,omitempty"`
	Pattern  string `json:"pattern,omitempty"`
}
type Relationship struct {
	ID               string `json:"id"`
	Type             string `json:"type"`
	RelationshipType string `json:"relationship_type"`
	SourceRef        string `json:"source_ref"`
	TargetRef        string `json:"target_ref"`
}
type Report struct {
	Source        targetidentity.Identity `json:"source"`
	STIXVersion   string                  `json:"stix_version"`
	Objects       []Object                `json:"objects"`
	Relationships []Relationship          `json:"relationships"`
	Rejected      int                     `json:"rejected"`
}
type HuntPlan struct {
	Hypothesis         string   `json:"hypothesis"`
	Techniques         []string `json:"techniques,omitempty"`
	Telemetry          []string `json:"telemetry"`
	Adapters           []string `json:"adapters,omitempty"`
	ExecutionPerformed bool     `json:"execution_performed"`
}

func ImportSTIX(path string, maxBytes int64, maxObjects int) (Report, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	if maxBytes > 256<<20 {
		maxBytes = 256 << 20
	}
	src, err := targetidentity.InspectBounded(path, maxBytes)
	if err != nil {
		return Report{}, err
	}
	if maxObjects <= 0 {
		maxObjects = DefaultMaxObjects
	}
	if maxObjects > 200000 {
		maxObjects = 200000
	}
	if src.Size > maxBytes {
		return Report{}, fmt.Errorf("STIX bundle exceeds max_bytes: %d", maxBytes)
	}
	body, err := os.ReadFile(src.Path)
	if err != nil {
		return Report{}, err
	}
	var bundle struct {
		Type    string            `json:"type"`
		ID      string            `json:"id"`
		Objects []json.RawMessage `json:"objects"`
	}
	if err := json.Unmarshal(body, &bundle); err != nil {
		return Report{}, fmt.Errorf("decode STIX bundle: %w", err)
	}
	if bundle.Type != "bundle" {
		return Report{}, errors.New("STIX top-level type must be bundle")
	}
	if len(bundle.Objects) > maxObjects {
		return Report{}, errors.New("STIX object limit exceeded")
	}
	allowed := map[string]bool{"indicator": true, "malware": true, "campaign": true, "intrusion-set": true, "infrastructure": true, "vulnerability": true, "observed-data": true, "attack-pattern": true, "identity": true, "tool": true, "course-of-action": true}
	report := Report{Source: src, STIXVersion: "2.1", Objects: []Object{}, Relationships: []Relationship{}}
	for _, raw := range bundle.Objects {
		var head struct {
			ID   string `json:"id"`
			Type string `json:"type"`
		}
		if json.Unmarshal(raw, &head) != nil {
			report.Rejected++
			continue
		}
		head.ID = strings.TrimSpace(head.ID)
		head.Type = strings.TrimSpace(head.Type)
		if head.Type == "relationship" {
			var rel Relationship
			if json.Unmarshal(raw, &rel) != nil || rel.ID == "" || rel.SourceRef == "" || rel.TargetRef == "" || rel.RelationshipType == "" {
				report.Rejected++
				continue
			}
			report.Relationships = append(report.Relationships, rel)
			continue
		}
		if !allowed[head.Type] || head.ID == "" {
			report.Rejected++
			continue
		}
		var o Object
		if json.Unmarshal(raw, &o) != nil {
			report.Rejected++
			continue
		}
		report.Objects = append(report.Objects, o)
	}
	sort.Slice(report.Objects, func(i, j int) bool { return report.Objects[i].ID < report.Objects[j].ID })
	sort.Slice(report.Relationships, func(i, j int) bool { return report.Relationships[i].ID < report.Relationships[j].ID })
	after, err := targetidentity.InspectBounded(src.Path, maxBytes)
	if err != nil {
		return Report{}, err
	}
	if after.ID != src.ID || after.Size != src.Size || after.ModifiedUTC != src.ModifiedUTC {
		return Report{}, errors.New("STIX source changed during import")
	}
	return report, nil
}

func BuildHuntPlan(hypothesis string, techniques, telemetry, adapters []string) (HuntPlan, error) {
	hypothesis = strings.TrimSpace(hypothesis)
	if hypothesis == "" {
		return HuntPlan{}, errors.New("hunt hypothesis is required")
	}
	telemetry = clean(telemetry)
	if len(telemetry) == 0 {
		return HuntPlan{}, errors.New("at least one telemetry source is required")
	}
	return HuntPlan{Hypothesis: hypothesis, Techniques: clean(techniques), Telemetry: telemetry, Adapters: clean(adapters), ExecutionPerformed: false}, nil
}
func clean(in []string) []string {
	m := map[string]bool{}
	out := []string{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v != "" && !m[v] {
			m[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}
