package sourceaudit

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"reverseresearch/internal/targetidentity"
)

const DefaultMaxSARIFBytes int64 = 64 << 20
const DefaultMaxSARIFResults = 2000

type SARIFLocation struct {
	URI       string `json:"uri,omitempty"`
	StartLine int    `json:"start_line,omitempty"`
	StartCol  int    `json:"start_col,omitempty"`
	EndLine   int    `json:"end_line,omitempty"`
	EndCol    int    `json:"end_col,omitempty"`
}

type SARIFCandidate struct {
	RuleID       string            `json:"rule_id,omitempty"`
	Level        string            `json:"level,omitempty"`
	Message      string            `json:"message"`
	ToolName     string            `json:"tool_name,omitempty"`
	ToolVersion  string            `json:"tool_version,omitempty"`
	Locations    []SARIFLocation   `json:"locations,omitempty"`
	Fingerprints map[string]string `json:"fingerprints,omitempty"`
	Strength     string            `json:"strength"`
}

type SARIFReport struct {
	Source     targetidentity.Identity `json:"source"`
	Version    string                  `json:"version"`
	Candidates []SARIFCandidate        `json:"candidates"`
	Rejected   int                     `json:"rejected"`
}

type sarifDocument struct {
	Version string `json:"version"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Name            string `json:"name"`
				Version         string `json:"version"`
				SemanticVersion string `json:"semanticVersion"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID  string `json:"ruleId"`
			Level   string `json:"level"`
			Message struct {
				Text     string `json:"text"`
				Markdown string `json:"markdown"`
			} `json:"message"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
					Region struct {
						StartLine   int `json:"startLine"`
						StartColumn int `json:"startColumn"`
						EndLine     int `json:"endLine"`
						EndColumn   int `json:"endColumn"`
					} `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
			Fingerprints        map[string]string `json:"fingerprints"`
			PartialFingerprints map[string]string `json:"partialFingerprints"`
		} `json:"results"`
	} `json:"runs"`
}

func ImportSARIF(path string, maxBytes int64, maxResults int) (SARIFReport, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxSARIFBytes
	}
	if maxBytes > 256<<20 {
		maxBytes = 256 << 20
	}
	source, err := targetidentity.InspectBounded(path, maxBytes)
	if err != nil {
		return SARIFReport{}, err
	}
	if maxResults <= 0 {
		maxResults = DefaultMaxSARIFResults
	}
	if maxResults > 10000 {
		maxResults = 10000
	}
	if source.Size > maxBytes {
		return SARIFReport{}, fmt.Errorf("SARIF exceeds max_bytes: size=%d max=%d", source.Size, maxBytes)
	}
	body, err := os.ReadFile(source.Path)
	if err != nil {
		return SARIFReport{}, err
	}
	var document sarifDocument
	if err := json.Unmarshal(body, &document); err != nil {
		return SARIFReport{}, fmt.Errorf("decode SARIF: %w", err)
	}
	document.Version = strings.TrimSpace(document.Version)
	if document.Version == "" || len(document.Runs) == 0 {
		return SARIFReport{}, errors.New("SARIF version and at least one run are required")
	}
	report := SARIFReport{Source: source, Version: document.Version, Candidates: []SARIFCandidate{}}
	for _, run := range document.Runs {
		toolVersion := strings.TrimSpace(run.Tool.Driver.SemanticVersion)
		if toolVersion == "" {
			toolVersion = strings.TrimSpace(run.Tool.Driver.Version)
		}
		for _, result := range run.Results {
			if len(report.Candidates) >= maxResults {
				return SARIFReport{}, fmt.Errorf("SARIF result limit exceeded: %d", maxResults)
			}
			message := strings.TrimSpace(result.Message.Text)
			if message == "" {
				message = strings.TrimSpace(result.Message.Markdown)
			}
			if len(message) > 4096 {
				message = message[:4096]
			}
			if message == "" {
				report.Rejected++
				continue
			}
			candidate := SARIFCandidate{
				RuleID: strings.TrimSpace(result.RuleID), Level: strings.ToLower(strings.TrimSpace(result.Level)),
				Message: message, ToolName: strings.TrimSpace(run.Tool.Driver.Name), ToolVersion: toolVersion,
				Strength: "unverified", Fingerprints: map[string]string{},
			}
			for _, location := range result.Locations {
				p := location.PhysicalLocation
				candidate.Locations = append(candidate.Locations, SARIFLocation{
					URI: strings.TrimSpace(p.ArtifactLocation.URI), StartLine: p.Region.StartLine, StartCol: p.Region.StartColumn,
					EndLine: p.Region.EndLine, EndCol: p.Region.EndColumn,
				})
			}
			for key, value := range result.Fingerprints {
				candidate.Fingerprints[key] = value
			}
			for key, value := range result.PartialFingerprints {
				if _, exists := candidate.Fingerprints[key]; !exists {
					candidate.Fingerprints[key] = value
				}
			}
			if len(candidate.Fingerprints) == 0 {
				candidate.Fingerprints = nil
			}
			report.Candidates = append(report.Candidates, candidate)
		}
	}
	after, err := targetidentity.InspectBounded(source.Path, maxBytes)
	if err != nil {
		return SARIFReport{}, err
	}
	if after.ID != source.ID || after.Size != source.Size || after.ModifiedUTC != source.ModifiedUTC {
		return SARIFReport{}, errors.New("SARIF source changed during import")
	}
	return report, nil
}
