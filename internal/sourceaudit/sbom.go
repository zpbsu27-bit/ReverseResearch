package sourceaudit

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"reverseresearch/internal/targetidentity"
)

const DefaultMaxSBOMBytes int64 = 64 << 20
const DefaultMaxSBOMComponents = 50000

type SBOMComponent struct {
	Type     string `json:"type,omitempty"`
	Name     string `json:"name"`
	Version  string `json:"version,omitempty"`
	PURL     string `json:"purl,omitempty"`
	License  string `json:"license,omitempty"`
	Supplier string `json:"supplier,omitempty"`
}

type SBOMReport struct {
	Source      targetidentity.Identity `json:"source"`
	Format      string                  `json:"format"`
	SpecVersion string                  `json:"spec_version,omitempty"`
	Components  []SBOMComponent         `json:"components"`
}

func ImportSBOM(path string, maxBytes int64, maxComponents int) (SBOMReport, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxSBOMBytes
	}
	if maxBytes > 256<<20 {
		maxBytes = 256 << 20
	}
	source, err := targetidentity.InspectBounded(path, maxBytes)
	if err != nil {
		return SBOMReport{}, err
	}
	if maxComponents <= 0 {
		maxComponents = DefaultMaxSBOMComponents
	}
	if maxComponents > 200000 {
		maxComponents = 200000
	}
	if source.Size > maxBytes {
		return SBOMReport{}, fmt.Errorf("SBOM exceeds max_bytes: size=%d max=%d", source.Size, maxBytes)
	}
	body, err := os.ReadFile(source.Path)
	if err != nil {
		return SBOMReport{}, err
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(body, &probe); err != nil {
		return SBOMReport{}, fmt.Errorf("decode SBOM: %w", err)
	}
	var report SBOMReport
	report.Source = source
	switch {
	case probe["bomFormat"] != nil:
		report, err = parseCycloneDX(source, body, maxComponents)
	case probe["spdxVersion"] != nil:
		report, err = parseSPDX(source, body, maxComponents)
	default:
		err = errors.New("unsupported SBOM JSON: expected CycloneDX bomFormat or SPDX spdxVersion")
	}
	if err != nil {
		return SBOMReport{}, err
	}
	after, err := targetidentity.InspectBounded(source.Path, maxBytes)
	if err != nil {
		return SBOMReport{}, err
	}
	if after.ID != source.ID || after.Size != source.Size || after.ModifiedUTC != source.ModifiedUTC {
		return SBOMReport{}, errors.New("SBOM source changed during import")
	}
	sort.Slice(report.Components, func(i, j int) bool {
		if report.Components[i].Name != report.Components[j].Name {
			return report.Components[i].Name < report.Components[j].Name
		}
		return report.Components[i].Version < report.Components[j].Version
	})
	return report, nil
}

func parseCycloneDX(source targetidentity.Identity, body []byte, max int) (SBOMReport, error) {
	var doc struct {
		BomFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		Components  []struct {
			Type     string `json:"type"`
			Name     string `json:"name"`
			Version  string `json:"version"`
			PURL     string `json:"purl"`
			Supplier struct {
				Name string `json:"name"`
			} `json:"supplier"`
			Licenses []struct {
				License struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"license"`
				Expression string `json:"expression"`
			} `json:"licenses"`
		} `json:"components"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return SBOMReport{}, err
	}
	if !strings.EqualFold(strings.TrimSpace(doc.BomFormat), "CycloneDX") {
		return SBOMReport{}, errors.New("invalid CycloneDX bomFormat")
	}
	if len(doc.Components) > max {
		return SBOMReport{}, fmt.Errorf("SBOM component limit exceeded: %d", max)
	}
	report := SBOMReport{Source: source, Format: "cyclonedx", SpecVersion: strings.TrimSpace(doc.SpecVersion), Components: []SBOMComponent{}}
	for _, item := range doc.Components {
		if strings.TrimSpace(item.Name) == "" {
			continue
		}
		licenses := []string{}
		for _, l := range item.Licenses {
			v := strings.TrimSpace(l.Expression)
			if v == "" {
				v = strings.TrimSpace(l.License.ID)
			}
			if v == "" {
				v = strings.TrimSpace(l.License.Name)
			}
			if v != "" {
				licenses = append(licenses, v)
			}
		}
		report.Components = append(report.Components, SBOMComponent{
			Type: strings.TrimSpace(item.Type), Name: strings.TrimSpace(item.Name), Version: strings.TrimSpace(item.Version),
			PURL: strings.TrimSpace(item.PURL), License: strings.Join(uniqueSorted(licenses), ";"), Supplier: strings.TrimSpace(item.Supplier.Name),
		})
	}
	return report, nil
}

func parseSPDX(source targetidentity.Identity, body []byte, max int) (SBOMReport, error) {
	var doc struct {
		SPDXVersion string `json:"spdxVersion"`
		Packages    []struct {
			Name             string `json:"name"`
			VersionInfo      string `json:"versionInfo"`
			LicenseConcluded string `json:"licenseConcluded"`
			LicenseDeclared  string `json:"licenseDeclared"`
			Supplier         string `json:"supplier"`
			ExternalRefs     []struct {
				ReferenceType    string `json:"referenceType"`
				ReferenceLocator string `json:"referenceLocator"`
			} `json:"externalRefs"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return SBOMReport{}, err
	}
	if strings.TrimSpace(doc.SPDXVersion) == "" {
		return SBOMReport{}, errors.New("invalid SPDX version")
	}
	if len(doc.Packages) > max {
		return SBOMReport{}, fmt.Errorf("SBOM component limit exceeded: %d", max)
	}
	report := SBOMReport{Source: source, Format: "spdx", SpecVersion: strings.TrimSpace(doc.SPDXVersion), Components: []SBOMComponent{}}
	for _, p := range doc.Packages {
		if strings.TrimSpace(p.Name) == "" {
			continue
		}
		license := strings.TrimSpace(p.LicenseConcluded)
		if license == "" || license == "NOASSERTION" {
			license = strings.TrimSpace(p.LicenseDeclared)
		}
		purl := ""
		for _, ref := range p.ExternalRefs {
			if strings.Contains(strings.ToLower(ref.ReferenceType), "purl") || strings.HasPrefix(ref.ReferenceLocator, "pkg:") {
				purl = strings.TrimSpace(ref.ReferenceLocator)
				break
			}
		}
		report.Components = append(report.Components, SBOMComponent{Name: strings.TrimSpace(p.Name), Version: strings.TrimSpace(p.VersionInfo), PURL: purl, License: license, Supplier: strings.TrimSpace(p.Supplier)})
	}
	return report, nil
}

func uniqueSorted(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}
