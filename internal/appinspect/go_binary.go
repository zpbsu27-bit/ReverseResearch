package appinspect

import (
	"runtime/debug"
	"unicode/utf8"
)

type GoBinaryReport struct {
	Path                     string               `json:"path"`
	SHA256                   string               `json:"sha256"`
	Format                   string               `json:"format"`
	BuildInfoAvailable       bool                 `json:"build_info_available"`
	UnavailableReason        string               `json:"unavailable_reason,omitempty"`
	GoVersion                string               `json:"go_version,omitempty"`
	PackagePath              string               `json:"package_path,omitempty"`
	Main                     debug.Module         `json:"main"`
	Settings                 []debug.BuildSetting `json:"settings"`
	TotalDependencies        int                  `json:"total_dependencies"`
	Offset                   int                  `json:"offset"`
	Dependencies             []*debug.Module      `json:"dependencies"`
	NextOffset               *int                 `json:"next_offset,omitempty"`
	CoverageComplete         bool                 `json:"coverage_complete"`
	EvidenceAuthority        string               `json:"evidence_authority"`
	ExecutionPerformed       bool                 `json:"execution_performed"`
	Limitations              []string             `json:"limitations"`
	ModuleSemanticsAvailable bool                 `json:"module_semantics_available"`
	ModuleFramingRecognized  bool                 `json:"module_framing_recognized"`
	GrammarComplete          bool                 `json:"grammar_complete"`
	TextSummaryComplete      bool                 `json:"text_summary_complete"`
	TotalRecords             int                  `json:"total_records"`
	UnparsedRecords          int                  `json:"unparsed_records"`
	TotalSettingsObserved    int                  `json:"total_settings_observed"`
	GoVersionUTF8            bool                 `json:"go_version_utf8"`
	GoVersionSHA256          string               `json:"go_version_sha256,omitempty"`
}

func InspectGoBinary(path string, o PageOptions) (GoBinaryReport, error) {
	body, abs, hash, err := readArtifact(path, MaxArtifactBytes, o.ExpectedSHA256)
	if err != nil {
		return GoBinaryReport{}, err
	}
	g, err := locateGoMetadata(body)
	if err != nil {
		return GoBinaryReport{}, err
	}
	r := GoBinaryReport{Path: abs, SHA256: hash, Format: g.format, Settings: []debug.BuildSetting{}, Dependencies: []*debug.Module{}, EvidenceAuthority: "embedded-build-metadata", Limitations: []string{"summary derives from the canonical raw locator and lossless record observation; page coverage is separate from grammar/text completeness", "unknown/invalid/duplicate records and non-UTF8 decoded values remain available through app_go_metadata_read records/record-field and exact original module-body bytes", "embedded compiler/module/settings declarations are unauthenticated and do not establish runtime or supply-chain integrity", "absence does not prove the artifact is not Go"}}
	if len(g.header) == 0 {
		if _, _, err := page(o, 0); err != nil {
			return r, err
		}
		r.UnavailableReason = "no aligned recognized Go build-info header"
		return r, nil
	}
	r.BuildInfoAvailable = true
	r.GoVersionUTF8 = utf8.Valid(g.version)
	r.GoVersionSHA256 = digest(g.version)
	if r.GoVersionUTF8 {
		r.GoVersion = string(g.version)
	}
	moduleBody, source, framed := g.moduleBody()
	r.ModuleFramingRecognized = framed && len(g.module) > 0
	if !framed {
		if _, _, err := page(o, 0); err != nil {
			return r, err
		}
		r.UnavailableReason = "module framing unrecognized; exact original bytes remain available"
		return r, projectionLimit(r)
	}
	observation, err := parseGoModuleRecords(moduleBody, source)
	if err != nil {
		return r, err
	}
	info := &observation.info
	start, end, err := page(o, len(info.Deps))
	if err != nil {
		return r, err
	}
	r.ModuleSemanticsAvailable = true
	r.TotalRecords, r.UnparsedRecords = len(observation.rows), observation.unparsed
	r.GrammarComplete = observation.unparsed == 0
	r.TextSummaryComplete = observation.textComplete && r.GoVersionUTF8
	r.TotalSettingsObserved = observation.settingsObserved
	r.PackagePath = info.Path
	r.Main = info.Main
	r.Settings = info.Settings
	r.TotalDependencies = len(info.Deps)
	r.Offset = start
	r.Dependencies = info.Deps[start:end]
	r.CoverageComplete = start == 0 && end == len(info.Deps)
	if end < len(info.Deps) {
		r.NextOffset = &end
	}
	return r, projectionLimit(r)
}
