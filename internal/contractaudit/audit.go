package contractaudit

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"reverseresearch/internal/catalog"
)

const DefaultSnapshotName = "online-rr-rt-contract-20261001.json"

func FindDefaultSnapshot(start string) (string, error) {
	candidates := []string{start}
	if executable, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Dir(executable))
	}
	seen := map[string]struct{}{}
	for _, candidate := range candidates {
		absolute, err := filepath.Abs(candidate)
		if err != nil {
			continue
		}
		for dir := filepath.Clean(absolute); ; dir = filepath.Dir(dir) {
			if _, exists := seen[dir]; !exists {
				seen[dir] = struct{}{}
				path := filepath.Join(dir, "testdata", DefaultSnapshotName)
				if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
					return path, nil
				}
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
		}
	}
	return "", fmt.Errorf("cannot locate testdata/%s from %q or executable ancestors", DefaultSnapshotName, start)
}

type Parameter struct {
	Name     string `json:"name"`
	Required bool   `json:"required"`
	Type     string `json:"type"`
}

type Tool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Params      []Parameter `json:"params"`
}

type Snapshot struct {
	SchemaVersion       int    `json:"schema_version"`
	ObservedDateUTC     string `json:"observed_date_utc"`
	Source              string `json:"source"`
	RRToolCount         int    `json:"rr_tool_count"`
	RTToolCount         int    `json:"rt_tool_count"`
	RRRTNormalizedEqual bool   `json:"rr_rt_normalized_equal"`
	Tools               []Tool `json:"tools"`
}

type ToolDiff struct {
	Name                string      `json:"name"`
	SnapshotDescription string      `json:"snapshot_description"`
	LocalDescription    string      `json:"local_description"`
	Snapshot            []Parameter `json:"snapshot"`
	Local               []Parameter `json:"local"`
}

type Report struct {
	SnapshotSource          string     `json:"snapshot_source"`
	SnapshotObservedDateUTC string     `json:"snapshot_observed_date_utc"`
	SnapshotToolCount       int        `json:"snapshot_tool_count"`
	LocalBaseToolCount      int        `json:"local_base_tool_count"`
	RRToolCount             int        `json:"rr_tool_count"`
	RTToolCount             int        `json:"rt_tool_count"`
	RRRTNormalizedEqual     bool       `json:"rr_rt_normalized_equal"`
	MissingLocal            []string   `json:"missing_local,omitempty"`
	ExtraLocal              []string   `json:"extra_local,omitempty"`
	ParameterDiffs          []ToolDiff `json:"parameter_diffs,omitempty"`
	Match                   bool       `json:"match"`
}

func Audit(snapshotPath string) (Report, error) {
	snapshot, err := loadSnapshot(snapshotPath)
	if err != nil {
		return Report{}, err
	}
	local, err := LocalBaseContract()
	if err != nil {
		return Report{}, err
	}
	report := compare(snapshot, local)
	return report, nil
}

func LocalBaseContract() ([]Tool, error) {
	specs := []struct {
		Catalog string
		Prefix  string
	}{
		{Catalog: "ghidra", Prefix: "ghidra_"},
		{Catalog: "r2", Prefix: "r2_"},
		{Catalog: "x32dbg", Prefix: "x32dbg_"},
	}
	var result []Tool
	for _, spec := range specs {
		tools, err := catalog.Load(spec.Catalog, spec.Prefix)
		if err != nil {
			return nil, err
		}
		for _, tool := range tools {
			params, err := schemaParameters(tool.InputSchema)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", tool.Name, err)
			}
			result = append(result, Tool{Name: tool.Name, Description: strings.TrimSpace(tool.Description), Params: params})
		}
	}
	result = append(result, Tool{
		Name:        "reverse_status",
		Description: "Show x32dbg, Ghidra, and radare2 module state without starting a backend.",
		Params:      []Parameter{},
	})
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	if err := validateTools(result); err != nil {
		return nil, fmt.Errorf("local base contract: %w", err)
	}
	return result, nil
}

func loadSnapshot(path string) (Snapshot, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return Snapshot{}, fmt.Errorf("read online contract snapshot: %w", err)
	}
	var snapshot Snapshot
	if err := json.Unmarshal(body, &snapshot); err != nil {
		return Snapshot{}, fmt.Errorf("decode online contract snapshot: %w", err)
	}
	if snapshot.SchemaVersion != 1 {
		return Snapshot{}, fmt.Errorf("unsupported contract snapshot schema_version %d", snapshot.SchemaVersion)
	}
	if !snapshot.RRRTNormalizedEqual {
		return Snapshot{}, errors.New("snapshot says RR and RT normalized contracts differ")
	}
	if snapshot.RRToolCount != len(snapshot.Tools) || snapshot.RTToolCount != len(snapshot.Tools) {
		return Snapshot{}, fmt.Errorf(
			"snapshot count mismatch: rr=%d rt=%d tools=%d",
			snapshot.RRToolCount, snapshot.RTToolCount, len(snapshot.Tools),
		)
	}
	for i := range snapshot.Tools {
		sort.Slice(snapshot.Tools[i].Params, func(a, b int) bool {
			return snapshot.Tools[i].Params[a].Name < snapshot.Tools[i].Params[b].Name
		})
	}
	sort.Slice(snapshot.Tools, func(i, j int) bool { return snapshot.Tools[i].Name < snapshot.Tools[j].Name })
	if err := validateTools(snapshot.Tools); err != nil {
		return Snapshot{}, fmt.Errorf("online contract snapshot: %w", err)
	}
	return snapshot, nil
}

func compare(snapshot Snapshot, local []Tool) Report {
	report := Report{
		SnapshotSource:          snapshot.Source,
		SnapshotObservedDateUTC: snapshot.ObservedDateUTC,
		SnapshotToolCount:       len(snapshot.Tools),
		LocalBaseToolCount:      len(local),
		RRToolCount:             snapshot.RRToolCount,
		RTToolCount:             snapshot.RTToolCount,
		RRRTNormalizedEqual:     snapshot.RRRTNormalizedEqual,
	}
	snapshotByName := make(map[string]Tool, len(snapshot.Tools))
	localByName := make(map[string]Tool, len(local))
	for _, tool := range snapshot.Tools {
		snapshotByName[tool.Name] = tool
	}
	for _, tool := range local {
		localByName[tool.Name] = tool
	}
	for _, tool := range snapshot.Tools {
		localTool, ok := localByName[tool.Name]
		if !ok {
			report.MissingLocal = append(report.MissingLocal, tool.Name)
			continue
		}
		if tool.Description != localTool.Description || !parametersEqual(tool.Params, localTool.Params) {
			report.ParameterDiffs = append(report.ParameterDiffs, ToolDiff{
				Name:                tool.Name,
				SnapshotDescription: tool.Description,
				LocalDescription:    localTool.Description,
				Snapshot:            tool.Params,
				Local:               localTool.Params,
			})
		}
	}
	for _, tool := range local {
		if _, ok := snapshotByName[tool.Name]; !ok {
			report.ExtraLocal = append(report.ExtraLocal, tool.Name)
		}
	}
	report.Match = report.RRRTNormalizedEqual &&
		len(report.MissingLocal) == 0 &&
		len(report.ExtraLocal) == 0 &&
		len(report.ParameterDiffs) == 0 &&
		report.SnapshotToolCount == report.LocalBaseToolCount
	return report
}

func parametersEqual(left, right []Parameter) bool {
	if len(left) == 0 && len(right) == 0 {
		return true
	}
	return reflect.DeepEqual(left, right)
}

func schemaParameters(schema any) ([]Parameter, error) {
	object, ok := schema.(map[string]any)
	if !ok {
		return nil, errors.New("input schema is not an object")
	}
	properties := map[string]any{}
	if raw, exists := object["properties"]; exists {
		var propertiesOK bool
		properties, propertiesOK = raw.(map[string]any)
		if !propertiesOK {
			return nil, errors.New("schema properties are not an object")
		}
	}
	required := requiredNames(object["required"])
	params := make([]Parameter, 0, len(properties))
	for name, raw := range properties {
		property, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("property %q schema is not an object", name)
		}
		kind := schemaType(property)
		if kind == "" {
			return nil, fmt.Errorf("property %q has no supported type", name)
		}
		params = append(params, Parameter{Name: name, Required: required[name], Type: kind})
	}
	sort.Slice(params, func(i, j int) bool { return params[i].Name < params[j].Name })
	return params, nil
}

func schemaType(schema map[string]any) string {
	if raw, ok := schema["type"].(string); ok {
		kind := strings.TrimSpace(raw)
		if kind != "" {
			return kind
		}
	}
	if raw, ok := schema["type"].([]any); ok {
		return singleNonNullType(raw)
	}
	for _, key := range []string{"anyOf", "oneOf"} {
		raw, ok := schema[key].([]any)
		if !ok {
			continue
		}
		kinds := make([]string, 0, len(raw))
		seen := map[string]struct{}{}
		for _, item := range raw {
			variant, ok := item.(map[string]any)
			if !ok {
				continue
			}
			kind := schemaType(variant)
			if kind == "" || kind == "null" {
				continue
			}
			if _, exists := seen[kind]; exists {
				continue
			}
			seen[kind] = struct{}{}
			kinds = append(kinds, kind)
		}
		if len(kinds) == 1 {
			return kinds[0]
		}
	}
	if _, ok := schema["enum"]; ok {
		return "string"
	}
	return ""
}

func singleNonNullType(values []any) string {
	var result string
	for _, value := range values {
		kind, ok := value.(string)
		if !ok {
			return ""
		}
		kind = strings.TrimSpace(kind)
		if kind == "" || kind == "null" {
			continue
		}
		if result != "" && result != kind {
			return ""
		}
		result = kind
	}
	return result
}

func requiredNames(value any) map[string]bool {
	result := map[string]bool{}
	switch values := value.(type) {
	case []any:
		for _, value := range values {
			if text, ok := value.(string); ok {
				result[text] = true
			}
		}
	case []string:
		for _, value := range values {
			result[value] = true
		}
	}
	return result
}

func validateTools(tools []Tool) error {
	seen := make(map[string]struct{}, len(tools))
	for _, tool := range tools {
		if strings.TrimSpace(tool.Name) == "" {
			return errors.New("empty tool name")
		}
		if strings.TrimSpace(tool.Description) == "" {
			return fmt.Errorf("tool %q has empty description", tool.Name)
		}
		if _, exists := seen[tool.Name]; exists {
			return fmt.Errorf("duplicate tool %q", tool.Name)
		}
		seen[tool.Name] = struct{}{}
		paramSeen := map[string]struct{}{}
		for _, param := range tool.Params {
			if strings.TrimSpace(param.Name) == "" || strings.TrimSpace(param.Type) == "" {
				return fmt.Errorf("tool %q has invalid parameter %+v", tool.Name, param)
			}
			if _, exists := paramSeen[param.Name]; exists {
				return fmt.Errorf("tool %q has duplicate parameter %q", tool.Name, param.Name)
			}
			paramSeen[param.Name] = struct{}{}
		}
	}
	return nil
}
