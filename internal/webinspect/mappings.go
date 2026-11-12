package webinspect

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
)

const maxMappingSegments = 250000

type mapSegment struct {
	line, column, source, originalLine, originalColumn int
	name                                               string
}

type mapBudget struct{ maps, sources, names, segments int }

// Inventories flatten in section order, retaining each leaf's sourceRoot.
func parseMapTree(body []byte, depth int, budget *mapBudget) (sourceMapPayload, error) {
	var envelope map[string]json.RawMessage
	if err := decodeOfflineJSON(body, &envelope); err != nil {
		return sourceMapPayload{}, err
	}
	budget.maps++
	if depth > 16 || budget.maps > 4096 {
		return sourceMapPayload{}, errors.New("source-map section depth/count exceeds limit")
	}
	sections, indexed := envelope["sections"]
	if !indexed {
		p, err := parseClassicMap(body)
		if err != nil {
			return p, err
		}
		budget.sources += len(p.sources)
		budget.names += len(p.Names)
		if budget.sources > maxMapItems || budget.names > maxMapItems {
			return p, errors.New("combined source-map inventory exceeds limit")
		}
		p.segments, err = decodeMappings(*p.Mappings, len(p.sources), p.Names, budget)
		return p, err
	}
	var version int
	if err := json.Unmarshal(envelope["version"], &version); err != nil || version != 3 {
		return sourceMapPayload{}, errors.New("indexed source map requires version 3")
	}
	for _, key := range []string{"sources", "mappings", "sourcesContent", "names", "sourceRoot"} {
		if _, ok := envelope[key]; ok {
			return sourceMapPayload{}, fmt.Errorf("indexed source map cannot also declare %s", key)
		}
	}
	type section struct {
		Offset *struct {
			Line   *int `json:"line"`
			Column *int `json:"column"`
		} `json:"offset"`
		Map json.RawMessage `json:"map"`
		URL json.RawMessage `json:"url"`
	}
	var list []section
	if string(sections) == "null" || json.Unmarshal(sections, &list) != nil {
		return sourceMapPayload{}, errors.New("sections must be an array")
	}
	p := sourceMapPayload{Version: 3, indexed: true}
	if raw, ok := envelope["file"]; ok {
		if err := json.Unmarshal(raw, &p.File); err != nil || len(p.File) > maxMapLabelBytes {
			return p, errors.New("invalid indexed map file label")
		}
	}
	lastLine, lastColumn := -1, -1
	for _, s := range list {
		if s.Offset == nil || s.Offset.Line == nil || s.Offset.Column == nil {
			return p, errors.New("section requires line and column offsets")
		}
		line, column := *s.Offset.Line, *s.Offset.Column
		if line < 0 || column < 0 || line > math.MaxInt32 || column > math.MaxInt32 || line < lastLine || line == lastLine && column <= lastColumn {
			return p, errors.New("section offsets must be nonnegative and strictly increasing")
		}
		if len(s.URL) != 0 || len(s.Map) == 0 || string(s.Map) == "null" {
			return p, errors.New("section must contain an embedded map; section URLs are not loaded")
		}
		if len(p.segments) > 0 {
			prev := p.segments[len(p.segments)-1]
			if prev.line > line || prev.line == line && prev.column >= column {
				return p, errors.New("source-map sections overlap")
			}
		}
		child, err := parseMapTree(s.Map, depth+1, budget)
		if err != nil {
			return p, err
		}
		base := len(p.sources)
		p.sources = append(p.sources, child.sources...)
		p.roots = append(p.roots, child.roots...)
		for i := range child.sources {
			if i < len(child.contents) {
				p.contents = append(p.contents, child.contents[i])
			} else {
				p.contents = append(p.contents, nil)
			}
		}
		p.Names = append(p.Names, child.Names...)
		// A section boundary terminates a previous mapping even if this section
		// is empty or its first generated segment begins after its offset.
		if len(child.segments) == 0 || child.segments[0].line != 0 || child.segments[0].column != 0 {
			budget.segments++
			if budget.segments > maxMappingSegments {
				return p, errors.New("source-map segment count exceeds limit")
			}
			p.segments = append(p.segments, mapSegment{line: line, column: column, source: -1})
		}
		for _, m := range child.segments {
			if m.line == 0 {
				m.column += column
			}
			m.line += line
			if m.line > math.MaxInt32 || m.column > math.MaxInt32 {
				return p, errors.New("section coordinate overflow")
			}
			if m.source >= 0 {
				m.source += base
			}
			p.segments = append(p.segments, m)
		}
		lastLine, lastColumn = line, column
	}
	return p, nil
}

func decodeMappings(encoded string, sourceCount int, names []*string, budget *mapBudget) ([]mapSegment, error) {
	var result []mapSegment
	line, column, source, originalLine, originalColumn, name := 0, 0, 0, 0, 0, 0
	for i := 0; i < len(encoded); {
		if encoded[i] == ';' {
			line++
			column = 0
			i++
			if line > math.MaxInt32 {
				return nil, errors.New("mapping line overflow")
			}
			continue
		}
		if encoded[i] == ',' {
			return nil, errors.New("empty mapping segment")
		}
		var fields [5]int
		count := 0
		for i < len(encoded) && encoded[i] != ',' && encoded[i] != ';' {
			if count == len(fields) {
				return nil, errors.New("mapping segment has too many fields")
			}
			v, err := decodeVLQ(encoded, &i)
			if err != nil {
				return nil, err
			}
			fields[count] = v
			count++
		}
		if count != 1 && count != 4 && count != 5 {
			return nil, errors.New("mapping segment must have 1, 4 or 5 fields")
		}
		var err error
		column, err = mapDelta(column, fields[0])
		if err != nil {
			return nil, err
		}
		m := mapSegment{line: line, column: column, source: -1}
		if len(result) > 0 {
			prev := result[len(result)-1]
			if prev.line == line && prev.column >= column {
				return nil, errors.New("mapping coordinates are decreasing or ambiguous")
			}
		}
		if count >= 4 {
			if source, err = mapDelta(source, fields[1]); err != nil {
				return nil, err
			}
			if originalLine, err = mapDelta(originalLine, fields[2]); err != nil {
				return nil, err
			}
			if originalColumn, err = mapDelta(originalColumn, fields[3]); err != nil {
				return nil, err
			}
			if source >= sourceCount {
				return nil, errors.New("mapping references undeclared source")
			}
			m.source, m.originalLine, m.originalColumn = source, originalLine, originalColumn
			if count == 5 {
				if name, err = mapDelta(name, fields[4]); err != nil {
					return nil, err
				}
				if name >= len(names) {
					return nil, errors.New("mapping references undeclared name")
				}
				m.name = *names[name]
			}
		}
		budget.segments++
		if budget.segments > maxMappingSegments {
			return nil, errors.New("source-map segment count exceeds limit")
		}
		result = append(result, m)
		if i < len(encoded) && encoded[i] == ',' {
			i++
			if i == len(encoded) || encoded[i] == ';' {
				return nil, errors.New("empty mapping segment")
			}
		}
	}
	return result, nil
}

func mapDelta(previous, delta int) (int, error) {
	v := int64(previous) + int64(delta)
	if v < 0 || v > math.MaxInt32 {
		return 0, errors.New("source-map coordinate/index overflow")
	}
	return int(v), nil
}

func decodeVLQ(s string, index *int) (int, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var value uint64
	shift := uint(0)
	for *index < len(s) {
		ch := s[*index]
		(*index)++
		digit := -1
		for j := 0; j < 64; j++ {
			if alphabet[j] == ch {
				digit = j
				break
			}
		}
		if digit < 0 || shift > 30 {
			return 0, errors.New("invalid or overflowing base64 VLQ")
		}
		value |= uint64(digit&31) << shift
		if value > math.MaxUint32 {
			return 0, errors.New("base64 VLQ exceeds 32 bits")
		}
		if digit&32 == 0 {
			if value == 1 {
				return math.MinInt32, nil
			}
			v := int(value >> 1)
			if value&1 != 0 {
				v = -v
			}
			return v, nil
		}
		shift += 5
	}
	return 0, errors.New("unterminated base64 VLQ")
}

type SourceMapLocateOptions struct {
	Line           int    `json:"line"`
	Column         int    `json:"column"`
	ExpectedSHA256 string `json:"expected_sha256,omitempty"`
}

type SourceMapLocation struct {
	Path                 string `json:"path"`
	SHA256               string `json:"sha256"`
	Line                 int    `json:"line"`
	Column               int    `json:"column"`
	Mapped               bool   `json:"mapped"`
	Reason               string `json:"unavailable_reason,omitempty"`
	MappingLine          int    `json:"mapping_line"`
	MappingColumn        int    `json:"mapping_column"`
	SourceIndex          int    `json:"source_index"`
	Source               string `json:"source,omitempty"`
	SourceRoot           string `json:"source_root,omitempty"`
	OriginalLine         int    `json:"original_line"`
	OriginalColumn       int    `json:"original_column"`
	Name                 string `json:"name,omitempty"`
	ContentAvailable     bool   `json:"content_available"`
	CoordinateConvention string `json:"coordinate_convention"`
	EvidenceAuthority    string `json:"evidence_authority"`
	ExecutionPerformed   bool   `json:"execution_performed"`
	NetworkInteraction   bool   `json:"network_interaction"`
}

func LocateSourceMap(path string, o SourceMapLocateOptions) (SourceMapLocation, error) {
	if o.Line < 0 || o.Column < 0 || o.Line > math.MaxInt32 || o.Column > math.MaxInt32 {
		return SourceMapLocation{}, errors.New("line/column must be zero-based 32-bit nonnegative coordinates")
	}
	body, absolute, digest, err := readBoundedFile(path, MaxSourceMapBytes)
	if err != nil {
		return SourceMapLocation{}, err
	}
	if err = checkExpectedSHA256(digest, o.ExpectedSHA256); err != nil {
		return SourceMapLocation{}, err
	}
	p, err := parseSourceMap(body)
	if err != nil {
		return SourceMapLocation{}, err
	}
	r := SourceMapLocation{Path: absolute, SHA256: digest, Line: o.Line, Column: o.Column, SourceIndex: -1, CoordinateConvention: "zero-based lines; UTF-16 columns for JavaScript/CSS", EvidenceAuthority: "artifact-declared-source-map"}
	i := sort.Search(len(p.segments), func(i int) bool {
		m := p.segments[i]
		return m.line > o.Line || m.line == o.Line && m.column > o.Column
	}) - 1
	if i < 0 || p.segments[i].line != o.Line {
		r.Reason = "no mapping segment on the requested generated line"
		return r, nil
	}
	m := p.segments[i]
	r.MappingLine, r.MappingColumn = m.line, m.column
	if m.source < 0 {
		r.Reason = "generated position falls in an explicitly unmapped region"
		return r, nil
	}
	r.Mapped = true
	r.SourceIndex = m.source
	r.Source = p.sources[m.source]
	r.SourceRoot = p.roots[m.source]
	r.OriginalLine = m.originalLine
	r.OriginalColumn = m.originalColumn
	r.Name = m.name
	r.ContentAvailable = m.source < len(p.contents) && p.contents[m.source] != nil
	return r, nil
}
