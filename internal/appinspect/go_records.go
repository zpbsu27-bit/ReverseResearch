package appinspect

import (
	"bytes"
	"encoding/base64"
	"errors"
	"runtime/debug"
	"strings"
	"unicode/utf8"
)

const maxGoRecordCount = 65536

type GoRecordField struct {
	Name             string  `json:"name"`
	Bytes            int     `json:"bytes"`
	SHA256           string  `json:"sha256"`
	UTF8             bool    `json:"utf8"`
	TextPreview      *string `json:"text_preview"`
	DataPrefixBase64 string  `json:"data_prefix_base64"`
	PreviewComplete  bool    `json:"preview_complete"`
}

type GoModuleRecord struct {
	Index              int             `json:"index"`
	Kind               string          `json:"kind"`
	Status             string          `json:"status"`
	Reason             string          `json:"reason,omitempty"`
	BodyOffset         int             `json:"body_offset"`
	Range              GoMetadataRange `json:"source_range"`
	RawSHA256          string          `json:"raw_sha256"`
	RawUTF8            bool            `json:"raw_utf8"`
	RawPrefixBase64    string          `json:"raw_prefix_base64"`
	RawPreviewComplete bool            `json:"raw_preview_complete"`
	Terminated         bool            `json:"terminated"`
	ReplacementOf      *int            `json:"replacement_of,omitempty"`
	Fields             []GoRecordField `json:"fields,omitempty"`
}

type goModuleRecord struct {
	row    GoModuleRecord
	fields map[string][]byte
}

type goModuleObservation struct {
	info               debug.BuildInfo
	pathSeen, mainSeen bool
	rows               []goModuleRecord
	unparsed           int
	textComplete       bool
	settingsObserved   int
}

// Framing identifies exact sentinels, independently of whether the enclosed
// module grammar is valid, newline terminated, or empty.
func (g *goMetadata) moduleBody() ([]byte, GoMetadataRange, bool) {
	if len(g.module) == 0 {
		return g.module, g.mr, true
	}
	if len(g.module) < 32 || !bytes.Equal(g.module[:16], goModuleStart) || !bytes.Equal(g.module[len(g.module)-16:], goModuleEnd) {
		return nil, GoMetadataRange{}, false
	}
	r := g.mr
	r.Offset += 16
	r.Size -= 32
	return g.module[16 : len(g.module)-16], r, true
}

func goRecordField(name string, value []byte) GoRecordField {
	f := GoRecordField{Name: name, Bytes: len(value), SHA256: digest(value), UTF8: utf8.Valid(value), PreviewComplete: len(value) <= 256}
	n := min(len(value), 256)
	f.DataPrefixBase64 = base64.StdEncoding.EncodeToString(value[:n])
	if f.UTF8 {
		for !utf8.Valid(value[:n]) {
			n--
		}
		s := string(value[:n])
		f.TextPreview = &s
	}
	return f
}

// The pinned standard-library grammar parses each admitted record. This owner
// preserves every original line and association; summaries and byte reads are
// projections of the same observation, never a second module parser.
func parseGoModuleRecords(body []byte, source GoMetadataRange) (*goModuleObservation, error) {
	if len(body) > 1<<20 || source.Size != uint64(len(body)) {
		return nil, errors.New("Go module record byte budget/range differs")
	}
	o := &goModuleObservation{textComplete: true}
	o.info.Deps, o.info.Settings = []*debug.Module{}, []debug.BuildSetting{}
	var last *debug.Module
	lastRow, lastSource := -1, ""
	for start := 0; start < len(body); {
		if len(o.rows) >= maxGoRecordCount {
			return nil, errors.New("Go module record inventory exceeds 65536")
		}
		n := bytes.IndexByte(body[start:], '\n')
		end, terminated := len(body), n >= 0
		if terminated {
			end = start + n + 1
		}
		raw := body[start:end]
		line := raw
		if terminated {
			line = line[:len(line)-1]
		}
		r := goModuleRecord{row: GoModuleRecord{Index: len(o.rows), Kind: "unknown", Status: "unparsed", BodyOffset: start, Range: GoMetadataRange{Offset: source.Offset + uint64(start), Size: uint64(len(raw)), Basis: source.Basis}, RawSHA256: digest(raw), RawUTF8: utf8.Valid(raw), RawPrefixBase64: base64.StdEncoding.EncodeToString(raw[:min(len(raw), 256)]), RawPreviewComplete: len(raw) <= 256, Terminated: terminated}, fields: map[string][]byte{}}
		kind := ""
		for prefix, name := range map[string]string{"path\t": "package", "mod\t": "module", "dep\t": "dependency", "=>\t": "replacement", "build\t": "setting"} {
			if bytes.HasPrefix(line, []byte(prefix)) {
				kind = name
				break
			}
		}
		if kind != "" {
			r.row.Kind = kind
		}
		add := func(name, value string) {
			r.fields[name] = []byte(value)
			f := goRecordField(name, []byte(value))
			r.row.Fields = append(r.row.Fields, f)
			if !f.UTF8 {
				o.textComplete = false
			}
		}
		if len(line) == 0 {
			r.row.Kind, r.row.Status = "blank", "ignored"
		} else if !terminated {
			r.row.Reason = "unterminated record"
			if kind == "module" || kind == "dependency" || kind == "replacement" {
				last = nil
			}
		} else if !utf8.Valid(line) {
			r.row.Reason = "non-UTF8 original line"
			if kind == "module" || kind == "dependency" || kind == "replacement" {
				last = nil
			}
		} else if kind == "" {
			r.row.Reason = "unrecognized record prefix"
		} else if kind == "package" && o.pathSeen || kind == "module" && o.mainSeen {
			r.row.Reason = "duplicate package/main record preserved, not overwritten"
			if kind == "module" {
				last = nil
			}
		} else if kind == "replacement" && last == nil {
			r.row.Reason = "replacement has no valid unpaired module"
		} else {
			parseSource := string(raw)
			if kind == "replacement" {
				parseSource = lastSource + parseSource
			}
			info, err := debug.ParseBuildInfo(parseSource)
			if kind == "module" || kind == "dependency" {
				last = nil
			}
			if err != nil {
				r.row.Reason = "invalid " + kind + " grammar"
				if kind == "replacement" {
					last = nil
				}
			} else {
				r.row.Status = "parsed"
				switch kind {
				case "package":
					o.pathSeen = true
					o.info.Path = info.Path
					add("path", info.Path)
				case "module", "dependency":
					m := info.Main
					if kind == "dependency" {
						m = *info.Deps[0]
						o.info.Deps = append(o.info.Deps, &m)
						last = &m
					} else {
						o.info.Main = m
						o.mainSeen = true
						last = &o.info.Main
					}
					add("path", m.Path)
					add("version", m.Version)
					if len(strings.Split(string(line)[4:], "\t")) == 3 {
						add("sum", m.Sum)
					}
					lastRow, lastSource = r.row.Index, string(raw)
				case "replacement":
					m := info.Main.Replace
					if strings.HasPrefix(lastSource, "dep\t") {
						m = info.Deps[0].Replace
					}
					last.Replace = m
					antecedent := lastRow
					r.row.ReplacementOf = &antecedent
					add("path", m.Path)
					add("version", m.Version)
					add("sum", m.Sum)
					last = nil
				case "setting":
					setting := info.Settings[0]
					add("key", setting.Key)
					add("value", setting.Value)
					o.settingsObserved++
					if utf8.ValidString(setting.Key) && utf8.ValidString(setting.Value) {
						o.info.Settings = append(o.info.Settings, setting)
					}
				}
			}
		}
		if r.row.Status == "unparsed" {
			o.unparsed++
			o.textComplete = false
		}
		o.rows = append(o.rows, r)
		start = end
	}
	return o, nil
}
