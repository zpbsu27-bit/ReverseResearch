package iosinspect

import (
	"errors"
	"math/big"
	"strconv"
	"strings"
)

type KeyedArchiveOptions struct {
	InspectOptions
	Root string `json:"root,omitempty"`
}
type ArchiveReference struct {
	Path        string `json:"path"`
	PlistObject int    `json:"plist_object"`
	RawIndex    string `json:"raw_index,omitempty"`
	TargetIndex *int   `json:"target_index,omitempty"`
	Status      string `json:"status"`
}
type ArchiveObject struct {
	Index            int                `json:"index"`
	Kind             string             `json:"kind"`
	Value            PlistObject        `json:"value"`
	ClassIndex       *int               `json:"class_index,omitempty"`
	ClassName        string             `json:"class_name,omitempty"`
	ClassStatus      string             `json:"class_status,omitempty"`
	References       []ArchiveReference `json:"references"`
	TotalReferences  int                `json:"total_references"`
	CoverageComplete bool               `json:"coverage_complete"`
}
type ArchiveRoot struct {
	Name       string             `json:"name"`
	Value      PlistObject        `json:"value"`
	References []ArchiveReference `json:"references"`
}
type KeyedArchiveReport struct {
	Path                        string          `json:"path"`
	SHA256                      string          `json:"sha256"`
	Format                      string          `json:"format"`
	Version                     string          `json:"version"`
	Roots                       []ArchiveRoot   `json:"roots"`
	TotalObjects                int             `json:"total_objects"`
	TotalReferences             int             `json:"total_references"`
	Offset                      int             `json:"offset"`
	Objects                     []ArchiveObject `json:"objects"`
	NextOffset                  *int            `json:"next_offset,omitempty"`
	CoverageComplete            bool            `json:"coverage_complete"`
	ReferenceResolutionComplete bool            `json:"reference_resolution_complete"`
	ExecutionPerformed          bool            `json:"execution_performed"`
	Limitations                 []string        `json:"limitations"`
}

func (d plistDocument) field(id int, key string) (int, bool) {
	n := d.nodes[id]
	if n.kind != "dictionary" {
		return 0, false
	}
	for i, k := range n.keys {
		if d.nodes[k].text == key {
			return n.refs[i], true
		}
	}
	return 0, false
}

func (d plistDocument) archiveUID(id int) (string, bool) {
	n := d.nodes[id]
	if n.kind == "uid" {
		return n.text, true
	}
	// XML archives use an exact one-key CF$UID dictionary. A general dictionary
	// whose field happens to be named UID is not reclassified as a reference.
	if n.kind == "dictionary" && len(n.keys) == 1 && d.nodes[n.keys[0]].text == "CF$UID" {
		v := d.nodes[n.refs[0]]
		if v.kind != "integer" {
			return "", true
		}
		return v.text, true
	}
	return "", false
}
func pointerPart(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}

func InspectKeyedArchive(p string, o KeyedArchiveOptions) (KeyedArchiveReport, error) {
	b, abs, hash, err := captureApple(p, o.ExpectedSHA256)
	if err != nil {
		return KeyedArchiveReport{}, err
	}
	d, err := parsePlist(b)
	if err != nil {
		return KeyedArchiveReport{}, err
	}
	archiver, ok := d.field(d.root, "$archiver")
	if !ok || d.nodes[archiver].kind != "string" || d.nodes[archiver].text != "NSKeyedArchiver" {
		return KeyedArchiveReport{}, errors.New("selected plist is not an NSKeyedArchiver archive")
	}
	objects, ok := d.field(d.root, "$objects")
	if !ok || d.nodes[objects].kind != "array" {
		return KeyedArchiveReport{}, errors.New("keyed archive has no $objects array")
	}
	table := d.nodes[objects].refs
	top, ok := d.field(d.root, "$top")
	if !ok || d.nodes[top].kind != "dictionary" || len(d.nodes[top].keys) == 0 {
		return KeyedArchiveReport{}, errors.New("keyed archive has no named $top roots")
	}
	version, ok := d.field(d.root, "$version")
	if !ok || d.nodes[version].kind != "integer" {
		return KeyedArchiveReport{}, errors.New("keyed archive has no integer $version")
	}
	if len(table) == 0 || len(d.nodes[top].keys) > 200 {
		return KeyedArchiveReport{}, errors.New("empty archive object table or root count exceeds 200")
	}
	r := KeyedArchiveReport{Path: abs, SHA256: hash, Format: d.format, Version: d.nodes[version].text, TotalObjects: len(table), Roots: []ArchiveRoot{}, Objects: []ArchiveObject{}, ReferenceResolutionComplete: true, Limitations: []string{"archive identity is the original $objects index; class names and links are unauthenticated serialized declarations", "root selection filters named roots; paging always uses the original full object table", "inline values reference the shared plist object table; cycles between archive UIDs are preserved, never expanded", "no Foundation class instantiation, UIKit construction, runtime execution or completion acceptance"}}
	steps, pathBytes := 0, 0
	// $objects may repeat a single large data/string/container object. Cache its
	// projection so hashing source bytes is bounded by the unique plist table.
	projections := map[int]PlistObject{}
	project := func(id int) PlistObject {
		if v, ok := projections[id]; ok {
			return v
		}
		v := d.object(id)
		projections[id] = v
		return v
	}
	var scan func(int) ([]ArchiveReference, error)
	scan = func(initial int) ([]ArchiveReference, error) {
		type item struct {
			id    int
			path  string
			depth int
		}
		pending := []item{{id: initial}}
		refs := []ArchiveReference{}
		for len(pending) > 0 {
			p := pending[len(pending)-1]
			pending = pending[:len(pending)-1]
			steps++
			if steps > 1000000 || p.depth > 128 || len(p.path) > 16384 {
				return nil, errors.New("keyed archive inline expansion/path budget exceeded")
			}
			if raw, isUID := d.archiveUID(p.id); isUID {
				v := ArchiveReference{Path: p.path, PlistObject: p.id, RawIndex: raw, Status: "malformed"}
				index, valid := new(big.Int).SetString(raw, 10)
				if valid && index.Sign() >= 0 {
					v.Status = "unresolved"
					if index.IsUint64() && index.Uint64() < uint64(len(table)) {
						i := int(index.Uint64())
						v.TargetIndex = &i
						v.Status = "resolved"
						if i == 0 && d.nodes[table[0]].kind == "string" && d.nodes[table[0]].text == "$null" {
							v.Status = "nil"
						}
					}
				}
				if v.Status == "unresolved" || v.Status == "malformed" {
					r.ReferenceResolutionComplete = false
				}
				r.TotalReferences++
				if r.TotalReferences > maxPlistReferences {
					return nil, errors.New("keyed archive exceeds reference budget")
				}
				refs = append(refs, v)
				continue
			}
			n := d.nodes[p.id]
			for j := len(n.refs) - 1; j >= 0; j-- {
				part := strconv.Itoa(j)
				if n.kind == "dictionary" {
					part = pointerPart(d.nodes[n.keys[j]].text)
				}
				pathBytes += len(p.path) + len(part) + 65
				if pathBytes > 32<<20 {
					return nil, errors.New("keyed archive path storage budget exceeded")
				}
				pending = append(pending, item{n.refs[j], p.path + "/" + part, p.depth + 1})
			}
		}
		return refs, nil
	}
	selectedRoot := o.Root == ""
	for j, k := range d.nodes[top].keys {
		name := d.nodes[k].text
		refs, err := scan(d.nodes[top].refs[j])
		if err != nil {
			return r, err
		}
		if o.Root == "" || name == o.Root {
			selectedRoot = true
			root := ArchiveRoot{Name: name, Value: project(d.nodes[top].refs[j]), References: refs}
			if len(refs) > 100 {
				return r, errors.New("selected archive root exceeds 100 inline references")
			}
			r.Roots = append(r.Roots, root)
		}
	}
	if !selectedRoot {
		return r, errors.New("selected named archive root does not exist")
	}
	all := make([]ArchiveObject, len(table))
	for i, id := range table {
		refs, err := scan(id)
		if err != nil {
			return r, err
		}
		value := project(id)
		v := ArchiveObject{Index: i, Kind: d.nodes[id].kind, Value: value, References: refs[:min(len(refs), 100)], TotalReferences: len(refs), CoverageComplete: value.ValueComplete && len(refs) <= 100}
		if i == 0 && d.nodes[id].kind == "string" && d.nodes[id].text == "$null" {
			v.Kind = "nil"
		}
		if classID, ok := d.field(id, "$class"); ok {
			v.Kind = "archived-object"
			v.ClassStatus = "malformed-class-reference"
			raw, isUID := d.archiveUID(classID)
			index, valid := new(big.Int).SetString(raw, 10)
			if isUID && valid && index.Sign() >= 0 {
				v.ClassStatus = "unresolved-class"
				if index.IsUint64() && index.Uint64() < uint64(len(table)) {
					ci := int(index.Uint64())
					v.ClassIndex = &ci
					v.ClassStatus = "unknown-class"
					if name, ok := d.field(table[ci], "$classname"); ok && d.nodes[name].kind == "string" {
						v.ClassName = project(name).Text
						v.ClassStatus = "declared"
						v.CoverageComplete = v.CoverageComplete && project(name).ValueComplete
					}
				}
			}
		} else if _, ok := d.field(id, "$classname"); ok {
			v.Kind = "class-descriptor"
		}
		all[i] = v
	}
	start, end, err := selection(o.InspectOptions, len(all))
	if err != nil {
		return r, err
	}
	r.Offset = start
	r.Objects = all[start:end]
	r.CoverageComplete = start == 0 && end == len(all) && o.Root == ""
	for _, v := range r.Objects {
		r.CoverageComplete = r.CoverageComplete && v.CoverageComplete
	}
	if end < len(all) {
		r.NextOffset = &end
	}
	return r, boundedProjection(r)
}
