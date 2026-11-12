package appinspect

import (
	"errors"
	"fmt"
	"slices"
)

type AndroidResource struct {
	Index               int           `json:"resource_index"`
	ID                  uint32        `json:"resource_id"`
	PackageID           uint32        `json:"package_id"`
	PackageName         string        `json:"package_name"`
	TypeID              uint8         `json:"type_id"`
	TypeName            *string       `json:"type_name"`
	EntryIndex          uint32        `json:"entry_index"`
	KeyIndex            uint32        `json:"key_index"`
	KeyName             *string       `json:"key_name"`
	Flags               uint16        `json:"entry_flags"`
	Compact             bool          `json:"compact"`
	ConfigurationSHA256 string        `json:"configuration_sha256"`
	ConfigurationOffset int           `json:"configuration_offset"`
	ConfigurationBytes  int           `json:"configuration_bytes"`
	SourceOffset        int           `json:"source_offset"`
	SourceBytes         int           `json:"source_bytes"`
	Value               *AndroidValue `json:"value,omitempty"`
	ParentID            uint32        `json:"parent_id"`
	TotalMappings       int           `json:"total_mappings"`
}
type AndroidResourceMapping struct {
	Index int          `json:"mapping_index"`
	Name  uint32       `json:"name_resource_id"`
	Value AndroidValue `json:"value"`
}
type AndroidResourcesReport struct {
	TotalPackages               int                      `json:"total_packages"`
	TotalResourceConfigurations int                      `json:"total_resource_configurations"`
	TotalUnknownChunks          int                      `json:"total_unknown_chunks"`
	UnknownChunkTypes           []uint16                 `json:"unknown_chunk_types,omitempty"`
	Offset                      int                      `json:"offset"`
	NextOffset                  *int                     `json:"next_offset,omitempty"`
	Resources                   []AndroidResource        `json:"resources,omitempty"`
	SelectedResource            *AndroidResource         `json:"selected_resource,omitempty"`
	Mappings                    []AndroidResourceMapping `json:"mappings,omitempty"`
	CoverageComplete            bool                     `json:"coverage_complete"`
	EffectiveValuesResolved     bool                     `json:"effective_values_resolved"`
	Limitations                 []string                 `json:"limitations"`
}
type androidResourceReader struct {
	body     []byte
	budget   androidBudget
	global   *androidPool
	report   AndroidResourcesReport
	o        PageOptions
	detail   *int
	rowCount int
	mapCount uint64
}

type androidTypeSpec struct {
	entries        uint32
	configurations uint16 // Zero is the historical unspecified value.
}

func inspectAndroidResources(body []byte, o PageOptions, detail *int) (AndroidResourcesReport, error) {
	r := &androidResourceReader{body: body, o: o, detail: detail, report: AndroidResourcesReport{Limitations: []string{"resource IDs, keys, raw typed values, bag mappings and configuration hashes are declarations", "configuration qualifiers, overlays, dynamic package IDs, inherited symbol pools and reference/bag-parent effective values are not resolved", "all admitted type/entry/value tables are checked before returning a page; unknown auxiliary chunk payloads are reported without semantic acceptance", "no runtime resource selection, XML inflation, app install or target execution"}}}
	root, err := androidChunkAt(body, 0)
	if err != nil {
		return r.report, err
	}
	if root.kind != 2 || root.header < 12 || root.size != len(body) {
		return r.report, errors.New("Android resource-table root/header/size invalid")
	}
	declared := u32(root.body[8:])
	if declared > 256 {
		return r.report, errors.New("Android package count exceeds 256")
	}
	packages := []androidChunk{}
	unknown := map[uint16]bool{}
	for at := root.header; at < root.size; {
		c, err := androidChunkAt(body, at)
		if err != nil {
			return r.report, err
		}
		at += c.size
		switch c.kind {
		case 1:
			if r.global != nil || len(packages) > 0 {
				return r.report, errors.New("Android resource table duplicate/late global pool")
			}
			r.global, err = parseAndroidPool(c, body, &r.budget)
			if err != nil {
				return r.report, err
			}
		case 0x200:
			packages = append(packages, c)
			if len(packages) > 256 {
				return r.report, errors.New("Android resource package budget exceeded")
			}
		default:
			r.report.TotalUnknownChunks++
			unknown[c.kind] = true
		}
	}
	if len(packages) != int(declared) {
		return r.report, errors.New("Android resource package count mismatch")
	}
	r.report.TotalPackages = len(packages)
	seen := map[string]bool{}
	for _, c := range packages {
		if err := r.packageChunk(c, seen, unknown); err != nil {
			return r.report, err
		}
	}
	r.report.TotalResourceConfigurations = r.rowCount
	for typ := range unknown {
		r.report.UnknownChunkTypes = append(r.report.UnknownChunkTypes, typ)
	}
	slices.Sort(r.report.UnknownChunkTypes)
	if detail == nil {
		start, end, err := page(o, r.rowCount)
		if err != nil {
			return r.report, err
		}
		r.report.Offset = start
		r.report.CoverageComplete = start == 0 && end == r.rowCount
		if end < r.rowCount {
			r.report.NextOffset = &end
		}
	} else {
		if *detail < 0 || *detail >= r.rowCount || r.report.SelectedResource == nil {
			return r.report, errors.New("Android resource_index outside configuration inventory")
		}
		total := r.report.SelectedResource.TotalMappings
		start, end, err := page(o, total)
		if err != nil {
			return r.report, err
		}
		r.report.Offset = start
		r.report.CoverageComplete = start == 0 && end == total
		if end < total {
			r.report.NextOffset = &end
		}
	}
	return r.report, nil
}

func (r *androidResourceReader) packageChunk(c androidChunk, seen map[string]bool, unknown map[uint16]bool) error {
	if c.header < 284 {
		return errors.New("Android resource package header truncated")
	}
	b := c.body
	id := u32(b[8:])
	if id > 255 {
		return errors.New("Android package ID exceeds 8 bits")
	}
	units := []uint16{}
	terminated := false
	for pos := 12; pos < 268; pos += 2 {
		v := u16(b[pos:])
		if v == 0 {
			terminated = true
			break
		}
		units = append(units, v)
	}
	name, valid := androidUTF16Text(units)
	if !terminated || !valid {
		return errors.New("Android package name invalid UTF-16/terminator")
	}
	identity := fmt.Sprintf("%d:%s", id, name)
	if seen[identity] {
		return errors.New("duplicate Android package identity")
	}
	seen[identity] = true
	typeOffset := uint32(0)
	if c.header >= 288 {
		typeOffset = u32(b[284:])
		if typeOffset > 254 {
			return errors.New("Android type ID offset exceeds 8-bit domain")
		}
	}
	typesOff, keysOff := int(u32(b[268:])), int(u32(b[276:]))
	children := map[int]androidChunk{}
	order := []androidChunk{}
	for at := c.header; at < c.size; {
		child, err := androidChunkAt(b, at)
		if err != nil {
			return err
		}
		child.start += c.start
		children[at] = child
		order = append(order, child)
		at += child.size
		if len(order) > 100000 {
			return errors.New("Android package chunk inventory exceeds budget")
		}
	}
	var types, keys *androidPool
	var err error
	for off, dest := range map[int]**androidPool{typesOff: &types, keysOff: &keys} {
		if off == 0 {
			continue
		}
		child, ok := children[off]
		if !ok || child.kind != 1 {
			return errors.New("Android type/key pool offset is not a child string chunk")
		}
		*dest, err = parseAndroidPool(child, r.body, &r.budget)
		if err != nil {
			return err
		}
	}
	if typesOff != 0 && typesOff == keysOff {
		return errors.New("Android type/key symbol pools overlap")
	}
	specs := map[uint8]androidTypeSpec{}
	for _, child := range order {
		if child.kind != 0x202 {
			continue
		}
		h := child.body
		if child.header < 16 || h[8] == 0 || h[9] != 0 {
			return errors.New("Android type-spec header invalid")
		}
		count := u32(h[12:])
		if count > 65536 || uint64(child.header)+uint64(count)*4 > uint64(child.size) {
			return errors.New("Android type-spec flags outside chunk")
		}
		if _, ok := specs[h[8]]; ok {
			return errors.New("duplicate Android type spec")
		}
		specs[h[8]] = androidTypeSpec{entries: count, configurations: u16(h[10:])}
	}
	configurations := map[uint8]uint32{}
	for _, child := range order {
		switch child.kind {
		case 1:
			if child.start-c.start != typesOff && child.start-c.start != keysOff {
				return errors.New("unreferenced Android package string pool")
			}
		case 0x202:
		case 0x201:
			if err := r.typeChunk(child, id, name, typeOffset, types, keys, specs); err != nil {
				return err
			}
			configurations[child.body[8]]++
		default:
			r.report.TotalUnknownChunks++
			unknown[child.kind] = true
		}
	}
	for id, spec := range specs {
		if spec.configurations != 0 && uint32(spec.configurations) != configurations[id] {
			return errors.New("Android type-spec configuration count differs from type chunks")
		}
	}
	return nil
}

func (r *androidResourceReader) typeChunk(c androidChunk, pkg uint32, pkgName string, typeOffset uint32, types, keys *androidPool, specs map[uint8]androidTypeSpec) error {
	b := c.body
	if c.header < 24 || b[8] == 0 || u16(b[10:]) != 0 || b[9]&^byte(3) != 0 || b[9] == 3 {
		return errors.New("Android resource type header/flags invalid")
	}
	rawID := b[8]
	id := uint32(rawID) + typeOffset
	if id > 255 {
		return errors.New("Android resource type ID overflow")
	}
	count, start := u32(b[12:]), uint64(u32(b[16:]))
	cfg := uint64(u32(b[20:]))
	if cfg < 4 || cfg > 1024 || 20+cfg > uint64(c.header) {
		return errors.New("Android configuration size outside type header")
	}
	if count > 65536 {
		return errors.New("Android type index count exceeds 65536")
	}
	width := uint64(4)
	if b[9]&2 != 0 {
		width = 2
	}
	if start < uint64(c.header)+uint64(count)*width || start > uint64(c.size) {
		return errors.New("Android type entry offsets outside chunk")
	}
	var typeName *string
	if types != nil {
		v, err := types.name(uint32(rawID-1), false)
		if err != nil {
			return err
		}
		typeName = &v
	}
	configuration := b[20 : 20+cfg]
	cfgHash := digest(configuration)
	var previous uint32
	cache := map[uint32]AndroidResource{}
	for i := uint32(0); i < count; i++ {
		entryIndex := i
		offset := uint32(0)
		pos := c.header + int(i)*int(width)
		switch b[9] {
		case 1:
			entryIndex = uint32(u16(b[pos:]))
			offset = uint32(u16(b[pos+2:])) * 4
			if i > 0 && entryIndex <= previous {
				return errors.New("Android sparse entry indexes are duplicate/not sorted")
			}
			previous = entryIndex
		case 2:
			v := u16(b[pos:])
			if v == 0xffff {
				continue
			}
			offset = uint32(v) * 4
		default:
			offset = u32(b[pos:])
			if offset == 0xffffffff {
				continue
			}
		}
		if spec, ok := specs[rawID]; ok && entryIndex >= spec.entries {
			return errors.New("Android resource index exceeds type spec")
		}
		if entryIndex > 65535 {
			return errors.New("Android resource ID entry overflow")
		}
		at := start + uint64(offset)
		if offset%4 != 0 || at+8 > uint64(c.size) {
			return errors.New("Android resource entry offset outside data")
		}
		row, ok := cache[offset]
		if !ok {
			var err error
			row, _, err = r.entry(c, int(at), keys, false)
			if err != nil {
				return err
			}
			cache[offset] = row
		}
		row.Index = r.rowCount
		row.ID = pkg<<24 | id<<16 | entryIndex
		row.PackageID = pkg
		row.PackageName = pkgName
		row.TypeID = uint8(id)
		row.TypeName = typeName
		row.EntryIndex = entryIndex
		row.ConfigurationSHA256 = cfgHash
		row.ConfigurationOffset = c.start + 20
		row.ConfigurationBytes = int(cfg)
		r.rowCount++
		if r.rowCount > 8<<20 {
			return errors.New("Android resource work exceeds 8M entries")
		}
		if r.detail == nil {
			limit := r.o.Limit
			if limit == 0 {
				limit = 50
			}
			if row.Index >= r.o.Offset && row.Index < r.o.Offset+limit {
				r.report.Resources = append(r.report.Resources, row)
			}
		} else if row.Index == *r.detail {
			r.report.SelectedResource = &row
			_, maps, err := r.entry(c, int(at), keys, true)
			if err != nil {
				return err
			}
			r.report.Mappings = maps
		}
	}
	return nil
}

func (r *androidResourceReader) entry(c androidChunk, at int, keys *androidPool, collect bool) (AndroidResource, []AndroidResourceMapping, error) {
	b := c.body[at:]
	flags := u16(b[2:])
	row := AndroidResource{Flags: flags, SourceOffset: c.start + at}
	maps := []AndroidResourceMapping{}
	var size int
	key := u32(b[4:])
	if flags&8 != 0 {
		if flags&1 != 0 || flags&0x00f0 != 0 {
			return row, nil, errors.New("Android compact entry flags invalid")
		}
		size = 8
		key = uint32(u16(b))
		v := AndroidValue{Type: uint8(flags >> 8), Data: u32(b[4:])}
		if v.Type == 3 {
			var err error
			v.String, err = r.global.value(v.Data)
			if err != nil {
				return row, nil, err
			}
		}
		row.Value = &v
		row.Compact = true
	} else {
		size = int(u16(b))
		if flags&^uint16(7) != 0 || size < 8 || size%4 != 0 || size > len(b) {
			return row, nil, errors.New("Android full entry header/flags invalid")
		}
		if flags&1 == 0 {
			v, err := androidTypedValue(b[size:], r.global)
			if err != nil {
				return row, nil, err
			}
			row.Value = &v
			size += 8
		} else {
			if size < 16 {
				return row, nil, errors.New("Android complex entry header truncated")
			}
			row.ParentID = u32(b[8:])
			count := u32(b[12:])
			if uint64(size)+uint64(count)*12 > uint64(len(b)) {
				return row, nil, errors.New("Android complex mapping table outside entry")
			}
			if !collect {
				r.mapCount += uint64(count)
			}
			if r.mapCount > 8<<20 {
				return row, nil, errors.New("Android mapping work exceeds 8M")
			}
			row.TotalMappings = int(count)
			pageStart, pageEnd := 0, 0
			if collect {
				var err error
				pageStart, pageEnd, err = page(r.o, int(count))
				if err != nil {
					return row, nil, err
				}
			}
			for i := uint32(0); i < count; i++ {
				pos := size + int(i)*12
				v, err := androidTypedValue(b[pos+4:], r.global)
				if err != nil {
					return row, nil, err
				}
				if collect && int(i) >= pageStart && int(i) < pageEnd {
					maps = append(maps, AndroidResourceMapping{Index: int(i), Name: u32(b[pos:]), Value: v})
				}
			}
			size += int(count) * 12
		}
	}
	row.KeyIndex = key
	if keys != nil {
		v, err := keys.name(key, false)
		if err != nil {
			return row, nil, err
		}
		row.KeyName = &v
	}
	row.SourceBytes = size
	return row, maps, nil
}
