package appinspect

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"reverseresearch/internal/targetidentity"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Column layouts follow ECMA-335 II.22. Coded indexes retain their declared
// table/tag width; build-local tokens are never treated as native addresses.
var tableLayouts = []string{
	"2 s g g g", "cResolutionScope s s", "4 s s cTypeDefOrRef t4 t6", "t4", "2 s b", "t6", "4 2 2 s b t8", "t8", "2 2 s",
	"t2 cTypeDefOrRef", "cMemberRefParent s b", "2 cHasConstant b", "cHasCustomAttribute cCustomAttributeType b", "cHasFieldMarshal b", "2 cHasDeclSecurity b", "2 4 t2", "4 t4", "b", "t2 t20", "t20", "2 s cTypeDefOrRef", "t2 t23", "t23", "2 s b", "2 t6 cHasSemantics", "t2 cMethodDefOrRef cMethodDefOrRef", "s", "b", "2 cMemberForwarded s t26", "4 t4", "4 4", "4", "4 2 2 2 2 4 b s s", "4", "4 4 4", "2 2 2 2 4 b s s b", "4 t35", "4 4 4 t35", "4 s b", "4 4 s s cImplementation", "4 4 s cImplementation", "t2 t2", "2 2 cTypeOrMethodDef s", "cMethodDefOrRef b", "t42 cTypeDefOrRef",
}

type codedIndex struct {
	bits   uint
	tables []int
}

var codedIndexes = map[string]codedIndex{
	"ResolutionScope": {2, []int{0, 26, 35, 1}}, "TypeDefOrRef": {2, []int{2, 1, 27}}, "MemberRefParent": {3, []int{2, 1, 26, 6, 27}}, "HasConstant": {2, []int{4, 8, 23}},
	"HasCustomAttribute": {5, []int{6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42, 44, 43}}, "CustomAttributeType": {3, []int{-1, -1, 6, 10}},
	"HasFieldMarshal": {1, []int{4, 8}}, "HasDeclSecurity": {2, []int{2, 6, 32}}, "HasSemantics": {1, []int{20, 23}}, "MethodDefOrRef": {1, []int{6, 10}}, "MemberForwarded": {1, []int{4, 6}}, "Implementation": {2, []int{38, 35, 39}}, "TypeOrMethodDef": {1, []int{2, 6}},
}

type metadata struct {
	image        []byte
	file         *pe.File
	cliFlags     uint32
	version      string
	streams      map[string][]byte
	rows         [64]int
	starts       [64]int
	widths       [64][]int
	columns      [64][]string
	table        []byte
	nativeHeader bool
}

func u16(b []byte) uint16 { return binary.LittleEndian.Uint16(b) }
func u32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }
func (m *metadata) rva(rva, size uint32) ([]byte, error) {
	var result []byte
	matches := 0
	for _, s := range m.file.Sections {
		if uint64(rva) < uint64(s.VirtualAddress) {
			continue
		}
		delta := uint64(rva) - uint64(s.VirtualAddress)
		if delta >= uint64(max(s.VirtualSize, s.Size)) {
			continue
		}
		matches++
		if delta+uint64(size) > uint64(s.Size) || uint64(s.Offset)+delta+uint64(size) > uint64(len(m.image)) {
			return nil, errors.New("RVA range has no admitted file bytes")
		}
		result = m.image[uint64(s.Offset)+delta : uint64(s.Offset)+delta+uint64(size)]
	}
	if matches != 1 {
		return nil, errors.New("RVA mapping is missing or ambiguous")
	}
	return result, nil
}
func parseMetadata(body []byte) (*metadata, error) {
	if err := targetidentity.ValidateContainerBudget(bytes.NewReader(body), int64(len(body))); err != nil {
		return nil, err
	}
	f, err := pe.NewFile(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("PE: %w", err)
	}
	m := &metadata{image: body, file: f, streams: map[string][]byte{}}
	if len(f.Sections) > 4096 {
		return nil, errors.New("PE section inventory exceeds limit")
	}
	var dir pe.DataDirectory
	switch h := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if h.NumberOfRvaAndSizes > 14 {
			dir = h.DataDirectory[14]
		}
	case *pe.OptionalHeader64:
		if h.NumberOfRvaAndSizes > 14 {
			dir = h.DataDirectory[14]
		}
	default:
		return nil, errors.New("PE optional header is unavailable")
	}
	if dir.VirtualAddress == 0 && dir.Size == 0 {
		return m, nil
	}
	if dir.VirtualAddress == 0 || dir.Size < 72 {
		return nil, errors.New("invalid CLI directory")
	}
	cli, err := m.rva(dir.VirtualAddress, 72)
	if err != nil {
		return nil, err
	}
	if u32(cli[:4]) < 72 || u32(cli[:4]) > dir.Size {
		return nil, errors.New("invalid CLI header size")
	}
	m.cliFlags = u32(cli[16:20])
	m.nativeHeader = u32(cli[64:68]) != 0
	root, err := m.rva(u32(cli[8:12]), u32(cli[12:16]))
	if err != nil {
		return nil, err
	}
	if len(root) < 20 || string(root[:4]) != "BSJB" {
		return nil, errors.New("invalid CLI metadata root")
	}
	versionLength := int(u32(root[12:16]))
	if versionLength > 4096 || versionLength > len(root)-20 {
		return nil, errors.New("invalid metadata version size")
	}
	m.version = strings.TrimRight(string(root[16:16+versionLength]), "\x00")
	cursor := (16 + versionLength + 3) &^ 3
	if cursor > len(root)-4 {
		return nil, errors.New("truncated metadata stream count")
	}
	streamCount := int(u16(root[cursor+2 : cursor+4]))
	cursor += 4
	if streamCount > 64 {
		return nil, errors.New("metadata stream count exceeds limit")
	}
	type streamRange struct{ start, end int }
	var spans []streamRange
	for i := 0; i < streamCount; i++ {
		if cursor > len(root)-8 {
			return nil, errors.New("truncated stream header")
		}
		start, size := int(u32(root[cursor:cursor+4])), int(u32(root[cursor+4:cursor+8]))
		cursor += 8
		end := cursor
		for end < len(root) && end-cursor <= 32 && root[end] != 0 {
			end++
		}
		if end == len(root) || end-cursor > 32 {
			return nil, errors.New("invalid metadata stream name")
		}
		name := string(root[cursor:end])
		cursor = (end + 1 + 3) &^ 3
		if start > len(root) || size > len(root)-start {
			return nil, errors.New("metadata stream outside declared root")
		}
		if _, exists := m.streams[name]; exists {
			return nil, errors.New("duplicate metadata stream")
		}
		m.streams[name] = root[start : start+size]
		spans = append(spans, streamRange{start, start + size})
	}
	for i, a := range spans {
		if a.start < cursor {
			return nil, errors.New("metadata stream overlaps headers")
		}
		for j := 0; j < i; j++ {
			b := spans[j]
			if a.start < b.end && b.start < a.end {
				return nil, errors.New("metadata streams overlap")
			}
		}
	}
	table, ok := m.streams["#~"]
	if other, present := m.streams["#-"]; present {
		if ok {
			return nil, errors.New("ambiguous metadata table streams")
		}
		table = other
		ok = true
	}
	if !ok || len(table) < 24 {
		return nil, errors.New("metadata table stream missing or truncated")
	}
	m.table = table
	heapFlags := table[6]
	valid := binary.LittleEndian.Uint64(table[8:16])
	cursor = 24
	total := 0
	for i := 0; i < 64; i++ {
		if valid&(uint64(1)<<uint(i)) == 0 {
			continue
		}
		if i >= len(tableLayouts) {
			return nil, errors.New("metadata table kind is unsupported")
		}
		if cursor > len(table)-4 {
			return nil, errors.New("truncated metadata row count")
		}
		m.rows[i] = int(u32(table[cursor : cursor+4]))
		cursor += 4
		total += m.rows[i]
		if total > 1000000 {
			return nil, errors.New("metadata row inventory exceeds limit")
		}
	}
	if heapFlags&0x40 != 0 {
		cursor += 4
		if cursor > len(table) {
			return nil, errors.New("truncated metadata ExtraData")
		}
	}
	for t, layout := range tableLayouts {
		cols := strings.Fields(layout)
		if t == 2 {
			if m.rows[3] > 0 {
				cols[4] = "t3"
			}
			if m.rows[5] > 0 {
				cols[5] = "t5"
			}
		}
		if t == 6 && m.rows[7] > 0 {
			cols[5] = "t7"
		}
		if t == 18 && m.rows[19] > 0 {
			cols[1] = "t19"
		}
		if t == 21 && m.rows[22] > 0 {
			cols[1] = "t22"
		}
		m.columns[t] = cols
		rowSize := 0
		for _, col := range cols {
			width := 2
			switch col {
			case "2":
			case "4":
				width = 4
			case "s":
				if heapFlags&1 != 0 {
					width = 4
				}
			case "g":
				if heapFlags&2 != 0 {
					width = 4
				}
			case "b":
				if heapFlags&4 != 0 {
					width = 4
				}
			default:
				if col[0] == 't' {
					ref, _ := strconv.Atoi(col[1:])
					if m.rows[ref] >= 65536 {
						width = 4
					}
				} else {
					c := codedIndexes[col[1:]]
					for _, ref := range c.tables {
						if ref >= 0 && m.rows[ref] >= (1<<uint(16-c.bits)) {
							width = 4
							break
						}
					}
				}
			}
			m.widths[t] = append(m.widths[t], width)
			rowSize += width
		}
		m.starts[t] = cursor
		if m.rows[t] > (len(table)-cursor)/rowSize {
			return nil, errors.New("metadata table rows exceed stream bounds")
		}
		cursor += m.rows[t] * rowSize
	}
	if m.rows[0] != 1 || m.rows[32] > 1 || m.rows[6] > 100000 || m.rows[2] > 100000 {
		return nil, errors.New("invalid or oversized managed member inventory")
	}
	return m, nil
}
func (m *metadata) row(table, id int) ([]uint32, error) {
	if table < 0 || table >= 64 || id < 1 || id > m.rows[table] {
		return nil, errors.New("metadata row reference outside table")
	}
	rowSize := 0
	for _, w := range m.widths[table] {
		rowSize += w
	}
	pos := m.starts[table] + (id-1)*rowSize
	values := make([]uint32, len(m.widths[table]))
	for i, w := range m.widths[table] {
		if w == 2 {
			values[i] = uint32(u16(m.table[pos : pos+2]))
		} else {
			values[i] = u32(m.table[pos : pos+4])
		}
		pos += w
	}
	return values, nil
}
func (m *metadata) text(index uint32) (string, error) {
	if index == 0 {
		return "", nil
	}
	heap := m.streams["#Strings"]
	if uint64(index) >= uint64(len(heap)) {
		return "", errors.New("string heap index outside stream")
	}
	b := heap[index:]
	end := bytes.IndexByte(b, 0)
	if end < 0 || end > 4096 || !utf8.Valid(b[:end]) {
		return "", errors.New("metadata string is invalid or exceeds limit")
	}
	return string(b[:end]), nil
}
func (m *metadata) blob(index uint32) ([]byte, error) {
	if index == 0 {
		return nil, nil
	}
	heap := m.streams["#Blob"]
	if uint64(index) >= uint64(len(heap)) {
		return nil, errors.New("blob heap index outside stream")
	}
	b := heap[index:]
	size, n := 0, 1
	switch {
	case b[0]&0x80 == 0:
		size = int(b[0])
	case b[0]&0xc0 == 0x80:
		if len(b) < 2 {
			return nil, errors.New("truncated blob length")
		}
		n = 2
		size = int(b[0]&63)<<8 | int(b[1])
	case b[0]&0xe0 == 0xc0:
		if len(b) < 4 {
			return nil, errors.New("truncated blob length")
		}
		n = 4
		size = int(b[0]&31)<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	default:
		return nil, errors.New("invalid compressed blob length")
	}
	if size > len(b)-n {
		return nil, errors.New("blob exceeds heap bounds")
	}
	return b[n : n+size], nil
}
func (m *metadata) guid(index uint32) (string, error) {
	if index == 0 {
		return "", nil
	}
	pos := uint64(index-1) * 16
	b := m.streams["#GUID"]
	if pos+16 > uint64(len(b)) {
		return "", errors.New("GUID index outside heap")
	}
	v := b[pos : pos+16]
	return fmt.Sprintf("%08x-%04x-%04x-%x-%x", u32(v[:4]), u16(v[4:6]), u16(v[6:8]), v[8:10], v[10:]), nil
}
