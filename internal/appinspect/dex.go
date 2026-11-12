package appinspect

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"hash/adler32"
	"slices"
	"strings"
)

const dexNoIndex = uint32(0xffffffff)

type DEXOptions struct {
	PageOptions
	Entry       string `json:"entry,omitempty"`
	View        string `json:"view,omitempty"`
	StringIndex *int   `json:"string_index,omitempty"`
	MethodIndex *int   `json:"method_index,omitempty"`
}

type DEXClass struct {
	Index           int      `json:"class_def_index"`
	TypeIndex       uint32   `json:"type_index"`
	Descriptor      string   `json:"descriptor"`
	AccessFlags     uint32   `json:"access_flags"`
	Superclass      *string  `json:"superclass"`
	Interfaces      []string `json:"interfaces"`
	SourceFileIndex *uint32  `json:"source_file_string_index"`
	ClassDataOffset uint32   `json:"class_data_offset"`
	StaticFields    uint32   `json:"static_fields"`
	InstanceFields  uint32   `json:"instance_fields"`
	DirectMethods   uint32   `json:"direct_methods"`
	VirtualMethods  uint32   `json:"virtual_methods"`
}

type DEXMethod struct {
	Index              int    `json:"method_index"`
	Class              string `json:"class"`
	Name               string `json:"name"`
	Descriptor         string `json:"descriptor"`
	Defined            bool   `json:"defined_in_class_data"`
	AccessFlags        uint32 `json:"access_flags"`
	NativeDeclared     bool   `json:"native_declared"`
	MethodKind         string `json:"method_kind"`
	CodeOffset         uint32 `json:"code_offset"`
	CodeUnits          uint32 `json:"code_units"`
	InstructionsSHA256 string `json:"instructions_sha256,omitempty"`
}

type DEXString struct {
	Index           int     `json:"string_index"`
	UTF16Units      uint32  `json:"utf16_units"`
	UTF8Available   bool    `json:"utf8_available"`
	TextPreview     *string `json:"text_preview"`
	PreviewComplete bool    `json:"preview_complete"`
	ItemOffset      uint32  `json:"item_offset"`
	ItemBytes       uint32  `json:"item_bytes"`
	ItemSHA256      string  `json:"item_sha256"`
}

type DEXReport struct {
	Path               string           `json:"path"`
	SHA256             string           `json:"sha256"`
	Entry              *ZIPEntry        `json:"entry,omitempty"`
	ContentSHA256      string           `json:"content_sha256"`
	CRCVerified        bool             `json:"crc_verified"`
	Version            string           `json:"dex_version"`
	View               string           `json:"view"`
	TotalStrings       int              `json:"total_strings"`
	TotalTypes         int              `json:"total_types"`
	TotalPrototypes    int              `json:"total_prototypes"`
	TotalFields        int              `json:"total_fields"`
	TotalMethods       int              `json:"total_method_references"`
	DefinedMethods     int              `json:"total_defined_methods"`
	TotalClasses       int              `json:"total_class_definitions"`
	Offset             int              `json:"offset"`
	NextOffset         *int             `json:"next_offset,omitempty"`
	Classes            []DEXClass       `json:"classes,omitempty"`
	Methods            []DEXMethod      `json:"methods,omitempty"`
	Strings            []DEXString      `json:"strings,omitempty"`
	Method             *DEXMethod       `json:"method,omitempty"`
	CodeAvailable      bool             `json:"code_available"`
	Registers          uint16           `json:"registers,omitempty"`
	IncomingRegisters  uint16           `json:"incoming_registers,omitempty"`
	OutgoingRegisters  uint16           `json:"outgoing_registers,omitempty"`
	TotalInstructions  int              `json:"total_instructions,omitempty"`
	TotalBlocks        int              `json:"total_blocks,omitempty"`
	TotalEdges         int              `json:"total_edges,omitempty"`
	Instructions       []DEXInstruction `json:"instructions,omitempty"`
	Blocks             []DEXBlock       `json:"blocks,omitempty"`
	Edges              []DEXEdge        `json:"edges,omitempty"`
	StringIndex        *int             `json:"string_index,omitempty"`
	ReadBytes          int              `json:"read_bytes,omitempty"`
	DataBase64         string           `json:"data_base64,omitempty"`
	ChecksumVerified   bool             `json:"checksum_verified"`
	SignatureVerified  bool             `json:"header_sha1_verified"`
	CoverageComplete   bool             `json:"coverage_complete"`
	ExecutionPerformed bool             `json:"execution_performed"`
	NetworkInteraction bool             `json:"network_interaction"`
	EvidenceAuthority  string           `json:"evidence_authority"`
	Limitations        []string         `json:"limitations"`
}

type dexString struct {
	text      string
	units     uint32
	utf8      bool
	off, size uint32
}
type dexProto struct {
	result     uint32
	parameters []uint16
}
type dexField struct {
	class, typ uint16
	name       uint32
}
type dexMethod struct {
	class, proto      uint16
	name, flags, code uint32
	defined           bool
	kind              string
}
type dexCode struct {
	units                         uint32
	hash                          string
	registers, incoming, outgoing uint16
	tries                         []dexTry
}
type dexTable struct{ count, off, width uint32 }
type dexImage struct {
	body                                  []byte
	version                               string
	dataStart, dataEnd                    uint32
	strings                               []dexString
	types                                 []string
	protos                                []dexProto
	fields                                []dexField
	methods                               []dexMethod
	classes                               []DEXClass
	codes                                 map[uint32]dexCode
	lists                                 map[uint32][]uint16
	decodedBudget, listBudget, codeBudget uint64
	referenceBudget                       uint64
	optionalIDs                           map[uint16]uint32
}

func InspectDEX(p string, o DEXOptions) (DEXReport, error) {
	if o.View == "" {
		o.View = "classes"
	}
	methodView := o.View == "instructions" || o.View == "cfg" || o.View == "edges"
	if o.View != "classes" && o.View != "methods" && o.View != "strings" && o.View != "string-bytes" && !methodView {
		return DEXReport{}, errors.New("DEX view must be classes, methods, strings, string-bytes, instructions, cfg or edges")
	}
	if methodView != (o.MethodIndex != nil) {
		return DEXReport{}, errors.New("instruction/CFG views require method_index; other views do not accept it")
	}
	if (o.View == "string-bytes") != (o.StringIndex != nil) {
		return DEXReport{}, errors.New("string-bytes requires string_index; other views do not accept it")
	}
	if o.Offset > 0 && o.ExpectedSHA256 == "" {
		return DEXReport{}, errors.New("subsequent DEX pages require expected_sha256")
	}
	body, abs, hash, err := readArtifact(p, MaxArtifactBytes, o.ExpectedSHA256)
	if err != nil {
		return DEXReport{}, err
	}
	r := DEXReport{Path: abs, SHA256: hash, View: o.View, EvidenceAuthority: "build-local DEX declarations and byte ranges", Limitations: []string{"method_ids contains references; only class_data declares definitions and access flags", "header SHA-1 and Adler32 are format integrity checks, not an authenticated signer", "supported standalone DEX 035/037/038/039/040 little-endian metadata; no DEX 041 container or CompactDex", "code envelopes are bounded; instruction semantics, annotations, debug information, encoded static values and call-site behavior are not fully verified", "no APK signature verification, extraction, class loading, decompilation, JNI-call proof or target execution"}}
	if o.Entry != "" {
		files, entries, e := parseZIP(body)
		if e != nil {
			return r, e
		}
		found := false
		for i, entry := range entries {
			if entry.Path == o.Entry {
				body, err = readZIPContent(files[i], entry, MaxArtifactBytes)
				if err != nil {
					return r, err
				}
				r.Entry = &entry
				r.CRCVerified = true
				found = true
				break
			}
		}
		if !found {
			return r, errors.New("DEX ZIP member not found")
		}
	}
	r.ContentSHA256 = digest(body)
	d, err := parseDEX(body)
	if err != nil {
		return r, err
	}
	r.Version = d.version
	r.ChecksumVerified = true
	r.SignatureVerified = true
	r.TotalStrings = len(d.strings)
	r.TotalTypes = len(d.types)
	r.TotalPrototypes = len(d.protos)
	r.TotalFields = len(d.fields)
	r.TotalMethods = len(d.methods)
	r.TotalClasses = len(d.classes)
	for _, m := range d.methods {
		if m.defined {
			r.DefinedMethods++
		}
	}
	if methodView {
		return d.codeReport(r, o)
	}
	if o.View == "string-bytes" {
		i := *o.StringIndex
		if i < 0 || i >= len(d.strings) {
			return r, errors.New("DEX string index outside inventory")
		}
		s := d.strings[i]
		limit := o.Limit
		if limit == 0 {
			limit = 8192
		}
		if o.Offset < 0 || o.Offset > int(s.size) || limit < 1 || limit > 16384 {
			return r, errors.New("DEX string byte offset outside item or limit outside 1..16384")
		}
		end := min(int(s.size), o.Offset+limit)
		r.Offset = o.Offset
		r.StringIndex = &i
		r.ReadBytes = end - o.Offset
		r.DataBase64 = base64.StdEncoding.EncodeToString(body[int(s.off)+o.Offset : int(s.off)+end])
		r.CoverageComplete = o.Offset == 0 && end == int(s.size)
		if end < int(s.size) {
			r.NextOffset = &end
		}
	} else {
		total := len(d.classes)
		if o.View == "methods" {
			total = len(d.methods)
		}
		if o.View == "strings" {
			total = len(d.strings)
		}
		start, end, e := page(o.PageOptions, total)
		if e != nil {
			return r, e
		}
		r.Offset = start
		r.CoverageComplete = start == 0 && end == total
		if end < total {
			r.NextOffset = &end
		}
		for i := start; i < end; i++ {
			switch o.View {
			case "classes":
				r.Classes = append(r.Classes, d.classes[i])
			case "methods":
				m, err := d.methodReport(i)
				if err != nil {
					return r, err
				}
				r.Methods = append(r.Methods, m)
			case "strings":
				s := d.strings[i]
				var text *string
				complete := false
				if s.utf8 {
					v := s.text
					runes := []rune(v)
					complete = len(runes) <= 1024
					if !complete {
						v = string(runes[:1024])
					}
					text = &v
				}
				r.Strings = append(r.Strings, DEXString{Index: i, UTF16Units: s.units, UTF8Available: s.utf8, TextPreview: text, PreviewComplete: complete, ItemOffset: s.off, ItemBytes: s.size, ItemSHA256: digest(body[s.off : s.off+s.size])})
			}
		}
	}
	return r, projectionLimit(r)
}

func (d *dexImage) take(off uint32, count uint64, width uint32, align uint32, data bool) ([]byte, error) {
	end := uint64(off) + count*uint64(width)
	if align > 0 && off%align != 0 || end > uint64(len(d.body)) || (data && (off < d.dataStart || end > uint64(d.dataEnd))) {
		return nil, errors.New("DEX declared range/alignment outside admitted bytes")
	}
	return d.body[uint64(off):end], nil
}

func dexULEB(body []byte, at *uint32, end uint32) (uint32, error) {
	var value uint32
	for i := 0; i < 5; i++ {
		if *at >= end {
			return 0, errors.New("truncated DEX ULEB128")
		}
		b := body[*at]
		*at++
		if i == 4 && b&0xf0 != 0 {
			return 0, errors.New("DEX ULEB128 overflow")
		}
		value |= uint32(b&0x7f) << uint(7*i)
		if b&0x80 == 0 {
			return value, nil
		}
	}
	return 0, errors.New("DEX ULEB128 exceeds 5 bytes")
}

func dexSLEB(body []byte, at *uint32, end uint32) (int32, error) {
	var v uint32
	for i := 0; i < 5; i++ {
		if *at >= end {
			return 0, errors.New("truncated DEX SLEB128")
		}
		b := body[*at]
		*at++
		if i == 4 && b&0x78 != 0 && b&0x78 != 0x78 {
			return 0, errors.New("DEX SLEB128 overflow")
		}
		v |= uint32(b&0x7f) << uint(7*i)
		if b&0x80 == 0 {
			if i < 4 && b&0x40 != 0 {
				v |= ^uint32(0) << uint(7*(i+1))
			}
			return int32(v), nil
		}
	}
	return 0, errors.New("DEX SLEB128 exceeds 5 bytes")
}

func (d *dexImage) readString(off uint32) (dexString, []uint16, error) {
	if off < d.dataStart || off >= d.dataEnd {
		return dexString{}, nil, errors.New("DEX string offset outside data")
	}
	at := off
	n, err := dexULEB(d.body, &at, d.dataEnd)
	if err != nil {
		return dexString{}, nil, err
	}
	if n > 1<<20 {
		return dexString{}, nil, errors.New("DEX string exceeds 1M UTF-16 units")
	}
	d.decodedBudget += uint64(n) * 2
	if d.decodedBudget > 32<<20 {
		return dexString{}, nil, errors.New("DEX decoded string budget exceeds 32 MiB")
	}
	// A code unit needs at most three bytes. Bound the terminator scan by the
	// declaration, so malformed aliases cannot repeatedly scan the whole DEX.
	end := min(int(d.dataEnd), int(at)+int(n)*3+1)
	length := bytes.IndexByte(d.body[at:end], 0)
	if length < 0 {
		return dexString{}, nil, errors.New("unterminated or oversized DEX MUTF-8 string")
	}
	units, err := decodeAndroidUTF8(d.body[at:int(at)+length], int(n), false)
	if err != nil {
		return dexString{}, nil, fmt.Errorf("DEX MUTF-8: %w", err)
	}
	text, valid := androidUTF16Text(units)
	return dexString{text: text, units: n, utf8: valid, off: off, size: at + uint32(length) + 1 - off}, units, nil
}

func dexSimpleName(s, version string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || strings.ContainsRune("$_-", r) ||
			r >= 0x00a1 && r <= 0x1fff || r >= 0x2010 && r <= 0x2027 || r >= 0x2030 && r <= 0xd7ff || r >= 0xe000 && r <= 0xffef || r >= 0x10000 && r <= 0x10ffff {
			continue
		}
		if version >= "040" && (r == ' ' || r == 0xa0 || r >= 0x2000 && r <= 0x200a || r == 0x202f) {
			continue
		}
		return false
	}
	return true
}

func dexTypeValid(s, version string) bool {
	depth := 0
	for depth < len(s) && s[depth] == '[' {
		depth++
	}
	if depth > 255 || depth >= len(s) {
		return false
	}
	s = s[depth:]
	if len(s) == 1 {
		return strings.Contains("BCDFIJSZ", s) || (depth == 0 && s == "V")
	}
	if len(s) < 3 || s[0] != 'L' || s[len(s)-1] != ';' {
		return false
	}
	name := s[1 : len(s)-1]
	for _, part := range strings.Split(name, "/") {
		if !dexSimpleName(part, version) {
			return false
		}
	}
	return true
}
func dexClassType(s string) bool { return len(s) > 2 && s[0] == 'L' }
func dexShorty(s string) byte {
	if len(s) > 1 {
		return 'L'
	}
	return s[0]
}

func (d *dexImage) typeList(off uint32) ([]uint16, error) {
	if off == 0 {
		return nil, nil
	}
	if v, ok := d.lists[off]; ok {
		return v, nil
	}
	h, err := d.take(off, 1, 4, 4, true)
	if err != nil {
		return nil, err
	}
	n := u32(h)
	if n > 65536 {
		return nil, errors.New("DEX type list exceeds 65536")
	}
	d.listBudget += uint64(n) * 2
	if d.listBudget > 16<<20 {
		return nil, errors.New("DEX type list budget exceeds 16 MiB")
	}
	b, err := d.take(off+4, uint64(n), 2, 0, true)
	if err != nil {
		return nil, err
	}
	v := make([]uint16, int(n))
	for i := range v {
		v[i] = u16(b[i*2:])
		if int(v[i]) >= len(d.types) {
			return nil, errors.New("DEX type list index outside table")
		}
	}
	d.lists[off] = v
	return v, nil
}

func parseDEX(body []byte) (*dexImage, error) {
	if len(body) < 112 || string(body[:4]) != "dex\n" || body[7] != 0 {
		return nil, errors.New("invalid or truncated DEX header")
	}
	version := string(body[4:7])
	if version != "035" && version != "037" && version != "038" && version != "039" && version != "040" {
		return nil, fmt.Errorf("unsupported DEX %s: 041 containers and historical variants require a separate admitted profile", version)
	}
	if u32(body[32:]) != uint32(len(body)) || u32(body[36:]) != 112 || u32(body[40:]) != 0x12345678 {
		return nil, errors.New("DEX file size/header size/little-endian tag mismatch")
	}
	if u32(body[8:]) != adler32.Checksum(body[12:]) {
		return nil, errors.New("DEX Adler32 mismatch")
	}
	sig := sha1.Sum(body[32:])
	if !bytes.Equal(sig[:], body[12:32]) {
		return nil, errors.New("DEX header SHA-1 mismatch")
	}
	d := &dexImage{body: body, version: version, dataStart: u32(body[108:]), codes: map[uint32]dexCode{}, lists: map[uint32][]uint16{}}
	dataSize := u32(body[104:])
	if d.dataStart < 112 || d.dataStart%4 != 0 || uint64(d.dataStart)+uint64(dataSize) > uint64(len(body)) || dataSize == 0 {
		return nil, errors.New("DEX data section outside artifact")
	}
	d.dataEnd = d.dataStart + dataSize
	tables := []dexTable{}
	for i, w := range []uint32{4, 4, 12, 8, 8, 32} {
		count, off := u32(body[56+i*8:]), u32(body[60+i*8:])
		cap := uint32(65536)
		if i == 1 || i == 2 {
			cap = 65535
		}
		if i == 0 {
			cap = 1 << 20
		}
		if count > cap || count == 0 && off != 0 || count > 0 && (off < 112 || uint64(off)+uint64(count)*uint64(w) > uint64(d.dataStart)) {
			return nil, errors.New("DEX ID table count/offset outside metadata profile")
		}
		if _, err := d.take(off, uint64(count), w, 4, false); err != nil {
			return nil, err
		}
		tables = append(tables, dexTable{count, off, w})
	}
	for i, a := range tables {
		if a.count == 0 {
			continue
		}
		for _, b := range tables[:i] {
			if b.count > 0 && uint64(a.off) < uint64(b.off)+uint64(b.count)*uint64(b.width) && uint64(b.off) < uint64(a.off)+uint64(a.count)*uint64(a.width) {
				return nil, errors.New("overlapping DEX ID tables")
			}
		}
	}
	linkSize, linkOff := u32(body[44:]), u32(body[48:])
	if linkSize == 0 && linkOff != 0 {
		return nil, errors.New("DEX empty link section has nonzero offset")
	}
	if linkSize > 0 {
		if linkOff < d.dataEnd {
			return nil, errors.New("DEX link data overlaps admitted sections")
		}
		if _, err := d.take(linkOff, uint64(linkSize), 1, 0, false); err != nil {
			return nil, err
		}
	}
	if err := d.checkMap(u32(body[52:]), tables); err != nil {
		return nil, err
	}
	d.strings = make([]dexString, int(tables[0].count))
	var previous []uint16
	for i := range d.strings {
		off := u32(body[int(tables[0].off)+i*4:])
		s, units, err := d.readString(off)
		if err != nil {
			return nil, fmt.Errorf("DEX string %d: %w", i, err)
		}
		if i > 0 && slices.Compare(previous, units) >= 0 {
			return nil, errors.New("DEX strings are duplicate or not UTF-16 sorted")
		}
		previous = units
		d.strings[i] = s
	}
	d.types = make([]string, int(tables[1].count))
	var priorIndex uint32
	for i := range d.types {
		idx := u32(body[int(tables[1].off)+i*4:])
		if int(idx) >= len(d.strings) || i > 0 && idx <= priorIndex || !d.strings[idx].utf8 || !dexTypeValid(d.strings[idx].text, d.version) {
			return nil, errors.New("DEX type descriptor/index/order invalid")
		}
		d.types[i] = d.strings[idx].text
		priorIndex = idx
	}
	d.protos = make([]dexProto, int(tables[2].count))
	for i := range d.protos {
		b := body[int(tables[2].off)+i*12:]
		s, ret := u32(b), u32(b[4:])
		if int(s) >= len(d.strings) || !d.strings[s].utf8 || int(ret) >= len(d.types) {
			return nil, errors.New("DEX prototype index invalid")
		}
		params, err := d.typeList(u32(b[8:]))
		if err != nil {
			return nil, err
		}
		d.referenceBudget += uint64(len(params))
		if d.referenceBudget > 1<<20 {
			return nil, errors.New("DEX referenced list work exceeds 1M entries")
		}
		shorty := d.strings[s].text
		if len(shorty) != len(params)+1 || shorty[0] != dexShorty(d.types[ret]) {
			return nil, errors.New("DEX shorty does not match prototype")
		}
		for j, typ := range params {
			if d.types[typ] == "V" || shorty[j+1] != dexShorty(d.types[typ]) {
				return nil, errors.New("DEX parameter/shorty invalid")
			}
		}
		v := dexProto{ret, params}
		if i > 0 {
			old := d.protos[i-1]
			if old.result > ret || old.result == ret && slices.Compare(old.parameters, params) >= 0 {
				return nil, errors.New("DEX prototypes duplicate or not sorted")
			}
		}
		d.protos[i] = v
	}
	d.fields = make([]dexField, int(tables[3].count))
	for i := range d.fields {
		b := body[int(tables[3].off)+i*8:]
		v := dexField{u16(b), u16(b[2:]), u32(b[4:])}
		if int(v.class) >= len(d.types) || !dexClassType(d.types[v.class]) || int(v.typ) >= len(d.types) || d.types[v.typ] == "V" || !d.validName(v.name) {
			return nil, errors.New("DEX field reference invalid")
		}
		if i > 0 {
			a := d.fields[i-1]
			if a.class > v.class || a.class == v.class && (a.name > v.name || a.name == v.name && a.typ >= v.typ) {
				return nil, errors.New("DEX fields duplicate or not sorted")
			}
		}
		d.fields[i] = v
	}
	d.methods = make([]dexMethod, int(tables[4].count))
	for i := range d.methods {
		b := body[int(tables[4].off)+i*8:]
		v := dexMethod{class: u16(b), proto: u16(b[2:]), name: u32(b[4:]), kind: "reference-only"}
		if int(v.class) >= len(d.types) || !dexClassType(d.types[v.class]) || int(v.proto) >= len(d.protos) || !d.validName(v.name) {
			return nil, errors.New("DEX method reference invalid")
		}
		if i > 0 {
			a := d.methods[i-1]
			if a.class > v.class || a.class == v.class && (a.name > v.name || a.name == v.name && a.proto >= v.proto) {
				return nil, errors.New("DEX methods duplicate or not sorted")
			}
		}
		d.methods[i] = v
	}
	classOrder := map[uint32]int{}
	d.classes = make([]DEXClass, int(tables[5].count))
	for i := range d.classes {
		b := body[int(tables[5].off)+i*32:]
		typ, super, source := u32(b), u32(b[8:]), u32(b[16:])
		if int(typ) >= len(d.types) || !dexClassType(d.types[typ]) {
			return nil, errors.New("DEX class definition type invalid")
		}
		if _, ok := classOrder[typ]; ok {
			return nil, errors.New("duplicate DEX class definition")
		}
		classOrder[typ] = i
		c := DEXClass{Index: i, TypeIndex: typ, Descriptor: d.types[typ], AccessFlags: u32(b[4:]), ClassDataOffset: u32(b[24:]), Interfaces: []string{}}
		if super != dexNoIndex {
			if int(super) >= len(d.types) || !dexClassType(d.types[super]) {
				return nil, errors.New("DEX superclass reference invalid")
			}
			v := d.types[super]
			c.Superclass = &v
		}
		if source != dexNoIndex {
			if int(source) >= len(d.strings) {
				return nil, errors.New("DEX source file index invalid")
			}
			v := source
			c.SourceFileIndex = &v
		}
		list, err := d.typeList(u32(b[12:]))
		if err != nil {
			return nil, err
		}
		d.referenceBudget += uint64(len(list))
		if d.referenceBudget > 1<<20 {
			return nil, errors.New("DEX referenced list work exceeds 1M entries")
		}
		seen := map[uint16]bool{}
		for _, idx := range list {
			if !dexClassType(d.types[idx]) || seen[idx] {
				return nil, errors.New("DEX interface reference invalid or duplicated")
			}
			seen[idx] = true
			c.Interfaces = append(c.Interfaces, d.types[idx])
		}
		for _, off := range []uint32{u32(b[20:]), u32(b[28:])} {
			if off != 0 {
				if _, err := d.take(off, 1, 1, 0, true); err != nil {
					return nil, err
				}
			}
		}
		d.classes[i] = c
	}
	for i := range d.classes {
		b := body[int(tables[5].off)+i*32:]
		super := u32(b[8:])
		if n, ok := classOrder[super]; ok && n >= i {
			return nil, errors.New("DEX defined superclass must precede dependent class")
		}
		interfaces, _ := d.typeList(u32(b[12:]))
		for _, idx := range interfaces {
			if n, ok := classOrder[uint32(idx)]; ok && n >= i {
				return nil, errors.New("DEX defined interface must precede dependent class")
			}
		}
		if err := d.classData(&d.classes[i]); err != nil {
			return nil, err
		}
	}
	return d, nil
}

func (d *dexImage) validName(idx uint32) bool {
	if int(idx) >= len(d.strings) || !d.strings[idx].utf8 {
		return false
	}
	s := d.strings[idx].text
	if strings.HasPrefix(s, "<") && strings.HasSuffix(s, ">") {
		s = s[1 : len(s)-1]
	}
	return dexSimpleName(s, d.version)
}

func (d *dexImage) checkMap(off uint32, tables []dexTable) error {
	h, err := d.take(off, 1, 4, 4, true)
	if err != nil {
		return err
	}
	n := u32(h)
	if n == 0 || n > 100000 {
		return errors.New("DEX map list count invalid")
	}
	b, err := d.take(off+4, uint64(n), 12, 4, true)
	if err != nil {
		return err
	}
	seen := map[uint16]bool{}
	var previous uint32
	for i := uint32(0); i < n; i++ {
		v := b[i*12:]
		typ, size, pos := u16(v), u32(v[4:]), u32(v[8:])
		if u16(v[2:]) != 0 || size == 0 || seen[typ] || i > 0 && pos <= previous || pos >= uint32(len(d.body)) {
			return errors.New("DEX map duplicate/order/range/count invalid")
		}
		seen[typ] = true
		previous = pos
		switch {
		case typ == 0:
			if size != 1 || pos != 0 {
				return errors.New("DEX map header mismatch")
			}
		case typ >= 1 && typ <= 6:
			t := tables[typ-1]
			if t.count != size || t.off != pos {
				return errors.New("DEX map/header table mismatch")
			}
		case typ == 0x1000:
			if size != 1 || pos != off {
				return errors.New("DEX map self-reference mismatch")
			}
		default:
			if pos < d.dataStart || pos >= d.dataEnd {
				return errors.New("DEX mapped data outside data section")
			}
			if typ == 7 || typ == 8 {
				if d.optionalIDs == nil {
					d.optionalIDs = map[uint16]uint32{}
				}
				d.optionalIDs[typ] = size
				if d.version < "038" {
					return errors.New("DEX call-site/method-handle table requires version 038+")
				}
				width := uint32(4)
				if typ == 8 {
					width = 8
				}
				if size > 65536 {
					return errors.New("DEX optional ID table exceeds profile")
				}
				if _, err := d.take(pos, uint64(size), width, 4, true); err != nil {
					return err
				}
			}
		}
	}
	if !seen[0] || !seen[0x1000] {
		return errors.New("DEX map lacks header or self item")
	}
	for i, t := range tables {
		if t.count > 0 && !seen[uint16(i+1)] {
			return errors.New("DEX map omits declared ID table")
		}
	}
	return nil
}

func (d *dexImage) classData(c *DEXClass) error {
	if c.ClassDataOffset == 0 {
		return nil
	}
	at := c.ClassDataOffset
	if at < d.dataStart || at >= d.dataEnd {
		return errors.New("DEX class_data outside data")
	}
	counts := make([]uint32, 4)
	for i := range counts {
		v, err := dexULEB(d.body, &at, d.dataEnd)
		if err != nil {
			return err
		}
		counts[i] = v
	}
	c.StaticFields = counts[0]
	c.InstanceFields = counts[1]
	c.DirectMethods = counts[2]
	c.VirtualMethods = counts[3]
	seenFields := map[uint32]bool{}
	for group := 0; group < 4; group++ {
		cap := len(d.methods)
		if group < 2 {
			cap = len(d.fields)
		}
		if uint64(counts[group]) > uint64(cap) {
			return errors.New("DEX class_data count exceeds reference table")
		}
		var idx uint64
		for j := uint32(0); j < counts[group]; j++ {
			delta, err := dexULEB(d.body, &at, d.dataEnd)
			if err != nil {
				return err
			}
			flags, err := dexULEB(d.body, &at, d.dataEnd)
			if err != nil {
				return err
			}
			if j > 0 && delta == 0 {
				return errors.New("duplicate DEX class_data member")
			}
			idx += uint64(delta)
			if idx >= uint64(cap) {
				return errors.New("DEX class_data delta index outside table")
			}
			if group < 2 {
				f := d.fields[idx]
				if uint32(f.class) != c.TypeIndex || seenFields[uint32(idx)] || ((flags&8 != 0) != (group == 0)) {
					return errors.New("DEX field definition belongs to another class/group or is duplicated")
				}
				seenFields[uint32(idx)] = true
				continue
			}
			code, err := dexULEB(d.body, &at, d.dataEnd)
			if err != nil {
				return err
			}
			m := &d.methods[idx]
			if uint32(m.class) != c.TypeIndex || m.defined {
				return errors.New("DEX method definition belongs to another class or is duplicated")
			}
			direct := flags&(8|2|0x10000) != 0
			if direct != (group == 2) {
				return errors.New("DEX direct/virtual method flags conflict")
			}
			if flags&(0x100|0x400) != 0 && code != 0 {
				return errors.New("DEX native/abstract declaration carries code")
			}
			if code != 0 {
				if err := d.code(code); err != nil {
					return err
				}
			}
			m.defined = true
			m.flags = flags
			m.code = code
			m.kind = "virtual"
			if group == 2 {
				m.kind = "direct"
			}
		}
	}
	return nil
}

func (d *dexImage) code(off uint32) error {
	if _, ok := d.codes[off]; ok {
		return nil
	}
	h, err := d.take(off, 1, 16, 4, true)
	if err != nil {
		return err
	}
	regs, ins, tries := u16(h), u16(h[2:]), u16(h[6:])
	code := dexCode{registers: regs, incoming: ins, outgoing: u16(h[4:])}
	if ins > regs {
		return errors.New("DEX code incoming registers exceed register count")
	}
	debug, units := u32(h[8:]), u32(h[12:])
	if debug != 0 {
		if _, err := d.take(debug, 1, 1, 0, true); err != nil {
			return err
		}
	}
	d.codeBudget += uint64(units) * 2
	if d.codeBudget > MaxArtifactBytes {
		return errors.New("DEX code-envelope byte budget exceeded")
	}
	raw, err := d.take(off+16, uint64(units), 2, 0, true)
	if err != nil {
		return err
	}
	end := uint32(uint64(off) + 16 + uint64(units)*2)
	fullEnd := end
	if tries > 0 {
		if units%2 != 0 {
			padding, err := d.take(end, 1, 2, 0, true)
			if err != nil || u16(padding) != 0 {
				return errors.New("DEX code try alignment padding invalid")
			}
			end += 2
		}
		ranges, err := d.take(end, uint64(tries), 8, 4, true)
		if err != nil {
			return err
		}
		handlersStart := end + uint32(tries)*8
		at := handlersStart
		n, err := dexULEB(d.body, &at, d.dataEnd)
		if err != nil {
			return err
		}
		if n > 65536 {
			return errors.New("DEX handler count exceeds profile")
		}
		handlerOffsets := map[uint32][]dexCatch{}
		for i := uint32(0); i < n; i++ {
			handlerOffset := at - handlersStart
			var catches []dexCatch
			count, err := dexSLEB(d.body, &at, d.dataEnd)
			if err != nil {
				return err
			}
			size := int64(count)
			if size < 0 {
				size = -size
			}
			if size > 65536 {
				return errors.New("DEX catch handler count exceeds profile")
			}
			for j := int64(0); j < size; j++ {
				typ, err := dexULEB(d.body, &at, d.dataEnd)
				if err != nil {
					return err
				}
				addr, err := dexULEB(d.body, &at, d.dataEnd)
				if err != nil {
					return err
				}
				if int(typ) >= len(d.types) || !dexClassType(d.types[typ]) || addr >= units {
					return errors.New("DEX typed catch reference/address invalid")
				}
				typeIndex := typ
				catches = append(catches, dexCatch{&typeIndex, addr})
			}
			if count <= 0 {
				addr, err := dexULEB(d.body, &at, d.dataEnd)
				if err != nil || addr >= units {
					return errors.New("DEX catch-all address invalid")
				}
				catches = append(catches, dexCatch{nil, addr})
			}
			handlerOffsets[handlerOffset] = catches
		}
		var previousEnd uint64
		fullEnd = at
		for i := 0; i < int(tries); i++ {
			v := ranges[i*8:]
			start, length, handler := u32(v), u16(v[4:]), u16(v[6:])
			finish := uint64(start) + uint64(length)
			if length == 0 || finish > uint64(units) || uint64(start) < previousEnd || len(handlerOffsets[uint32(handler)]) == 0 {
				return errors.New("DEX try range/handler offset invalid")
			}
			previousEnd = finish
			code.tries = append(code.tries, dexTry{start, uint32(finish), handlerOffsets[uint32(handler)]})
		}
	}
	d.codeBudget += uint64(fullEnd-off) - uint64(units)*2
	if d.codeBudget > MaxArtifactBytes {
		return errors.New("DEX complete code-envelope work exceeds byte budget")
	}
	code.units, code.hash = units, digest(raw)
	d.codes[off] = code
	return nil
}
