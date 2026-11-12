package iosinspect

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

type NIBOptions struct {
	InspectOptions
	View string `json:"view,omitempty"`
}
type NIBValue struct {
	Index           int     `json:"index"`
	Key             string  `json:"key"`
	Kind            string  `json:"kind"`
	Text            string  `json:"text,omitempty"`
	IEEE754Hex      string  `json:"ieee754_hex,omitempty"`
	DataBytes       int     `json:"data_bytes,omitempty"`
	DataSHA256      string  `json:"data_sha256,omitempty"`
	ObjectReference *uint32 `json:"object_reference,omitempty"`
	ReferenceStatus string  `json:"reference_status,omitempty"`
	ByteOffset      int     `json:"byte_offset"`
	ByteLength      int     `json:"byte_length"`
}
type NIBObject struct {
	Index                int        `json:"index"`
	ClassIndex           int        `json:"class_index"`
	ClassName            string     `json:"class_name"`
	ClassExtensions      []uint32   `json:"class_extensions,omitempty"`
	TotalClassExtensions int        `json:"total_class_extensions"`
	ByteOffset           int        `json:"byte_offset"`
	ByteLength           int        `json:"byte_length"`
	ValueStart           int        `json:"value_start"`
	TotalValues          int        `json:"total_values"`
	Values               []NIBValue `json:"values"`
	CoverageComplete     bool       `json:"coverage_complete"`
}
type NIBReport struct {
	Path               string      `json:"path"`
	SHA256             string      `json:"sha256"`
	FormatVersion      uint32      `json:"format_version"`
	CoderVersion       uint32      `json:"coder_version"`
	View               string      `json:"view"`
	TotalObjects       int         `json:"total_objects"`
	TotalKeys          int         `json:"total_keys"`
	TotalValues        int         `json:"total_values"`
	TotalClasses       int         `json:"total_classes"`
	Offset             int         `json:"offset"`
	Objects            []NIBObject `json:"objects,omitempty"`
	Values             []NIBValue  `json:"values,omitempty"`
	NextOffset         *int        `json:"next_offset,omitempty"`
	CoverageComplete   bool        `json:"coverage_complete"`
	ExecutionPerformed bool        `json:"execution_performed"`
	Limitations        []string    `json:"limitations"`
}
type nibCursor struct {
	b        []byte
	pos, end int
}

func (c *nibCursor) take(size int) ([]byte, error) {
	if size < 0 || c.pos > c.end || size > c.end-c.pos {
		return nil, errors.New("NIB table data is truncated")
	}
	v := c.b[c.pos : c.pos+size]
	c.pos += size
	return v, nil
}
func (c *nibCursor) number() (int, error) {
	var v uint64
	for i := 0; i < 5; i++ {
		raw, err := c.take(1)
		if err != nil {
			return 0, err
		}
		v |= uint64(raw[0]&127) << uint(i*7)
		if raw[0]&128 != 0 {
			if v > 0x7fffffff {
				return 0, errors.New("NIB variable integer exceeds signed 31-bit profile")
			}
			return int(v), nil
		}
	}
	return 0, errors.New("NIB variable integer is too long")
}
func (c *nibCursor) text() (string, error) {
	n, err := c.number()
	if err != nil {
		return "", err
	}
	raw, err := c.take(n)
	if err != nil {
		return "", err
	}
	if n > 4096 || !utf8.Valid(raw) {
		return "", errors.New("NIB name is invalid UTF-8 or exceeds 4096 bytes")
	}
	return string(raw), nil
}
func (c *nibCursor) done() error {
	if c.pos != c.end {
		return errors.New("NIB table has unexplained trailing bytes")
	}
	return nil
}

func InspectNIB(p string, o NIBOptions) (NIBReport, error) {
	b, abs, hash, err := captureApple(p, o.ExpectedSHA256)
	if err != nil {
		return NIBReport{}, err
	}
	if len(b) < 50 || !bytes.Equal(b[:10], []byte("NIBArchive")) {
		return NIBReport{}, errors.New("expected compiled NIBArchive")
	}
	u32 := func(off int) uint32 { return binary.LittleEndian.Uint32(b[off : off+4]) }
	if u32(10) != 1 {
		return NIBReport{}, errors.New("unsupported NIB format version")
	}
	counts, offsets := make([]int, 4), make([]int, 5)
	for i := 0; i < 4; i++ {
		if u32(18+8*i) > maxPlistReferences {
			return NIBReport{}, errors.New("NIB table count exceeds bounded profile")
		}
		counts[i] = int(u32(18 + 8*i))
		offsets[i] = int(u32(22 + 8*i))
		if counts[i] > maxPlistReferences || offsets[i] < 50 || offsets[i] > len(b) {
			return NIBReport{}, errors.New("NIB table count/offset exceeds bounded artifact")
		}
	}
	offsets[4] = len(b)
	for i := 1; i < 5; i++ {
		if offsets[i] < offsets[i-1] {
			return NIBReport{}, errors.New("NIB tables overlap or are out of order")
		}
	}
	if offsets[0] != 50 || counts[0] > maxPlistObjects {
		return NIBReport{}, errors.New("NIB object count/header gap is unsupported")
	}
	type objectRecord struct{ class, start, count, offset, length int }
	objects := make([]objectRecord, counts[0])
	c := nibCursor{b, offsets[0], offsets[1]}
	totalFields := 0
	for i := range objects {
		begin := c.pos
		cl, err := c.number()
		if err != nil {
			return NIBReport{}, err
		}
		start, err := c.number()
		if err != nil {
			return NIBReport{}, err
		}
		count, err := c.number()
		if err != nil {
			return NIBReport{}, err
		}
		if cl >= counts[3] || start > counts[2] || count > counts[2]-start {
			return NIBReport{}, errors.New("NIB object references invalid table range")
		}
		totalFields += count
		if totalFields > maxPlistReferences {
			return NIBReport{}, errors.New("NIB projected field count exceeds budget")
		}
		objects[i] = objectRecord{cl, start, count, begin, c.pos - begin}
	}
	if err := c.done(); err != nil {
		return NIBReport{}, err
	}
	c = nibCursor{b, offsets[1], offsets[2]}
	keys := make([]string, counts[1])
	for i := range keys {
		keys[i], err = c.text()
		if err != nil {
			return NIBReport{}, err
		}
	}
	if err := c.done(); err != nil {
		return NIBReport{}, err
	}
	c = nibCursor{b, offsets[2], offsets[3]}
	values := make([]NIBValue, counts[2])
	for i := range values {
		begin := c.pos
		key, err := c.number()
		if err != nil {
			return NIBReport{}, err
		}
		if key >= len(keys) {
			return NIBReport{}, errors.New("NIB value references invalid key")
		}
		tag, err := c.take(1)
		if err != nil {
			return NIBReport{}, err
		}
		v := NIBValue{Index: i, Key: keys[key], ByteOffset: begin}
		var raw []byte
		switch tag[0] {
		case 0, 1, 2, 3:
			width := 1 << uint(tag[0])
			raw, err = c.take(width)
			if err == nil {
				be := make([]byte, width)
				for j := range raw {
					be[width-1-j] = raw[j]
				}
				v.Kind = "integer"
				v.Text = integerText(be, true)
			}
		case 4, 5:
			v.Kind = "boolean"
			v.Text = strconv.FormatBool(tag[0] == 4)
		case 6, 7:
			width := 4
			if tag[0] == 7 {
				width = 8
			}
			raw, err = c.take(width)
			if err == nil {
				be := make([]byte, width)
				for j := range raw {
					be[width-1-j] = raw[j]
				}
				v.Kind = "real"
				v.IEEE754Hex = hex.EncodeToString(be)
				f := math.Float64frombits(uintBE(be))
				if width == 4 {
					f = float64(math.Float32frombits(uint32(uintBE(be))))
				}
				v.Text = strconv.FormatFloat(f, 'g', -1, width*8)
			}
		case 8:
			var n int
			n, err = c.number()
			if err == nil {
				raw, err = c.take(n)
				if err == nil {
					v.Kind = "data"
					v.DataBytes = n
					v.DataSHA256 = contentHash(raw)
				}
			}
		case 9:
			v.Kind = "null"
		case 10:
			raw, err = c.take(4)
			if err == nil {
				index := binary.LittleEndian.Uint32(raw)
				v.Kind = "object-reference"
				v.ObjectReference = &index
				v.ReferenceStatus = "unresolved"
				if uint64(index) < uint64(len(objects)) {
					v.ReferenceStatus = "declared"
				}
			}
		default:
			return NIBReport{}, errors.New("unsupported NIB value encoding")
		}
		if err != nil {
			return NIBReport{}, err
		}
		v.ByteLength = c.pos - begin
		values[i] = v
	}
	if err := c.done(); err != nil {
		return NIBReport{}, err
	}
	c = nibCursor{b, offsets[3], offsets[4]}
	classes := make([]string, counts[3])
	extensions := make([][]uint32, counts[3])
	for i := range classes {
		length, err := c.number()
		if err != nil {
			return NIBReport{}, err
		}
		extra, err := c.number()
		if err != nil {
			return NIBReport{}, err
		}
		if extra > maxPlistReferences {
			return NIBReport{}, errors.New("NIB class extension count exceeds budget")
		}
		raw, err := c.take(extra * 4)
		if err != nil {
			return NIBReport{}, err
		}
		for j := 0; j < extra; j++ {
			extensions[i] = append(extensions[i], binary.LittleEndian.Uint32(raw[j*4:]))
		}
		raw, err = c.take(length)
		if err != nil {
			return NIBReport{}, err
		}
		if length > 4096 || !utf8.Valid(raw) {
			return NIBReport{}, errors.New("NIB class name is invalid UTF-8 or exceeds limit")
		}
		classes[i] = strings.TrimRight(string(raw), "\x00")
	}
	if err := c.done(); err != nil {
		return NIBReport{}, err
	}
	if o.View == "" {
		o.View = "objects"
	}
	total := len(objects)
	if o.View == "values" {
		total = len(values)
	} else if o.View != "objects" {
		return NIBReport{}, errors.New("NIB view must be objects or values")
	}
	start, end, err := selection(o.InspectOptions, total)
	if err != nil {
		return NIBReport{}, err
	}
	r := NIBReport{Path: abs, SHA256: hash, FormatVersion: u32(10), CoderVersion: u32(14), View: o.View, TotalObjects: len(objects), TotalKeys: len(keys), TotalValues: len(values), TotalClasses: len(classes), Offset: start, CoverageComplete: start == 0 && end == total, Limitations: []string{"supports compiled NIBArchive v1 table declarations, not UIKit runtime construction or rendered layout", "class extension values are opaque producer integers; unknown value tags fail explicitly", "object fields are bounded to 100; use view=values to page every original value", "data fields expose byte counts and hashes, not inferred strings, images or Interface Builder semantics"}}
	if o.View == "values" {
		r.Values = values[start:end]
	} else {
		r.Objects = []NIBObject{}
		for i := start; i < end; i++ {
			v := objects[i]
			ext := extensions[v.class]
			obj := NIBObject{Index: i, ClassIndex: v.class, ClassName: classes[v.class], ClassExtensions: ext[:min(len(ext), 16)], TotalClassExtensions: len(ext), ByteOffset: v.offset, ByteLength: v.length, ValueStart: v.start, TotalValues: v.count, Values: values[v.start : v.start+min(v.count, 100)], CoverageComplete: v.count <= 100 && len(ext) <= 16}
			r.Objects = append(r.Objects, obj)
			r.CoverageComplete = r.CoverageComplete && obj.CoverageComplete
		}
	}
	if end < total {
		r.NextOffset = &end
	}
	return r, boundedProjection(r)
}
