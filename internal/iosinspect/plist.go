package iosinspect

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"reverseresearch/internal/recordio"
	"reverseresearch/internal/targetidentity"
)

const maxPlistBytes = 16 << 20
const maxPlistObjects = 50000
const maxPlistReferences = 200000

type InspectOptions struct {
	Offset         int    `json:"offset,omitempty"`
	Limit          int    `json:"limit,omitempty"`
	ExpectedSHA256 string `json:"expected_sha256,omitempty"`
}

func selection(o InspectOptions, total int) (int, int, error) {
	if o.Limit == 0 {
		o.Limit = 50
	}
	if o.Offset < 0 || o.Offset > total || o.Limit < 1 || o.Limit > 200 {
		return 0, 0, errors.New("offset outside inventory or limit outside 1..200")
	}
	return o.Offset, min(total, o.Offset+o.Limit), nil
}

func boundedProjection(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > 48<<10 {
		return errors.New("Apple projection exceeds 48 KiB; request a smaller page")
	}
	return nil
}

func contentHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func captureApple(p, expected string) ([]byte, string, string, error) {
	b, abs, hash, err := targetidentity.CaptureFile(p, maxPlistBytes)
	if err != nil {
		return nil, "", "", err
	}
	if err = recordio.CheckExpectedSHA256(hash, expected); err != nil {
		return nil, "", "", err
	}
	return b, abs, hash, nil
}

// A plist is an object table. Shared containers retain their original references;
// they are never recursively copied into an exponentially expanded value tree.
type plistNode struct {
	kind, text, bits string
	data             []byte
	refs             []int
	keys             []int
	offset, length   int
}
type plistDocument struct {
	format, rangeBasis, rangeSHA256 string
	root                            int
	nodes                           []plistNode
}

type PlistPair struct {
	Key         string `json:"key"`
	KeyObject   int    `json:"key_object"`
	ValueObject int    `json:"value_object"`
}
type PlistObject struct {
	Index           int         `json:"index"`
	Kind            string      `json:"kind"`
	ByteOffset      int         `json:"byte_offset"`
	ByteLength      int         `json:"byte_length"`
	Text            string      `json:"text,omitempty"`
	TextBytes       int         `json:"text_bytes,omitempty"`
	IEEE754Hex      string      `json:"ieee754_hex,omitempty"`
	DataBytes       int         `json:"data_bytes,omitempty"`
	DataSHA256      string      `json:"data_sha256,omitempty"`
	References      []int       `json:"references,omitempty"`
	Pairs           []PlistPair `json:"pairs,omitempty"`
	TotalReferences int         `json:"total_references"`
	ValueComplete   bool        `json:"value_complete"`
}

func (d plistDocument) object(i int) PlistObject {
	n := d.nodes[i]
	v := PlistObject{Index: i, Kind: n.kind, ByteOffset: n.offset, ByteLength: n.length, Text: n.text, TextBytes: len(n.text), IEEE754Hex: n.bits, ValueComplete: true, TotalReferences: len(n.refs)}
	if len(v.Text) > 2048 {
		v.Text = v.Text[:2048]
		for !utf8.ValidString(v.Text) {
			v.Text = v.Text[:len(v.Text)-1]
		}
		v.ValueComplete = false
	}
	if n.kind == "data" {
		v.DataBytes = len(n.data)
		v.DataSHA256 = contentHash(n.data)
	}
	if n.kind == "dictionary" {
		for j := 0; j < min(len(n.refs), 100); j++ {
			v.Pairs = append(v.Pairs, PlistPair{Key: d.nodes[n.keys[j]].text, KeyObject: n.keys[j], ValueObject: n.refs[j]})
		}
	} else {
		v.References = n.refs[:min(len(n.refs), 100)]
	}
	if len(n.refs) > 100 {
		v.ValueComplete = false
	}
	return v
}

type PlistReport struct {
	Path               string        `json:"path"`
	SHA256             string        `json:"sha256"`
	Format             string        `json:"format"`
	RangeBasis         string        `json:"range_basis"`
	RangeSHA256        string        `json:"range_sha256"`
	RootObject         int           `json:"root_object"`
	TotalObjects       int           `json:"total_objects"`
	Offset             int           `json:"offset"`
	Objects            []PlistObject `json:"objects"`
	NextOffset         *int          `json:"next_offset,omitempty"`
	CoverageComplete   bool          `json:"coverage_complete"`
	ExecutionPerformed bool          `json:"execution_performed"`
	Limitations        []string      `json:"limitations"`
}

func InspectPlist(p string, o InspectOptions) (PlistReport, error) {
	b, abs, hash, err := captureApple(p, o.ExpectedSHA256)
	if err != nil {
		return PlistReport{}, err
	}
	d, err := parsePlist(b)
	if err != nil {
		return PlistReport{}, err
	}
	start, end, err := selection(o, len(d.nodes))
	if err != nil {
		return PlistReport{}, err
	}
	r := PlistReport{Path: abs, SHA256: hash, Format: d.format, RangeBasis: d.rangeBasis, RangeSHA256: d.rangeSHA256, RootObject: d.root, TotalObjects: len(d.nodes), Offset: start, Objects: []PlistObject{}, CoverageComplete: start == 0 && end == len(d.nodes), Limitations: []string{"object references are serialization identities, not instantiated Foundation objects", "strings and reference arrays are bounded previews; data bytes require explicit object selection", "XML ranges refer to normalized UTF-8 bytes without BOM; binary ranges refer to original artifact bytes", "only XML plist and bplist00 are supported; no external DTD/entity resolution"}}
	for i := start; i < end; i++ {
		v := d.object(i)
		r.Objects = append(r.Objects, v)
		r.CoverageComplete = r.CoverageComplete && v.ValueComplete
	}
	if end < len(d.nodes) {
		r.NextOffset = &end
	}
	return r, boundedProjection(r)
}

type PlistDataOptions struct {
	ObjectIndex int `json:"object_index"`
	InspectOptions
}
type PlistDataReport struct {
	Path               string `json:"path"`
	SHA256             string `json:"sha256"`
	ObjectIndex        int    `json:"object_index"`
	Size               int    `json:"size"`
	ContentSHA256      string `json:"content_sha256"`
	Offset             int    `json:"offset"`
	ReadBytes          int    `json:"read_bytes"`
	DataBase64         string `json:"data_base64"`
	NextOffset         *int   `json:"next_offset,omitempty"`
	CoverageComplete   bool   `json:"coverage_complete"`
	ExecutionPerformed bool   `json:"execution_performed"`
}

func ReadPlistData(p string, o PlistDataOptions) (PlistDataReport, error) {
	if o.Limit == 0 {
		o.Limit = 8192
	}
	if o.Offset < 0 || o.Limit < 1 || o.Limit > 16384 {
		return PlistDataReport{}, errors.New("offset must be nonnegative; limit must be 1..16384 bytes")
	}
	b, abs, hash, err := captureApple(p, o.ExpectedSHA256)
	if err != nil {
		return PlistDataReport{}, err
	}
	d, err := parsePlist(b)
	if err != nil {
		return PlistDataReport{}, err
	}
	if o.ObjectIndex < 0 || o.ObjectIndex >= len(d.nodes) || d.nodes[o.ObjectIndex].kind != "data" {
		return PlistDataReport{}, errors.New("selected plist object is not data")
	}
	data := d.nodes[o.ObjectIndex].data
	if o.Offset > len(data) {
		return PlistDataReport{}, errors.New("offset outside plist data")
	}
	end := min(len(data), o.Offset+o.Limit)
	r := PlistDataReport{Path: abs, SHA256: hash, ObjectIndex: o.ObjectIndex, Size: len(data), ContentSHA256: contentHash(data), Offset: o.Offset, ReadBytes: end - o.Offset, DataBase64: base64.StdEncoding.EncodeToString(data[o.Offset:end]), CoverageComplete: o.Offset == 0 && end == len(data)}
	if end < len(data) {
		r.NextOffset = &end
	}
	return r, boundedProjection(r)
}

func parsePlist(b []byte) (plistDocument, error) {
	if len(b) > maxPlistBytes {
		return plistDocument{}, errors.New("plist exceeds 16 MiB")
	}
	var d plistDocument
	var err error
	if bytes.HasPrefix(b, []byte("bplist00")) {
		d, err = parseBinaryPlist(b)
	} else {
		d, err = parseXMLPlist(b)
	}
	if err != nil {
		return d, err
	}
	return d, validatePlist(d)
}

func validatePlist(d plistDocument) error {
	if len(d.nodes) == 0 || len(d.nodes) > maxPlistObjects || d.root < 0 || d.root >= len(d.nodes) {
		return errors.New("invalid plist root/object count")
	}
	total := 0
	for _, n := range d.nodes {
		total += len(n.refs) + len(n.keys)
		if total > maxPlistReferences {
			return errors.New("plist exceeds reference budget")
		}
		for _, ref := range append(append([]int{}, n.refs...), n.keys...) {
			if ref < 0 || ref >= len(d.nodes) {
				return errors.New("plist reference outside object table")
			}
		}
		if n.kind == "dictionary" {
			seen := map[string]bool{}
			for _, key := range n.keys {
				s := d.nodes[key]
				if s.kind != "string" || len(s.text) > 4096 || seen[s.text] {
					return errors.New("plist dictionary has invalid or duplicate keys")
				}
				seen[s.text] = true
			}
		}
	}
	state := make([]byte, len(d.nodes))
	depth := make([]int, len(d.nodes))
	var visit func(int, int) (int, error)
	visit = func(i, level int) (int, error) {
		if level > 128 {
			return 0, errors.New("plist nesting exceeds 128")
		}
		if state[i] == 1 {
			return 0, errors.New("plist container references form a cycle")
		}
		if state[i] == 2 {
			return depth[i], nil
		}
		state[i] = 1
		longest := 1
		for _, ref := range d.nodes[i].refs {
			v, err := visit(ref, level+1)
			if err != nil {
				return 0, err
			}
			longest = max(longest, v+1)
			if longest > 128 {
				return 0, errors.New("plist nesting exceeds 128")
			}
		}
		state[i] = 2
		depth[i] = longest
		return longest, nil
	}
	for i := range d.nodes {
		if _, err := visit(i, 1); err != nil {
			return err
		}
	}
	return nil
}

func uintBE(b []byte) uint64 {
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	return v
}
func integerText(b []byte, signed bool) string {
	v := new(big.Int).SetBytes(b)
	if signed && b[0]&0x80 != 0 {
		v.Sub(v, new(big.Int).Lsh(big.NewInt(1), uint(len(b)*8)))
	}
	return v.String()
}

func parseBinaryPlist(b []byte) (plistDocument, error) {
	d := plistDocument{format: "binary-plist", rangeBasis: "original-artifact", rangeSHA256: contentHash(b)}
	if len(b) < 40 {
		return d, errors.New("binary plist trailer is truncated")
	}
	trailer := b[len(b)-32:]
	ow, rw := int(trailer[6]), int(trailer[7])
	count, root, table := uintBE(trailer[8:16]), uintBE(trailer[16:24]), uintBE(trailer[24:32])
	if !bytes.Equal(trailer[:6], make([]byte, 6)) || ow < 1 || ow > 8 || rw < 1 || rw > 8 || count == 0 || count > maxPlistObjects || root >= count || table < 8 || table > uint64(len(b)-32) || count*uint64(ow) != uint64(len(b)-32)-table {
		return d, errors.New("binary plist trailer/table is invalid or exceeds budget")
	}
	d.root = int(root)
	d.nodes = make([]plistNode, int(count))
	ranges := [][2]int{}
	references := 0
	for i := 0; i < int(count); i++ {
		off := uintBE(b[int(table)+i*ow : int(table)+(i+1)*ow])
		if off < 8 || off >= table {
			return d, errors.New("binary plist object offset outside table")
		}
		pos := int(off)
		marker := b[pos]
		pos++
		n := plistNode{offset: int(off)}
		take := func(size int) ([]byte, error) {
			if size < 0 || size > int(table)-pos {
				return nil, errors.New("binary plist object is truncated")
			}
			v := b[pos : pos+size]
			pos += size
			return v, nil
		}
		length := func() (int, error) {
			v := uint64(marker & 15)
			if v == 15 {
				t, err := take(1)
				if err != nil {
					return 0, err
				}
				if t[0]>>4 != 1 || t[0]&15 > 3 {
					return 0, errors.New("invalid binary plist extended length")
				}
				raw, err := take(1 << uint(t[0]&15))
				if err != nil {
					return 0, err
				}
				v = uintBE(raw)
			}
			if v > uint64(maxPlistBytes) {
				return 0, errors.New("binary plist object length exceeds budget")
			}
			return int(v), nil
		}
		var err error
		switch marker >> 4 {
		case 0:
			switch marker {
			case 0:
				n.kind = "null"
			case 8:
				n.kind = "boolean"
				n.text = "false"
			case 9:
				n.kind = "boolean"
				n.text = "true"
			default:
				err = errors.New("unsupported binary plist primitive")
			}
		case 1:
			if marker&15 > 4 {
				return d, errors.New("binary plist integer exceeds 128 bits")
			}
			var raw []byte
			raw, err = take(1 << uint(marker&15))
			if err == nil {
				n.kind = "integer"
				n.text = integerText(raw, len(raw) >= 8)
			}
		case 2, 3:
			width := 1 << uint(marker&15)
			if (marker>>4 == 3 && marker != 0x33) || (width != 4 && width != 8) {
				return d, errors.New("unsupported binary plist float/date representation")
			}
			var raw []byte
			raw, err = take(width)
			if err == nil {
				n.kind = "real"
				n.bits = hex.EncodeToString(raw)
				value := math.Float64frombits(uintBE(raw))
				if width == 4 {
					value = float64(math.Float32frombits(uint32(uintBE(raw))))
				}
				n.text = strconv.FormatFloat(value, 'g', -1, width*8)
				if marker>>4 == 3 {
					n.kind = "date"
					n.text = "CFAbsoluteTime:" + strconv.FormatFloat(value, 'g', -1, 64)
				}
			}
		case 4, 5, 6:
			var size int
			size, err = length()
			if err != nil {
				break
			}
			if marker>>4 == 6 {
				size *= 2
			}
			var raw []byte
			raw, err = take(size)
			if err != nil {
				break
			}
			switch marker >> 4 {
			case 4:
				n.kind = "data"
				n.data = raw
			case 5:
				n.kind = "string"
				for _, c := range raw {
					if c > 127 {
						err = errors.New("binary plist ASCII string is not ASCII")
						break
					}
				}
				n.text = string(raw)
			case 6:
				n.kind = "string"
				units := make([]uint16, len(raw)/2)
				for j := range units {
					units[j] = binary.BigEndian.Uint16(raw[j*2:])
				}
				n.text, err = decodeUTF16(units)
			}
		case 8:
			var raw []byte
			raw, err = take(int(marker&15) + 1)
			if err == nil {
				n.kind = "uid"
				n.text = integerText(raw, false)
			}
		case 10, 13:
			var size int
			size, err = length()
			if err != nil {
				break
			}
			multiplier := 1
			n.kind = "array"
			if marker>>4 == 13 {
				multiplier = 2
				n.kind = "dictionary"
			}
			if size > maxPlistReferences/multiplier || references+size*multiplier > maxPlistReferences {
				return d, errors.New("binary plist reference budget exceeded")
			}
			references += size * multiplier
			var raw []byte
			raw, err = take(size * multiplier * rw)
			if err != nil {
				break
			}
			for j := 0; j < size*multiplier; j++ {
				ref := uintBE(raw[j*rw : (j+1)*rw])
				if ref >= count {
					return d, errors.New("binary plist reference outside object table")
				}
				if multiplier == 2 && j < size {
					n.keys = append(n.keys, int(ref))
				} else {
					n.refs = append(n.refs, int(ref))
				}
			}
		default:
			err = errors.New("unsupported bplist00 object kind")
		}
		if err != nil {
			return d, err
		}
		n.length = pos - int(off)
		d.nodes[i] = n
		ranges = append(ranges, [2]int{int(off), pos})
	}
	sort.Slice(ranges, func(i, j int) bool { return ranges[i][0] < ranges[j][0] })
	for i := 1; i < len(ranges); i++ {
		if ranges[i][0] < ranges[i-1][1] {
			return d, errors.New("binary plist object ranges overlap")
		}
	}
	return d, nil
}

func decodeUTF16(units []uint16) (string, error) {
	for i := 0; i < len(units); i++ {
		x := units[i]
		if x >= 0xd800 && x <= 0xdbff {
			if i+1 == len(units) || units[i+1] < 0xdc00 || units[i+1] > 0xdfff {
				return "", errors.New("unpaired UTF-16 surrogate")
			}
			i++
		} else if x >= 0xdc00 && x <= 0xdfff {
			return "", errors.New("unpaired UTF-16 surrogate")
		}
	}
	return string(utf16.Decode(units)), nil
}

func normalizeXML(b []byte) ([]byte, error) {
	if bytes.HasPrefix(b, []byte{0xff, 0xfe}) || bytes.HasPrefix(b, []byte{0xfe, 0xff}) {
		if len(b)%2 != 0 {
			return nil, errors.New("UTF-16 XML is truncated")
		}
		var order binary.ByteOrder = binary.LittleEndian
		if b[0] == 0xfe {
			order = binary.BigEndian
		}
		units := make([]uint16, (len(b)-2)/2)
		for i := range units {
			units[i] = order.Uint16(b[2+i*2:])
		}
		s, err := decodeUTF16(units)
		if err != nil {
			return nil, err
		}
		return []byte(s), nil
	}
	b = bytes.TrimPrefix(b, []byte{0xef, 0xbb, 0xbf})
	if !utf8.Valid(b) {
		return nil, errors.New("XML plist is not UTF-8 or BOM-marked UTF-16")
	}
	return b, nil
}

func parseXMLPlist(b []byte) (plistDocument, error) {
	d := plistDocument{format: "xml-plist", rangeBasis: "normalized-utf8-without-bom"}
	normalized, err := normalizeXML(b)
	if err != nil {
		return d, err
	}
	d.rangeSHA256 = contentHash(normalized)
	decoder := xml.NewDecoder(bytes.NewReader(normalized))
	decoder.CharsetReader = func(name string, input io.Reader) (io.Reader, error) {
		if strings.EqualFold(name, "utf-16") && !bytes.HasPrefix(b, []byte{0xff, 0xfe}) && !bytes.HasPrefix(b, []byte{0xfe, 0xff}) {
			return nil, errors.New("UTF-16 declaration requires BOM-marked UTF-16 source")
		}
		if strings.EqualFold(name, "utf-16") || strings.EqualFold(name, "utf-8") {
			return input, nil
		}
		return nil, errors.New("unsupported XML charset")
	}
	var tokenStart int64
	var next func() (xml.Token, error)
	next = func() (xml.Token, error) {
		for {
			tokenStart = decoder.InputOffset()
			t, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			switch x := t.(type) {
			case xml.Comment, xml.ProcInst:
				continue
			case xml.Directive:
				if !strings.HasPrefix(strings.TrimSpace(string(x)), "DOCTYPE plist ") || strings.ContainsAny(string(x), "[]") {
					return nil, errors.New("XML plist directives/entities are unsupported")
				}
				continue
			case xml.CharData:
				if strings.TrimSpace(string(x)) == "" {
					continue
				}
			}
			return t, nil
		}
	}
	t, err := next()
	if err != nil {
		return d, err
	}
	root, ok := t.(xml.StartElement)
	if !ok || root.Name.Space != "" || root.Name.Local != "plist" {
		return d, errors.New("expected XML plist root")
	}
	for _, a := range root.Attr {
		if a.Name.Space != "" || a.Name.Local != "version" || a.Value != "1.0" {
			return d, errors.New("unsupported XML plist root attribute")
		}
	}
	var parse func(xml.StartElement, int) (int, error)
	refs := 0
	parse = func(start xml.StartElement, depth int) (int, error) {
		if depth > 128 || len(d.nodes) >= maxPlistObjects {
			return 0, errors.New("XML plist depth/object budget exceeded")
		}
		if start.Name.Space != "" || len(start.Attr) != 0 {
			return 0, errors.New("XML plist element namespace/attribute is unsupported")
		}
		kind := start.Name.Local
		id := len(d.nodes)
		d.nodes = append(d.nodes, plistNode{kind: kind, offset: int(tokenStart)})
		defer func() { d.nodes[id].length = int(decoder.InputOffset()) - d.nodes[id].offset }()
		if kind == "array" || kind == "dict" {
			if kind == "dict" {
				d.nodes[id].kind = "dictionary"
			}
			key := -1
			for {
				tok, err := next()
				if err != nil {
					return 0, err
				}
				if end, ok := tok.(xml.EndElement); ok {
					if end.Name != start.Name || key != -1 {
						return 0, errors.New("XML plist container/key has no matching value")
					}
					break
				}
				child, ok := tok.(xml.StartElement)
				if !ok {
					return 0, errors.New("unexpected XML plist container text")
				}
				if kind == "array" && child.Name.Local == "key" {
					return 0, errors.New("XML key cannot be an array value")
				}
				if kind == "dict" && (key == -1) != (child.Name.Local == "key") {
					return 0, errors.New("XML plist dictionary requires alternating keys/values")
				}
				childID, err := parse(child, depth+1)
				if err != nil {
					return 0, err
				}
				refs++
				if refs > maxPlistReferences {
					return 0, errors.New("XML plist reference budget exceeded")
				}
				if kind == "dict" && key == -1 {
					key = childID
				} else {
					if key != -1 {
						d.nodes[id].keys = append(d.nodes[id].keys, key)
						key = -1
					}
					d.nodes[id].refs = append(d.nodes[id].refs, childID)
				}
			}
			return id, nil
		}
		var text strings.Builder
		for {
			tok, err := decoder.Token()
			if err != nil {
				return 0, err
			}
			switch x := tok.(type) {
			case xml.CharData:
				text.Write(x)
			case xml.Comment:
				continue
			case xml.EndElement:
				if x.Name != start.Name {
					return 0, errors.New("XML plist scalar end mismatch")
				}
				goto scalar
			default:
				return 0, errors.New("XML plist scalar contains nested markup")
			}
		}
	scalar:
		n := &d.nodes[id]
		n.text = text.String()
		switch kind {
		case "key", "string":
			n.kind = "string"
		case "true", "false":
			if strings.TrimSpace(n.text) != "" {
				return 0, errors.New("XML boolean contains text")
			}
			n.kind = "boolean"
			n.text = kind
		case "integer":
			literal := strings.TrimSpace(n.text)
			if len(literal) > 256 {
				return 0, errors.New("XML integer literal exceeds budget")
			}
			base := 10
			digits := literal
			negative := strings.HasPrefix(digits, "-")
			digits = strings.TrimPrefix(strings.TrimPrefix(digits, "+"), "-")
			if strings.HasPrefix(digits, "0x") || strings.HasPrefix(digits, "0X") {
				base = 16
				digits = digits[2:]
			}
			v, ok := new(big.Int).SetString(digits, base)
			if !ok || v.Sign() < 0 {
				return 0, errors.New("invalid XML integer")
			}
			if negative {
				v.Neg(v)
			}
			n.text = v.String()
		case "real":
			literal := strings.TrimSpace(n.text)
			v, err := strconv.ParseFloat(literal, 64)
			if err != nil {
				return 0, errors.New("invalid XML real")
			}
			n.text = literal
			n.bits = fmt.Sprintf("%016x", math.Float64bits(v))
		case "date":
			n.text = strings.TrimSpace(n.text)
			if _, err := time.Parse(time.RFC3339Nano, n.text); err != nil {
				return 0, errors.New("invalid XML plist date")
			}
		case "data":
			encoded := strings.Map(func(r rune) rune {
				if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
					return -1
				}
				return r
			}, n.text)
			n.data, err = base64.StdEncoding.Strict().DecodeString(encoded)
			if err != nil {
				return 0, errors.New("invalid XML plist base64 data")
			}
			n.text = ""
		default:
			return 0, errors.New("unsupported XML plist scalar")
		}
		return id, nil
	}
	t, err = next()
	if err != nil {
		return d, err
	}
	start, ok := t.(xml.StartElement)
	if !ok || start.Name.Local == "key" {
		return d, errors.New("XML plist has no value")
	}
	d.root, err = parse(start, 1)
	if err != nil {
		return d, err
	}
	t, err = next()
	if err != nil {
		return d, err
	}
	end, ok := t.(xml.EndElement)
	if !ok || end.Name != root.Name {
		return d, errors.New("XML plist has multiple roots")
	}
	if _, err = next(); err != io.EOF {
		return d, errors.New("XML plist has trailing markup")
	}
	return d, nil
}
