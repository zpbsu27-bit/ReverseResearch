package appinspect

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math"
	"unicode/utf8"

	"reverseresearch/internal/targetidentity"
)

var goBuildMagic = []byte("\xff Go buildinf:")
var goModuleStart = []byte{0x30, 0x77, 0xaf, 0x0c, 0x92, 0x74, 0x08, 0x02, 0x41, 0xe1, 0xc1, 0x07, 0xe6, 0xd6, 0x18, 0xe6}
var goModuleEnd = []byte{0xf9, 0x32, 0x43, 0x31, 0x86, 0x18, 0x20, 0x72, 0x00, 0x82, 0x42, 0x10, 0x41, 0x16, 0xd8, 0xf2}

type GoMetadataOptions struct {
	PageOptions
	Part        string `json:"part,omitempty"`
	RecordIndex *int   `json:"record_index,omitempty"`
	Field       string `json:"field,omitempty"`
}
type GoMetadataRange struct {
	Offset uint64 `json:"offset"`
	Size   uint64 `json:"size"`
	Basis  string `json:"basis"`
}
type GoMetadataReport struct {
	Path                    string           `json:"path"`
	SHA256                  string           `json:"sha256"`
	Format                  string           `json:"format"`
	BuildInfoAvailable      bool             `json:"build_info_available"`
	UnavailableReason       string           `json:"unavailable_reason,omitempty"`
	Encoding                string           `json:"encoding,omitempty"`
	WordSize                int              `json:"word_size"`
	ByteOrder               string           `json:"byte_order"`
	HeaderRange             *GoMetadataRange `json:"header_range,omitempty"`
	VersionRange            *GoMetadataRange `json:"version_range,omitempty"`
	ModuleRange             *GoMetadataRange `json:"module_range,omitempty"`
	VersionSHA256           string           `json:"version_sha256,omitempty"`
	ModuleSHA256            string           `json:"module_sha256,omitempty"`
	VersionUTF8             bool             `json:"version_utf8"`
	ModuleUTF8              bool             `json:"module_utf8"`
	GoVersion               *string          `json:"go_version"`
	VersionPreviewComplete  bool             `json:"version_preview_complete"`
	ModuleFramingRecognized bool             `json:"module_framing_recognized"`
	ModuleBodyRange         *GoMetadataRange `json:"module_body_range,omitempty"`
	ModuleBodyUTF8          *bool            `json:"module_body_utf8,omitempty"`
	Part                    string           `json:"part"`
	Offset                  int              `json:"offset"`
	ReadBytes               int              `json:"read_bytes"`
	DataBase64              string           `json:"data_base64"`
	NextOffset              *int             `json:"next_offset,omitempty"`
	CoverageComplete        bool             `json:"coverage_complete"`
	ExecutionPerformed      bool             `json:"execution_performed"`
	Limitations             []string         `json:"limitations"`
	TotalRecords            int              `json:"total_records,omitempty"`
	UnparsedRecords         int              `json:"unparsed_records,omitempty"`
	GrammarComplete         bool             `json:"grammar_complete"`
	TextSummaryComplete     bool             `json:"text_summary_complete"`
	Records                 []GoModuleRecord `json:"records,omitempty"`
	Record                  *GoModuleRecord  `json:"record,omitempty"`
	DecodedField            *GoRecordField   `json:"decoded_field,omitempty"`
}
type goMetadata struct {
	format, encoding, order string
	word                    int
	header, version, module []byte
	hr, vr, mr              GoMetadataRange
}

func locateGoMetadata(body []byte) (*goMetadata, error) {
	image, err := targetidentity.ParseMappedImage(body)
	if err != nil {
		return nil, err
	}
	g := &goMetadata{format: image.Format, word: image.WordSize, order: "little-endian"}
	if image.Order == binary.BigEndian {
		g.order = "big-endian"
	}
	address, headerOffset := uint64(0), uint64(0)
	found := false
	var invalidHeader error
	scanned := uint64(0)
	for _, span := range image.GoData {
		if span.Size > MaxArtifactBytes || scanned+span.Size > MaxArtifactBytes {
			return nil, errors.New("Go build-info search exceeds snapshot budget")
		}
		scanned += span.Size
		data, off, err := image.FileBytes(span.Address, span.Size)
		if err != nil {
			return nil, err
		}
		for pos := 0; pos < len(data); {
			j := bytes.Index(data[pos:], goBuildMagic)
			if j < 0 {
				break
			}
			j += pos
			pos = j + len(goBuildMagic)
			if span.Address > math.MaxUint64-uint64(j) {
				return nil, errors.New("Go header address overflow")
			}
			candidate := span.Address + uint64(j)
			if candidate%16 != 0 {
				continue
			}
			candidateHeader, _, candidateErr := image.FileBytes(candidate, 32)
			if candidateErr != nil {
				invalidHeader = errors.New("recognized Go build-info header is truncated")
				continue
			}
			candidateWord, candidateFlags := int(candidateHeader[14]), candidateHeader[15]
			if candidateFlags&^byte(3) != 0 || (candidateWord != 4 && candidateWord != 8) || candidateWord != image.WordSize {
				invalidHeader = errors.New("Go build-info pointer/flags representation is unsupported")
				continue
			}
			if found {
				return nil, errors.New("multiple aligned Go build-info headers are ambiguous")
			}
			found = true
			address = candidate
			headerOffset = off + uint64(j)
		}
	}
	if !found {
		if invalidHeader != nil {
			return nil, invalidHeader
		}
		return g, nil
	}
	g.header, _, err = image.FileBytes(address, 32)
	if err != nil {
		return nil, errors.New("recognized Go build-info header is truncated")
	}
	g.hr = GoMetadataRange{headerOffset, 32, "original-file-bytes"}
	ptrSize := int(g.header[14])
	flags := g.header[15]
	if flags&^byte(3) != 0 || (ptrSize != 4 && ptrSize != 8) || ptrSize != image.WordSize {
		return nil, errors.New("Go build-info pointer/flags representation is unsupported")
	}
	g.word = ptrSize
	total := 0
	inline := func(addr uint64) ([]byte, GoMetadataRange, uint64, error) {
		length := uint64(0)
		n := 0
		for i := 0; i < 10; i++ {
			raw, _, err := image.FileBytes(addr+uint64(i), 1)
			if err != nil {
				return nil, GoMetadataRange{}, 0, err
			}
			x := raw[0]
			if i == 9 && x > 1 {
				return nil, GoMetadataRange{}, 0, errors.New("Go inline string varint overflows")
			}
			length |= uint64(x&127) << uint(i*7)
			n++
			if x < 128 {
				break
			}
			if i == 9 {
				return nil, GoMetadataRange{}, 0, errors.New("Go inline string varint is unterminated")
			}
		}
		if length > 1<<20 || total+int(length) > 1<<20 || addr > math.MaxUint64-uint64(n) || addr+uint64(n) > math.MaxUint64-length {
			return nil, GoMetadataRange{}, 0, errors.New("Go aggregate string budget/virtual range exceeded")
		}
		data, off, err := image.FileBytes(addr+uint64(n), length)
		if err != nil {
			return nil, GoMetadataRange{}, 0, err
		}
		total += len(data)
		return data, GoMetadataRange{off, length, "original-file-bytes"}, addr + uint64(n) + length, nil
	}
	if flags&2 != 0 {
		g.encoding = "inline-varint"
		var next uint64
		g.version, g.vr, next, err = inline(address + 32)
		if err != nil {
			return nil, err
		}
		g.module, g.mr, _, err = inline(next)
		if err != nil {
			return nil, err
		}
	} else {
		g.encoding = "pointer-string"
		var order binary.ByteOrder = binary.LittleEndian
		if flags&1 != 0 {
			order = binary.BigEndian
			g.order = "big-endian"
		} else {
			g.order = "little-endian"
		}
		pointer := func(b []byte) uint64 {
			if ptrSize == 4 {
				return uint64(order.Uint32(b))
			}
			return order.Uint64(b)
		}
		read := func(ptr uint64, optional bool, anchor uint64) ([]byte, GoMetadataRange, error) {
			stringHeader, headerOff, err := image.FileBytes(ptr, uint64(2*ptrSize))
			if err != nil {
				if optional && image.ZeroFill(ptr, uint64(2*ptrSize)) {
					return []byte{}, GoMetadataRange{anchor, 0, "zero-fill-empty-module-pointer-anchor"}, nil
				}
				return nil, GoMetadataRange{}, err
			}
			dataPtr, length := pointer(stringHeader[:ptrSize]), pointer(stringHeader[ptrSize:])
			if length > 1<<20 || total+int(length) > 1<<20 {
				return nil, GoMetadataRange{}, errors.New("Go aggregate string byte budget exceeded")
			}
			if length == 0 {
				return []byte{}, GoMetadataRange{headerOff + uint64(ptrSize), 0, "empty-string-length-field-anchor"}, nil
			}
			data, off, err := image.FileBytes(dataPtr, length)
			if err != nil {
				return nil, GoMetadataRange{}, err
			}
			total += len(data)
			return data, GoMetadataRange{off, length, "original-file-bytes"}, nil
		}
		g.version, g.vr, err = read(pointer(g.header[16:16+ptrSize]), false, headerOffset+16)
		if err != nil {
			return nil, err
		}
		g.module, g.mr, err = read(pointer(g.header[16+ptrSize:16+2*ptrSize]), true, headerOffset+uint64(16+ptrSize))
		if err != nil {
			return nil, err
		}
	}
	if len(g.version) == 0 {
		return nil, errors.New("recognized Go build-info compiler string is empty")
	}
	return g, nil
}

func ReadGoMetadata(p string, o GoMetadataOptions) (GoMetadataReport, error) {
	if o.Limit == 0 {
		if o.Part == "records" {
			o.Limit = 50
		} else {
			o.Limit = 8192
		}
	}
	if o.Offset < 0 || o.Limit < 1 || o.Limit > 16384 {
		return GoMetadataReport{}, errors.New("Go raw metadata offset must be nonnegative; limit must be 1..16384 bytes")
	}
	if o.Part == "" {
		o.Part = "module"
	}
	if o.Part != "module" && o.Part != "version" && o.Part != "header" && o.Part != "module-body" && o.Part != "records" && o.Part != "record-field" {
		return GoMetadataReport{}, errors.New("Go metadata part must be header, version, module, module-body, records or record-field")
	}
	if o.Part == "records" && o.Limit > 200 {
		return GoMetadataReport{}, errors.New("Go record page limit must be 1..200")
	}
	if o.Part == "record-field" {
		if o.RecordIndex == nil || *o.RecordIndex < 0 || *o.RecordIndex >= maxGoRecordCount || (o.Field != "path" && o.Field != "version" && o.Field != "sum" && o.Field != "key" && o.Field != "value") {
			return GoMetadataReport{}, errors.New("Go record-field requires exact record_index and decoded field name")
		}
	} else if o.RecordIndex != nil || o.Field != "" {
		return GoMetadataReport{}, errors.New("Go record/field selectors require record-field part")
	}
	if (o.Part == "records" || o.Part == "record-field") && o.Offset > 0 && o.ExpectedSHA256 == "" {
		return GoMetadataReport{}, errors.New("subsequent Go semantic pages require artifact SHA256")
	}
	body, abs, hash, err := readArtifact(p, MaxArtifactBytes, o.ExpectedSHA256)
	if err != nil {
		return GoMetadataReport{}, err
	}
	g, err := locateGoMetadata(body)
	if err != nil {
		return GoMetadataReport{}, err
	}
	r := GoMetadataReport{Path: abs, SHA256: hash, Format: g.format, WordSize: g.word, ByteOrder: g.order, Part: o.Part, Offset: o.Offset, Limitations: []string{"original header/version/module bytes, including framing and arbitrary encoding, are retained; no target execution or metadata authentication", "raw metadata availability does not imply a complete module/settings semantic parse", "zero-fill/empty historical module ranges are explicit anchors, not file-backed module contents", "missing build-info does not prove this is not a Go binary; fat Mach-O and nonnative containers are unsupported"}}
	if len(g.header) == 0 {
		if o.Offset != 0 {
			return r, errors.New("unavailable Go build-info requires zero offset")
		}
		r.UnavailableReason = "no aligned recognized Go build-info header in admitted data"
		return r, nil
	}
	r.BuildInfoAvailable = true
	r.Encoding = g.encoding
	r.HeaderRange = &g.hr
	r.VersionRange = &g.vr
	r.ModuleRange = &g.mr
	r.VersionSHA256 = digest(g.version)
	r.ModuleSHA256 = digest(g.module)
	r.VersionUTF8 = utf8.Valid(g.version)
	r.ModuleUTF8 = utf8.Valid(g.module)
	if r.VersionUTF8 {
		s := string(g.version)
		r.VersionPreviewComplete = len(s) <= 2048
		if len(s) > 2048 {
			s = s[:2048]
			for !utf8.ValidString(s) {
				s = s[:len(s)-1]
			}
		}
		r.GoVersion = &s
	}
	moduleBody, rng, framed := g.moduleBody()
	r.ModuleFramingRecognized = framed && len(g.module) > 0
	if framed {
		r.ModuleBodyRange = &rng
		valid := utf8.Valid(moduleBody)
		r.ModuleBodyUTF8 = &valid
	}
	content := g.module
	switch o.Part {
	case "header":
		content = g.header
	case "version":
		content = g.version
	case "module-body":
		if r.ModuleBodyRange == nil {
			return r, errors.New("module framing is not recognized; select original module bytes")
		}
		content = moduleBody
	case "records", "record-field":
		if !framed {
			return r, errors.New("Go semantic records require exact module framing; select original module bytes")
		}
		observation, err := parseGoModuleRecords(moduleBody, rng)
		if err != nil {
			return r, err
		}
		r.TotalRecords, r.UnparsedRecords = len(observation.rows), observation.unparsed
		r.GrammarComplete = observation.unparsed == 0
		r.TextSummaryComplete = observation.textComplete && r.VersionUTF8
		if o.Part == "records" {
			start, end, err := page(o.PageOptions, len(observation.rows))
			if err != nil {
				return r, err
			}
			r.Records = []GoModuleRecord{}
			for _, record := range observation.rows[start:end] {
				r.Records = append(r.Records, record.row)
			}
			for len(r.Records) > 0 && projectionLimit(r) != nil {
				r.Records = r.Records[:len(r.Records)-1]
				end--
			}
			if start < len(observation.rows) && len(r.Records) == 0 {
				return r, errors.New("single Go record projection exceeds profile")
			}
			r.CoverageComplete = start == 0 && end == len(observation.rows)
			if end < len(observation.rows) {
				r.NextOffset = &end
			}
			return r, projectionLimit(r)
		}
		if *o.RecordIndex >= len(observation.rows) {
			return r, errors.New("Go record_index outside current inventory")
		}
		record := observation.rows[*o.RecordIndex]
		value, ok := record.fields[o.Field]
		if !ok {
			return r, errors.New("selected Go record has no parsed field with that name")
		}
		r.Record = &record.row
		for _, field := range record.row.Fields {
			if field.Name == o.Field {
				selected := field
				r.DecodedField = &selected
			}
		}
		content = value
	}
	if o.Offset > len(content) {
		return r, errors.New("offset outside selected Go metadata string")
	}
	end := min(len(content), o.Offset+o.Limit)
	r.ReadBytes = end - o.Offset
	r.DataBase64 = base64.StdEncoding.EncodeToString(content[o.Offset:end])
	r.CoverageComplete = o.Offset == 0 && end == len(content)
	if end < len(content) {
		r.NextOffset = &end
	}
	return r, projectionLimit(r)
}
