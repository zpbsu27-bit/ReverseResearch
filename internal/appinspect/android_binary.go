package appinspect

import (
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
)

// Android compiled XML and resource tables share this chunk/string/value owner.
// Offsets always refer to one captured member, never an extracted filesystem.
type androidChunk struct {
	kind                uint16
	start, header, size int
	body                []byte
}
type androidBudget struct{ decoded, spans uint64 }
type androidPoolString struct {
	text      string
	valid     bool
	units     []uint16
	off, size int
}
type androidPool struct {
	strings []androidPoolString
	body    []byte
	values  map[int]AndroidStringValue
}

type AndroidStringValue struct {
	Index         uint32  `json:"pool_index"`
	Text          *string `json:"text"`
	TextComplete  bool    `json:"text_complete"`
	UTF8Available bool    `json:"utf8_available"`
	UTF16Units    int     `json:"utf16_units"`
	Offset        int     `json:"encoded_offset"`
	Bytes         int     `json:"encoded_bytes"`
	SHA256        string  `json:"encoded_sha256"`
	RangeBasis    string  `json:"range_basis"`
	DataBase64    string  `json:"encoded_base64,omitempty"`
}

type AndroidValue struct {
	Type   uint8               `json:"data_type"`
	Data   uint32              `json:"raw_data"`
	String *AndroidStringValue `json:"string,omitempty"`
}

func androidChunkAt(body []byte, off int) (androidChunk, error) {
	if off < 0 || off%4 != 0 || off > len(body)-8 {
		return androidChunk{}, errors.New("Android chunk header outside aligned bytes")
	}
	h, size := int(u16(body[off+2:])), uint64(u32(body[off+4:]))
	if h < 8 || h%4 != 0 || size < uint64(h) || size%4 != 0 || size > uint64(len(body)-off) {
		return androidChunk{}, errors.New("Android chunk size/header/alignment invalid")
	}
	return androidChunk{u16(body[off:]), off, h, int(size), body[off : off+int(size)]}, nil
}

func androidLength(b []byte, at *int, wide bool) (uint32, error) {
	if wide {
		if *at > len(b)-2 {
			return 0, errors.New("truncated Android UTF-16 length")
		}
		v := uint32(u16(b[*at:]))
		*at += 2
		if v&0x8000 != 0 {
			if *at > len(b)-2 {
				return 0, errors.New("truncated long Android UTF-16 length")
			}
			v = (v&0x7fff)<<16 | uint32(u16(b[*at:]))
			*at += 2
		}
		return v, nil
	}
	if *at >= len(b) {
		return 0, errors.New("truncated Android UTF-8 length")
	}
	v := uint32(b[*at])
	*at++
	if v&0x80 != 0 {
		if *at >= len(b) {
			return 0, errors.New("truncated long Android UTF-8 length")
		}
		v = (v&0x7f)<<8 | uint32(b[*at])
		*at++
	}
	return v, nil
}

func parseAndroidPool(c androidChunk, body []byte, budget *androidBudget) (*androidPool, error) {
	if c.kind != 1 || c.header < 28 {
		return nil, errors.New("Android string-pool header invalid")
	}
	b := c.body
	n, styles, flags := u32(b[8:]), u32(b[12:]), u32(b[16:])
	start, styleStart := uint64(u32(b[20:])), uint64(u32(b[24:]))
	indexesEnd := uint64(c.header) + uint64(n+styles)*4
	if n > 1<<20 || styles > n || flags&^uint32(0x101) != 0 || indexesEnd > uint64(len(b)) || start < indexesEnd || start > uint64(len(b)) {
		return nil, errors.New("Android string-pool counts/flags/indexes invalid")
	}
	end := uint64(len(b))
	if styles > 0 {
		if styleStart < start || styleStart > uint64(len(b)) || styleStart%4 != 0 {
			return nil, errors.New("Android style table outside pool")
		}
		end = styleStart
	} else if styleStart != 0 {
		return nil, errors.New("Android empty style table has an offset")
	}
	p := &androidPool{strings: make([]androidPoolString, int(n)), body: body, values: map[int]AndroidStringValue{}}
	cache := map[uint32]androidPoolString{}
	for i := 0; i < int(n); i++ {
		rel := u32(b[c.header+i*4:])
		s, ok := cache[rel]
		if !ok {
			pos := start + uint64(rel)
			if pos >= end {
				return nil, errors.New("Android string offset outside pool data")
			}
			raw := b[pos:end]
			at := 0
			units, err := androidLength(raw, &at, flags&0x100 == 0)
			if err != nil {
				return nil, err
			}
			if units > 1<<20 {
				return nil, errors.New("Android string exceeds 1M UTF-16 units")
			}
			budget.decoded += uint64(units) * 2
			if budget.decoded > 32<<20 {
				return nil, errors.New("Android decoded strings exceed 32 MiB")
			}
			s.off = c.start + int(pos)
			if flags&0x100 != 0 {
				length, err := androidLength(raw, &at, false)
				if err != nil {
					return nil, err
				}
				if uint64(at)+uint64(length)+1 > uint64(len(raw)) || raw[at+int(length)] != 0 {
					return nil, errors.New("Android UTF-8 string range/encoding/terminator invalid")
				}
				s.units, err = decodeAndroidUTF8(raw[at:at+int(length)], int(units), true)
				if err != nil {
					return nil, err
				}
				s.text, s.valid = androidUTF16Text(s.units)
				s.size = at + int(length) + 1
			} else {
				if uint64(at)+uint64(units)*2+2 > uint64(len(raw)) || u16(raw[at+int(units)*2:]) != 0 {
					return nil, errors.New("Android UTF-16 string range/terminator invalid")
				}
				s.units = make([]uint16, int(units))
				for j := range s.units {
					s.units[j] = u16(raw[at+j*2:])
				}
				s.text, s.valid = androidUTF16Text(s.units)
				s.size = at + len(s.units)*2 + 2
			}
			cache[rel] = s
		}
		p.strings[i] = s
		if flags&1 != 0 && i > 0 && slices.Compare(p.strings[i-1].units, s.units) > 0 {
			return nil, errors.New("Android SORTED string pool is not UTF-16 sorted")
		}
	}
	// Shared style arrays are scanned once; each alias still checks its own
	// string length. This avoids quadratic work on shared span declarations.
	spanMax := map[uint32]uint32{}
	for i := 0; i < int(styles); i++ {
		rel := u32(b[c.header+int(n)*4+i*4:])
		if rel == 0xffffffff {
			continue
		}
		maxChar, ok := spanMax[rel]
		if !ok {
			at := styleStart + uint64(rel)
			maxChar = 0
			for {
				if at+4 > uint64(len(b)) {
					return nil, errors.New("unterminated Android style span")
				}
				name := u32(b[at:])
				if name == 0xffffffff {
					break
				}
				if at+12 > uint64(len(b)) || name >= n {
					return nil, errors.New("Android style name/range invalid")
				}
				first, last := u32(b[at+4:]), u32(b[at+8:])
				if last < first {
					return nil, errors.New("Android style character range inverted")
				}
				maxChar = max(maxChar, last+1)
				if last == 0xffffffff {
					return nil, errors.New("Android style character range overflow")
				}
				budget.spans++
				if budget.spans > 1<<20 {
					return nil, errors.New("Android style work exceeds 1M spans")
				}
				at += 12
			}
			spanMax[rel] = maxChar
		}
		if maxChar > uint32(len(p.strings[i].units)) {
			return nil, errors.New("Android style exceeds referenced string")
		}
	}
	return p, nil
}

func (p *androidPool) name(index uint32, optional bool) (string, error) {
	if optional && index == 0xffffffff {
		return "", nil
	}
	if p == nil || uint64(index) >= uint64(len(p.strings)) {
		return "", errors.New("Android string reference outside pool")
	}
	s := p.strings[index]
	if !s.valid || len(s.text) > 4096 {
		return "", errors.New("Android identifier is unpaired UTF-16 or exceeds 4096 bytes")
	}
	return s.text, nil
}

func (p *androidPool) value(index uint32) (*AndroidStringValue, error) {
	if p == nil || uint64(index) >= uint64(len(p.strings)) {
		return nil, errors.New("Android value string reference outside pool")
	}
	s := p.strings[index]
	if cached, ok := p.values[s.off]; ok {
		cached.Index = index
		return &cached, nil
	}
	v := &AndroidStringValue{Index: index, UTF8Available: s.valid, UTF16Units: len(s.units), Offset: s.off, Bytes: s.size, SHA256: digest(p.body[s.off : s.off+s.size])}
	v.RangeBasis = "string-pool-encoded-item"
	if s.valid {
		runes := []rune(s.text)
		text := s.text
		v.TextComplete = len(runes) <= 1024
		if !v.TextComplete {
			text = string(runes[:1024])
		}
		v.Text = &text
	}
	if s.size <= 4096 {
		v.DataBase64 = base64.StdEncoding.EncodeToString(p.body[s.off : s.off+s.size])
	}
	p.values[s.off] = *v
	return v, nil
}

func androidTypedValue(b []byte, p *androidPool) (AndroidValue, error) {
	if len(b) < 8 || u16(b) != 8 || b[2] != 0 {
		return AndroidValue{}, errors.New("Android typed-value header invalid")
	}
	v := AndroidValue{Type: b[3], Data: u32(b[4:])}
	if v.Type == 3 {
		s, err := p.value(v.Data)
		if err != nil {
			return v, err
		}
		v.String = s
	}
	return v, nil
}

func androidUnknownChunk(kind uint16) error {
	return fmt.Errorf("unsupported Android chunk 0x%04x; no semantic projection accepted", kind)
}
