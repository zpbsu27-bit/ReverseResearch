package appinspect

import (
	"errors"
	"unicode/utf16"
)

// DEX and AAPT string pools encode UTF-16 code units in modified UTF-8.
// Pools also admit standard four-byte UTF-8; DEX explicitly forbids it.
// Unpaired surrogates remain code units and never become replacement text.
func decodeAndroidUTF8(raw []byte, expected int, fourByte bool) ([]uint16, error) {
	if expected < 0 || expected > 1<<20 || len(raw) > expected*3 {
		return nil, errors.New("Android UTF-8 exceeds declared UTF-16 length")
	}
	units := make([]uint16, 0, expected)
	for at := 0; at < len(raw); {
		a := raw[at]
		at++
		var value uint32
		more := 0
		switch {
		case a < 0x80:
			value = uint32(a)
		case a >= 0xc0 && a <= 0xdf:
			value, more = uint32(a&0x1f), 1
		case a >= 0xe0 && a <= 0xef:
			value, more = uint32(a&0x0f), 2
		case fourByte && a >= 0xf0 && a <= 0xf4:
			value, more = uint32(a&7), 3
		default:
			return nil, errors.New("Android UTF-8 leading byte invalid")
		}
		if more > len(raw)-at {
			return nil, errors.New("truncated Android UTF-8 continuation")
		}
		for end := at + more; at < end; at++ {
			if raw[at]&0xc0 != 0x80 {
				return nil, errors.New("Android UTF-8 continuation invalid")
			}
			value = value<<6 | uint32(raw[at]&0x3f)
		}
		if more == 1 && value < 0x80 && !(a == 0xc0 && value == 0) || more == 2 && value < 0x800 || more == 3 && (value < 0x10000 || value > 0x10ffff) {
			return nil, errors.New("overlong or out-of-range Android UTF-8")
		}
		if more == 3 {
			value -= 0x10000
			units = append(units, uint16(0xd800+(value>>10)), uint16(0xdc00+(value&0x3ff)))
		} else {
			units = append(units, uint16(value))
		}
		if len(units) > expected {
			return nil, errors.New("Android UTF-8 exceeds declared UTF-16 length")
		}
	}
	if len(units) != expected {
		return nil, errors.New("Android UTF-8/UTF-16 length mismatch")
	}
	return units, nil
}

func androidUTF16Text(units []uint16) (string, bool) {
	for i := 0; i < len(units); i++ {
		v := units[i]
		if v >= 0xd800 && v <= 0xdbff {
			if i+1 >= len(units) || units[i+1] < 0xdc00 || units[i+1] > 0xdfff {
				return "", false
			}
			i++
		} else if v >= 0xdc00 && v <= 0xdfff {
			return "", false
		}
	}
	return string(utf16.Decode(units)), true
}
