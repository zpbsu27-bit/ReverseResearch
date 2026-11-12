package memscan

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"strconv"
	"strings"
)

type valueDescriptor struct {
	name   string
	size   int
	bits   int
	signed bool
	float  bool
}

func descriptor(valueType string) (valueDescriptor, error) {
	switch strings.ToLower(strings.TrimSpace(valueType)) {
	case "u8":
		return valueDescriptor{name: "u8", size: 1, bits: 8}, nil
	case "i8":
		return valueDescriptor{name: "i8", size: 1, bits: 8, signed: true}, nil
	case "u16":
		return valueDescriptor{name: "u16", size: 2, bits: 16}, nil
	case "i16":
		return valueDescriptor{name: "i16", size: 2, bits: 16, signed: true}, nil
	case "u32":
		return valueDescriptor{name: "u32", size: 4, bits: 32}, nil
	case "i32":
		return valueDescriptor{name: "i32", size: 4, bits: 32, signed: true}, nil
	case "u64":
		return valueDescriptor{name: "u64", size: 8, bits: 64}, nil
	case "i64":
		return valueDescriptor{name: "i64", size: 8, bits: 64, signed: true}, nil
	case "f32":
		return valueDescriptor{name: "f32", size: 4, bits: 32, float: true}, nil
	case "f64":
		return valueDescriptor{name: "f64", size: 8, bits: 64, float: true}, nil
	default:
		return valueDescriptor{}, fmt.Errorf("unsupported value type %q; use u8/i8/u16/i16/u32/i32/u64/i64/f32/f64", valueType)
	}
}

func encodeValue(desc valueDescriptor, text string) ([]byte, string, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, "", fmt.Errorf("%s value is required", desc.name)
	}
	raw := make([]byte, desc.size)
	if desc.float {
		number, err := strconv.ParseFloat(text, desc.bits)
		if err != nil {
			return nil, "", fmt.Errorf("parse %s value %q: %w", desc.name, text, err)
		}
		if desc.bits == 32 {
			binary.LittleEndian.PutUint32(raw, math.Float32bits(float32(number)))
			return raw, strconv.FormatFloat(float64(float32(number)), 'g', -1, 32), nil
		}
		binary.LittleEndian.PutUint64(raw, math.Float64bits(number))
		return raw, strconv.FormatFloat(number, 'g', -1, 64), nil
	}
	if desc.signed {
		number, err := strconv.ParseInt(text, 0, desc.bits)
		if err != nil {
			return nil, "", fmt.Errorf("parse %s value %q: %w", desc.name, text, err)
		}
		switch desc.size {
		case 1:
			raw[0] = byte(number)
		case 2:
			binary.LittleEndian.PutUint16(raw, uint16(number))
		case 4:
			binary.LittleEndian.PutUint32(raw, uint32(number))
		case 8:
			binary.LittleEndian.PutUint64(raw, uint64(number))
		}
		return raw, strconv.FormatInt(number, 10), nil
	}
	number, err := strconv.ParseUint(text, 0, desc.bits)
	if err != nil {
		return nil, "", fmt.Errorf("parse %s value %q: %w", desc.name, text, err)
	}
	switch desc.size {
	case 1:
		raw[0] = byte(number)
	case 2:
		binary.LittleEndian.PutUint16(raw, uint16(number))
	case 4:
		binary.LittleEndian.PutUint32(raw, uint32(number))
	case 8:
		binary.LittleEndian.PutUint64(raw, number)
	}
	return raw, strconv.FormatUint(number, 10), nil
}

func decodeValue(desc valueDescriptor, raw []byte) (string, error) {
	if len(raw) != desc.size {
		return "", fmt.Errorf("decode %s requires %d bytes, got %d", desc.name, desc.size, len(raw))
	}
	if desc.float {
		if desc.bits == 32 {
			return strconv.FormatFloat(float64(math.Float32frombits(binary.LittleEndian.Uint32(raw))), 'g', -1, 32), nil
		}
		return strconv.FormatFloat(math.Float64frombits(binary.LittleEndian.Uint64(raw)), 'g', -1, 64), nil
	}
	if desc.signed {
		switch desc.size {
		case 1:
			return strconv.FormatInt(int64(int8(raw[0])), 10), nil
		case 2:
			return strconv.FormatInt(int64(int16(binary.LittleEndian.Uint16(raw))), 10), nil
		case 4:
			return strconv.FormatInt(int64(int32(binary.LittleEndian.Uint32(raw))), 10), nil
		case 8:
			return strconv.FormatInt(int64(binary.LittleEndian.Uint64(raw)), 10), nil
		}
	}
	switch desc.size {
	case 1:
		return strconv.FormatUint(uint64(raw[0]), 10), nil
	case 2:
		return strconv.FormatUint(uint64(binary.LittleEndian.Uint16(raw)), 10), nil
	case 4:
		return strconv.FormatUint(uint64(binary.LittleEndian.Uint32(raw)), 10), nil
	case 8:
		return strconv.FormatUint(binary.LittleEndian.Uint64(raw), 10), nil
	}
	return "", fmt.Errorf("invalid value descriptor %+v", desc)
}

func compareValue(desc valueDescriptor, previous, current []byte) (int, error) {
	if len(previous) != desc.size || len(current) != desc.size {
		return 0, fmt.Errorf("compare %s requires %d-byte values", desc.name, desc.size)
	}
	if bytes.Equal(previous, current) {
		return 0, nil
	}
	if desc.float {
		var left, right float64
		if desc.bits == 32 {
			left = float64(math.Float32frombits(binary.LittleEndian.Uint32(previous)))
			right = float64(math.Float32frombits(binary.LittleEndian.Uint32(current)))
		} else {
			left = math.Float64frombits(binary.LittleEndian.Uint64(previous))
			right = math.Float64frombits(binary.LittleEndian.Uint64(current))
		}
		if math.IsNaN(left) || math.IsNaN(right) {
			return 0, nil
		}
		if right > left {
			return 1, nil
		}
		return -1, nil
	}
	if desc.signed {
		var left, right int64
		switch desc.size {
		case 1:
			left, right = int64(int8(previous[0])), int64(int8(current[0]))
		case 2:
			left, right = int64(int16(binary.LittleEndian.Uint16(previous))), int64(int16(binary.LittleEndian.Uint16(current)))
		case 4:
			left, right = int64(int32(binary.LittleEndian.Uint32(previous))), int64(int32(binary.LittleEndian.Uint32(current)))
		case 8:
			left, right = int64(binary.LittleEndian.Uint64(previous)), int64(binary.LittleEndian.Uint64(current))
		}
		if right > left {
			return 1, nil
		}
		return -1, nil
	}
	var left, right uint64
	switch desc.size {
	case 1:
		left, right = uint64(previous[0]), uint64(current[0])
	case 2:
		left, right = uint64(binary.LittleEndian.Uint16(previous)), uint64(binary.LittleEndian.Uint16(current))
	case 4:
		left, right = uint64(binary.LittleEndian.Uint32(previous)), uint64(binary.LittleEndian.Uint32(current))
	case 8:
		left, right = binary.LittleEndian.Uint64(previous), binary.LittleEndian.Uint64(current)
	}
	if right > left {
		return 1, nil
	}
	return -1, nil
}

func candidateFromRaw(address uint64, raw []byte, desc valueDescriptor, region RegionIdentity) (Candidate, error) {
	value, err := decodeValue(desc, raw)
	if err != nil {
		return Candidate{}, err
	}
	return Candidate{
		Address: address, AddressHex: fmt.Sprintf("0x%X", address),
		RawHex: hex.EncodeToString(raw), Value: value, Region: region,
	}, nil
}

func rawCandidate(candidate Candidate, size int) ([]byte, error) {
	raw, err := hex.DecodeString(candidate.RawHex)
	if err != nil || len(raw) != size {
		return nil, fmt.Errorf("candidate %s has invalid raw value", candidate.AddressHex)
	}
	return raw, nil
}
