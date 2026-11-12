package protocolinfer

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
)

type Sample struct {
	Name string `json:"name,omitempty"`
	Hex  string `json:"hex"`
}

type LengthCandidate struct {
	Offset   int    `json:"offset"`
	Width    int    `json:"width"`
	Endian   string `json:"endian"`
	Relation string `json:"relation"`
	Strength string `json:"strength"`
}

type ChecksumCandidate struct {
	Offset    int    `json:"offset"`
	Algorithm string `json:"algorithm"`
	Coverage  string `json:"coverage"`
	Strength  string `json:"strength"`
}

type OffsetVariation struct {
	Offset        int      `json:"offset"`
	DistinctBytes []string `json:"distinct_bytes"`
}

type Result struct {
	CorpusSHA256       string              `json:"corpus_sha256"`
	SampleCount        int                 `json:"sample_count"`
	MinLength          int                 `json:"min_length"`
	MaxLength          int                 `json:"max_length"`
	CommonPrefixHex    string              `json:"common_prefix_hex,omitempty"`
	CommonSuffixHex    string              `json:"common_suffix_hex,omitempty"`
	Variations         []OffsetVariation   `json:"variations,omitempty"`
	LengthCandidates   []LengthCandidate   `json:"length_candidates,omitempty"`
	ChecksumCandidates []ChecksumCandidate `json:"checksum_candidates,omitempty"`
	Strength           string              `json:"strength"`
}

func Analyze(samples []Sample) (Result, error) {
	decoded, err := Decode(samples)
	if err != nil {
		return Result{}, err
	}
	if len(decoded) < 2 {
		return Result{}, errors.New("at least two protocol samples are required")
	}
	minLen, maxLen := len(decoded[0]), len(decoded[0])
	distinctLengths := map[int]bool{}
	for _, sample := range decoded {
		if len(sample) < minLen {
			minLen = len(sample)
		}
		if len(sample) > maxLen {
			maxLen = len(sample)
		}
		distinctLengths[len(sample)] = true
	}
	result := Result{
		CorpusSHA256: corpusSHA256(decoded),
		SampleCount:  len(decoded), MinLength: minLen, MaxLength: maxLen,
		CommonPrefixHex: hex.EncodeToString(commonPrefix(decoded)),
		CommonSuffixHex: hex.EncodeToString(commonSuffix(decoded)),
		Variations:      offsetVariations(decoded, minLen), Strength: "candidate",
	}
	if len(distinctLengths) > 1 {
		result.LengthCandidates = inferLengthFields(decoded, minLen)
	}
	result.ChecksumCandidates = inferChecksums(decoded)
	return result, nil
}

func Decode(samples []Sample) ([][]byte, error) {
	result := make([][]byte, 0, len(samples))
	for index, sample := range samples {
		raw := strings.Map(func(r rune) rune {
			switch r {
			case ' ', '\n', '\r', '\t', ':':
				return -1
			default:
				return r
			}
		}, strings.TrimSpace(sample.Hex))
		if raw == "" {
			return nil, fmt.Errorf("sample %d is empty", index)
		}
		body, err := hex.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("decode sample %d: %w", index, err)
		}
		result = append(result, body)
	}
	return result, nil
}

func ValidateLength(sample []byte, candidate LengthCandidate) bool {
	value, ok := readLength(sample, candidate.Offset, candidate.Width, candidate.Endian)
	if !ok {
		return false
	}
	switch candidate.Relation {
	case "total-length":
		return value == uint64(len(sample))
	case "payload-after-field":
		return value == uint64(len(sample)-(candidate.Offset+candidate.Width))
	default:
		return false
	}
}

func ValidateChecksum(sample []byte, candidate ChecksumCandidate) bool {
	offset := candidate.Offset
	if offset == -1 {
		offset = len(sample) - 1
	}
	if offset < 0 || offset >= len(sample) || offset != len(sample)-1 {
		return false
	}
	body := sample[:offset]
	switch candidate.Algorithm {
	case "sum8":
		var sum byte
		for _, value := range body {
			sum += value
		}
		return sample[offset] == sum
	case "xor8":
		var xor byte
		for _, value := range body {
			xor ^= value
		}
		return sample[offset] == xor
	default:
		return false
	}
}

func RebuildLength(sample []byte, candidate LengthCandidate) ([]byte, error) {
	if candidate.Offset < 0 || candidate.Width <= 0 || candidate.Offset+candidate.Width > len(sample) {
		return nil, errors.New("length field is outside sample")
	}
	result := append([]byte(nil), sample...)
	var value uint64
	switch candidate.Relation {
	case "total-length":
		value = uint64(len(result))
	case "payload-after-field":
		value = uint64(len(result) - (candidate.Offset + candidate.Width))
	default:
		return nil, fmt.Errorf("unsupported length relation %q", candidate.Relation)
	}
	if !writeLength(result, candidate.Offset, candidate.Width, candidate.Endian, value) {
		return nil, errors.New("length value does not fit candidate width")
	}
	return result, nil
}

func KaitaiSkeleton(id string, result Result) string {
	id = sanitizeID(id)
	if id == "" {
		id = "candidate_protocol"
	}
	lines := []string{
		"meta:",
		"  id: " + id,
		"  endian: le",
		"seq:",
	}
	var primary *LengthCandidate
	for index := range result.LengthCandidates {
		candidate := &result.LengthCandidates[index]
		if candidate.Offset == 0 && candidate.Relation == "total-length" && (candidate.Width == 2 || candidate.Width == 4) {
			primary = candidate
			break
		}
	}
	if primary == nil {
		lines = append(lines,
			"  - id: raw",
			"    size-eos: true",
			"# Candidate only: no validated framing field was inferred.")
		return strings.Join(lines, "\n") + "\n"
	}
	typeName := fmt.Sprintf("u%d%s", primary.Width, map[string]string{"little": "le", "big": "be"}[primary.Endian])
	lines = append(lines,
		"  - id: frame_len",
		"    type: "+typeName,
		"  - id: frame_body",
		fmt.Sprintf("    size: frame_len - %d", primary.Width),
		"# Candidate only: validate round-trip and message semantics before treating this as a protocol schema.")
	return strings.Join(lines, "\n") + "\n"
}

func inferLengthFields(samples [][]byte, minLen int) []LengthCandidate {
	result := make([]LengthCandidate, 0)
	for _, width := range []int{1, 2, 4} {
		for offset := 0; offset+width <= minLen; offset++ {
			for _, endian := range []string{"little", "big"} {
				for _, relation := range []string{"total-length", "payload-after-field"} {
					candidate := LengthCandidate{Offset: offset, Width: width, Endian: endian, Relation: relation, Strength: "candidate"}
					all := true
					for _, sample := range samples {
						if !ValidateLength(sample, candidate) {
							all = false
							break
						}
					}
					if all {
						result = append(result, candidate)
					}
				}
			}
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Offset != result[j].Offset {
			return result[i].Offset < result[j].Offset
		}
		if result[i].Width != result[j].Width {
			return result[i].Width < result[j].Width
		}
		if result[i].Relation != result[j].Relation {
			return result[i].Relation < result[j].Relation
		}
		return result[i].Endian < result[j].Endian
	})
	return result
}

func inferChecksums(samples [][]byte) []ChecksumCandidate {
	if len(samples) == 0 {
		return nil
	}
	result := make([]ChecksumCandidate, 0, 2)
	for _, algorithm := range []string{"sum8", "xor8"} {
		all := true
		for _, sample := range samples {
			if len(sample) < 2 || !ValidateChecksum(sample, ChecksumCandidate{Offset: len(sample) - 1, Algorithm: algorithm}) {
				all = false
				break
			}
		}
		if all {
			result = append(result, ChecksumCandidate{
				Offset: -1, Algorithm: algorithm, Coverage: "all-bytes-before-final-byte", Strength: "candidate",
			})
		}
	}
	return result
}

func commonPrefix(samples [][]byte) []byte {
	if len(samples) == 0 {
		return nil
	}
	limit := len(samples[0])
	for _, sample := range samples[1:] {
		if len(sample) < limit {
			limit = len(sample)
		}
	}
	index := 0
	for index < limit {
		value := samples[0][index]
		match := true
		for _, sample := range samples[1:] {
			if sample[index] != value {
				match = false
				break
			}
		}
		if !match {
			break
		}
		index++
	}
	return append([]byte(nil), samples[0][:index]...)
}

func commonSuffix(samples [][]byte) []byte {
	if len(samples) == 0 {
		return nil
	}
	minLen := len(samples[0])
	for _, sample := range samples[1:] {
		if len(sample) < minLen {
			minLen = len(sample)
		}
	}
	count := 0
	for count < minLen {
		value := samples[0][len(samples[0])-1-count]
		match := true
		for _, sample := range samples[1:] {
			if sample[len(sample)-1-count] != value {
				match = false
				break
			}
		}
		if !match {
			break
		}
		count++
	}
	return append([]byte(nil), samples[0][len(samples[0])-count:]...)
}

func offsetVariations(samples [][]byte, minLen int) []OffsetVariation {
	result := make([]OffsetVariation, 0)
	for offset := 0; offset < minLen; offset++ {
		seen := map[byte]bool{}
		for _, sample := range samples {
			seen[sample[offset]] = true
		}
		if len(seen) <= 1 {
			continue
		}
		values := make([]int, 0, len(seen))
		for value := range seen {
			values = append(values, int(value))
		}
		sort.Ints(values)
		item := OffsetVariation{Offset: offset}
		for _, value := range values {
			item.DistinctBytes = append(item.DistinctBytes, fmt.Sprintf("%02x", value))
		}
		result = append(result, item)
	}
	return result
}

func readLength(sample []byte, offset, width int, endian string) (uint64, bool) {
	if offset < 0 || width <= 0 || offset+width > len(sample) {
		return 0, false
	}
	body := sample[offset : offset+width]
	switch width {
	case 1:
		return uint64(body[0]), true
	case 2:
		if endian == "little" {
			return uint64(binary.LittleEndian.Uint16(body)), true
		}
		if endian == "big" {
			return uint64(binary.BigEndian.Uint16(body)), true
		}
	case 4:
		if endian == "little" {
			return uint64(binary.LittleEndian.Uint32(body)), true
		}
		if endian == "big" {
			return uint64(binary.BigEndian.Uint32(body)), true
		}
	}
	return 0, false
}

func writeLength(sample []byte, offset, width int, endian string, value uint64) bool {
	if offset < 0 || offset+width > len(sample) {
		return false
	}
	body := sample[offset : offset+width]
	switch width {
	case 1:
		if value > 0xff {
			return false
		}
		body[0] = byte(value)
		return true
	case 2:
		if value > 0xffff {
			return false
		}
		if endian == "little" {
			binary.LittleEndian.PutUint16(body, uint16(value))
			return true
		}
		if endian == "big" {
			binary.BigEndian.PutUint16(body, uint16(value))
			return true
		}
	case 4:
		if value > 0xffffffff {
			return false
		}
		if endian == "little" {
			binary.LittleEndian.PutUint32(body, uint32(value))
			return true
		}
		if endian == "big" {
			binary.BigEndian.PutUint32(body, uint32(value))
			return true
		}
	}
	return false
}

func sanitizeID(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var out strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_':
			out.WriteRune(r)
		case r == '-' || r == ' ':
			out.WriteByte('_')
		}
	}
	return strings.Trim(out.String(), "_")
}

func corpusSHA256(samples [][]byte) string {
	hash := sha256.New()
	for _, sample := range samples {
		digest := sha256.Sum256(sample)
		hash.Write(digest[:])
		hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}
