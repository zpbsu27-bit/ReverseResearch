package protocolinfer

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestAnalyzeFindsLengthFieldAndVariation(t *testing.T) {
	samples := []Sample{
		{Name: "a", Hex: frameHex([]byte{0x10, 0x20})},
		{Name: "b", Hex: frameHex([]byte{0x10, 0x21, 0x22})},
		{Name: "c", Hex: frameHex([]byte{0x10, 0x30, 0x31, 0x32})},
	}
	got, err := Analyze(samples)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, candidate := range got.LengthCandidates {
		if candidate.Offset == 0 && candidate.Width == 2 && candidate.Endian == "little" && candidate.Relation == "total-length" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("length candidates=%+v", got.LengthCandidates)
	}
	if len(got.CorpusSHA256) != 64 || got.MinLength != 5 || got.MaxLength != 7 || len(got.Variations) == 0 || got.Strength != "candidate" {
		t.Fatalf("analysis=%+v", got)
	}
	if skeleton := KaitaiSkeleton("Demo Protocol", got); !strings.Contains(skeleton, "frame_len") || !strings.Contains(skeleton, "Candidate only") {
		t.Fatalf("skeleton=%s", skeleton)
	}
}

func TestChecksumCandidatesAndValidation(t *testing.T) {
	samples := []Sample{
		{Hex: hex.EncodeToString(withSum8([]byte{1, 2, 3}))},
		{Hex: hex.EncodeToString(withSum8([]byte{4, 5, 6, 7}))},
	}
	got, err := Analyze(samples)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, candidate := range got.ChecksumCandidates {
		if candidate.Algorithm == "sum8" {
			found = true
		}
	}
	if !found {
		t.Fatalf("checksum candidates=%+v", got.ChecksumCandidates)
	}
}

func TestRebuildLengthRoundTrip(t *testing.T) {
	body := []byte{0, 0, 0xaa, 0xbb, 0xcc}
	candidate := LengthCandidate{Offset: 0, Width: 2, Endian: "little", Relation: "total-length"}
	rebuilt, err := RebuildLength(body, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if !ValidateLength(rebuilt, candidate) || rebuilt[2] != 0xaa {
		t.Fatalf("rebuilt=%x", rebuilt)
	}
}

func frameHex(payload []byte) string {
	body := make([]byte, 2+len(payload)+1)
	body[0] = byte(len(body))
	body[1] = 0
	copy(body[2:], payload)
	var sum byte
	for _, value := range body[:len(body)-1] {
		sum += value
	}
	body[len(body)-1] = sum
	return hex.EncodeToString(body)
}

func withSum8(body []byte) []byte {
	result := append([]byte(nil), body...)
	var sum byte
	for _, value := range body {
		sum += value
	}
	return append(result, sum)
}
