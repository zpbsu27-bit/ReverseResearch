package protocolinfer

import (
	"testing"
)

func TestValidateModelRequiresIndependentFixtures(t *testing.T) {
	modelSamples := []Sample{
		{Name: "a", Hex: frameHex([]byte{0x10, 0x20})},
		{Name: "b", Hex: frameHex([]byte{0x10, 0x21, 0x22})},
		{Name: "c", Hex: frameHex([]byte{0x10, 0x30, 0x31, 0x32})},
	}
	model, err := Analyze(modelSamples)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateModel(model, modelSamples); err == nil {
		t.Fatal("same corpus was accepted as independent validation")
	}

	fixtures := []Sample{
		{Name: "v1", Hex: frameHex([]byte{0x55, 0x66, 0x77, 0x88})},
		{Name: "v2", Hex: frameHex([]byte{0x99, 0xaa, 0xbb, 0xcc, 0xdd})},
	}
	got, err := ValidateModel(model, fixtures)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Validated || got.FixtureCorpusSHA256 == model.CorpusSHA256 || len(got.Checks) == 0 {
		t.Fatalf("validation=%+v", got)
	}
}

func TestValidateModelFailsWhenFixtureBreaksCandidate(t *testing.T) {
	modelSamples := []Sample{
		{Hex: frameHex([]byte{1, 2})},
		{Hex: frameHex([]byte{1, 2, 3})},
	}
	model, err := Analyze(modelSamples)
	if err != nil {
		t.Fatal(err)
	}
	bad := []Sample{
		{Hex: "0000010200"},
		{Hex: "000001020300"},
	}
	got, err := ValidateModel(model, bad)
	if err != nil {
		t.Fatal(err)
	}
	if got.Validated {
		t.Fatalf("invalid fixtures unexpectedly validated: %+v", got)
	}
}
