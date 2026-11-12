package memscan

import (
	"testing"
)

func TestValueEncodingAndOrdering(t *testing.T) {
	for _, test := range []struct {
		valueType string
		value     string
		want      string
	}{
		{valueType: "u32", value: "0x2A", want: "42"},
		{valueType: "i16", value: "-7", want: "-7"},
		{valueType: "f32", value: "1.5", want: "1.5"},
		{valueType: "f64", value: "-2.25", want: "-2.25"},
	} {
		desc, err := descriptor(test.valueType)
		if err != nil {
			t.Fatal(err)
		}
		raw, canonical, err := encodeValue(desc, test.value)
		if err != nil {
			t.Fatal(err)
		}
		if canonical != test.want {
			t.Fatalf("%s canonical=%s want=%s", test.valueType, canonical, test.want)
		}
		decoded, err := decodeValue(desc, raw)
		if err != nil || decoded != test.want {
			t.Fatalf("%s decoded=%s err=%v", test.valueType, decoded, err)
		}
	}
}

func TestCompareSignedAndFloatValues(t *testing.T) {
	for _, test := range []struct {
		valueType string
		left      string
		right     string
		want      int
	}{
		{valueType: "i32", left: "-5", right: "-2", want: 1},
		{valueType: "i32", left: "-2", right: "-5", want: -1},
		{valueType: "u64", left: "9", right: "10", want: 1},
		{valueType: "f64", left: "1.25", right: "1.5", want: 1},
	} {
		desc, _ := descriptor(test.valueType)
		left, _, _ := encodeValue(desc, test.left)
		right, _, _ := encodeValue(desc, test.right)
		got, err := compareValue(desc, left, right)
		if err != nil || got != test.want {
			t.Fatalf("%s %s -> %s got=%d err=%v", test.valueType, test.left, test.right, got, err)
		}
	}
}
