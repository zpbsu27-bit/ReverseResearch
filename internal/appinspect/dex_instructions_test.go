package appinspect

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"reverseresearch/internal/appinspect/testfixture"
)

func dexCodeVector(t *testing.T, units []uint16, regs, outs uint16) (*dexImage, uint32, dexCode) {
	t.Helper()
	body := testfixture.DEXWithInstructions(units, regs, outs)
	copy(body[4:7], "039")
	testfixture.RepairDEXHashes(body)
	d, err := parseDEX(body)
	if err != nil {
		t.Fatal(err)
	}
	offset := d.methods[2].code
	return d, offset, d.codes[offset]
}

func FuzzDEXInstructionsDoesNotPanic(f *testing.F) {
	f.Add([]byte{0x12, 0x70, 0x0f, 0})
	f.Add([]byte{0x18, 0, 0x23, 1, 0, 0, 0, 0, 0, 0x80, 0x12, 0x70, 0x0f, 0})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 8192 {
			return
		}
		units := make([]uint16, len(raw)/2)
		for i := range units {
			units[i] = binary.LittleEndian.Uint16(raw[2*i:])
		}
		body := testfixture.DEXWithInstructions(units, 32, 32)
		image, err := parseDEX(body)
		if err != nil {
			return
		}
		method := 2
		for _, view := range []string{"instructions", "cfg", "edges"} {
			_, _ = image.codeReport(DEXReport{}, DEXOptions{View: view, MethodIndex: &method})
		}
	})
}

func TestDEXAllStandardInstructionFormats(t *testing.T) {
	vectors := []struct {
		format     string
		units      []uint16
		regs, outs uint16
	}{
		{"10x", []uint16{0x000e}, 0, 0},
		{"12x", []uint16{0x1001, 0x000e}, 2, 0},
		{"22x", []uint16{0x0002, 1, 0x000e}, 2, 0},
		{"32x", []uint16{0x0003, 0, 1, 0x000e}, 2, 0},
		{"11x", []uint16{0x000f}, 1, 0},
		{"11n", []uint16{0xf012, 0x000f}, 1, 0},
		{"21s", []uint16{0x0013, 0xffff, 0x000f}, 1, 0},
		{"31i", []uint16{0x0014, 0xffff, 0x7fff, 0x000f}, 1, 0},
		{"21h", []uint16{0x0015, 0x8000, 0x000f}, 1, 0},
		{"51l", []uint16{0x0018, 0xffff, 0xffff, 0xffff, 0xffff, 0x0010}, 2, 0},
		{"21c", []uint16{0x001a, 0, 0x000f}, 1, 0},
		{"31c", []uint16{0x001b, 0, 0, 0x000f}, 1, 0},
		{"22c", []uint16{0x1020, 1, 0x000f}, 2, 0},
		{"35c", []uint16{0x106e, 3, 0, 0x000e}, 1, 1},
		{"3rc", []uint16{0x0174, 2, 0, 0x000e}, 1, 1},
		{"31t", []uint16{0x0026, 4, 0, 0x000e, 0x0300, 1, 2, 0, 0x0201}, 1, 0},
		{"10t", []uint16{0x0128, 0x000e}, 0, 0},
		{"20t", []uint16{0x0029, 2, 0x000e}, 0, 0},
		{"30t", []uint16{0x002a, 3, 0, 0x000e}, 0, 0},
		{"23x", []uint16{0x0090, 0x0100, 0x000f}, 2, 0},
		{"22t", []uint16{0x1032, 3, 0x000e, 0x000e}, 2, 0},
		{"21t", []uint16{0x0038, 3, 0x000e, 0x000e}, 1, 0},
		{"22s", []uint16{0x10d0, 0x8000, 0x000f}, 2, 0},
		{"22b", []uint16{0x00d8, 0x8001, 0x000f}, 2, 0},
		{"45cc", []uint16{0x10fa, 3, 0, 1, 0x000e}, 1, 1},
		{"4rcc", []uint16{0x01fb, 3, 0, 1, 0x000e}, 1, 1},
	}
	seen := map[string]bool{}
	for _, v := range vectors {
		t.Run(v.format, func(t *testing.T) {
			d, off, c := dexCodeVector(t, v.units, v.regs, v.outs)
			instructions, blocks, _, err := d.decodeCode(off, c)
			if err != nil {
				t.Fatal(err)
			}
			if len(instructions) == 0 || instructions[0].Format != v.format || instructions[0].ByteOffset != off+16 || len(blocks) == 0 || !blocks[0].Reachable {
				t.Fatalf("wrong projection: %+v %+v", instructions, blocks)
			}
			if instructions[0].RawSHA256 != digest(d.body[off+16:off+16+instructions[0].CodeUnits*2]) {
				t.Fatal("instruction source digest differs")
			}
			seen[v.format] = true
		})
	}
	for _, op := range dexOpcodes {
		if op.index != "Unknown" && !seen[op.format] {
			t.Fatalf("standard opcode format lacks independent vector: %s", op.format)
		}
	}
}

func TestDEXSwitchPayloadsAndConservativeExceptions(t *testing.T) {
	for _, units := range [][]uint16{
		{0x002b, 4, 0, 0x000e, 0x0100, 1, 0xffff, 0xffff, 3, 0},
		{0x002c, 4, 0, 0x000e, 0x0200, 1, 0xffff, 0xffff, 3, 0},
	} {
		d, off, c := dexCodeVector(t, units, 1, 0)
		decoded, blocks, edges, err := d.decodeCode(off, c)
		if err != nil {
			t.Fatal(err)
		}
		if len(decoded) != 3 || !decoded[2].Payload || len(blocks) != 2 {
			t.Fatalf("wrong switch split: %+v %+v", decoded, blocks)
		}
		found := false
		for _, edge := range edges {
			if edge.Kind == "switch" && edge.At == 0 && edge.Target == 3 && edge.CaseKey != nil && *edge.CaseKey == -1 {
				found = true
			}
		}
		if !found {
			t.Fatalf("switch relative base/key lost: %+v", edges)
		}
	}
	d, off, c := dexCodeVector(t, []uint16{0x002c, 4, 0, 0x000e, 0x0200, 0}, 1, 0)
	if _, _, _, err := d.decodeCode(off, c); err != nil {
		t.Fatalf("empty sparse switch: %v", err)
	}
	d, off, c = dexCodeVector(t, []uint16{0x001a, 0, 0x000f, 0x000d, 0x000f}, 1, 0)
	typ := uint32(2)
	c.tries = []dexTry{{0, 2, []dexCatch{{&typ, 3}}}}
	_, _, edges, err := d.decodeCode(off, c)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, edge := range edges {
		if edge.Kind == "exception_possible" && edge.Target == 3 && edge.CatchType != nil && *edge.CatchType == 2 {
			found = true
		}
	}
	if !found {
		t.Fatalf("possible catch edge lost: %+v", edges)
	}
}

func TestDEXInstructionBadBoundariesReferencesAndRegisters(t *testing.T) {
	vectors := [][]uint16{
		{0x0073},                        // unused opcode
		{0x010e},                        // reserved bits
		{0x0003, 0},                     // truncated 32x
		{0x1029, 2, 0x000e},             // reserved goto bits
		{0x0001, 0x000e},                // no register in header
		{0x0016, 0, 0x0010},             // wide register exceeds header
		{0x0029, 1, 0x000e},             // branch enters operand
		{0x0028},                        // illegal zero offset
		{0x002b, 3, 0, 0x0100, 0, 0, 0}, // unaligned payload
		{0x001a, 0xffff, 0x000e},        // invalid string
		{0x001c, 0xffff, 0x000e},        // invalid type
		{0x0052, 0xffff, 0x000e},        // invalid field
		{0x006e, 0xffff, 0, 0x000e},     // invalid method
		{0x0012},                        // reachable fall-off
		{0x0026, 4, 0, 0, 0x0300, 8, 0xffff, 0xffff}, // array work overflow
		{0x002b, 4, 0, 0x000e, 0x0200, 0},            // wrong payload type
	}
	for i, units := range vectors {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			regs := uint16(1)
			if i == 4 {
				regs = 0
			}
			d, off, c := dexCodeVector(t, units, regs, 1)
			if _, _, _, err := d.decodeCode(off, c); err == nil {
				t.Fatal("bad selected code accepted")
			}
		})
	}
	d, off, c := dexCodeVector(t, []uint16{0x001a, 0, 0x000f, 0x000d, 0x000f}, 1, 0)
	c.tries = []dexTry{{0, 1, []dexCatch{{nil, 3}}}}
	if _, _, _, err := d.decodeCode(off, c); err == nil {
		t.Fatal("try ends in operand")
	}
	c.tries = []dexTry{{0, 2, []dexCatch{{nil, 1}}}}
	if _, _, _, err := d.decodeCode(off, c); err == nil {
		t.Fatal("handler enters operand")
	}
}

func TestDEXInstructionViewsReuseSnapshotPagingAndMethodIdentity(t *testing.T) {
	body := testfixture.DEXWithInstructions([]uint16{0x0012, 0x0112, 0x1021, 0x000f}, 2, 0)
	p := writeDEXFixture(t, body)
	method := 2
	r, err := InspectDEX(p, DEXOptions{View: "instructions", MethodIndex: &method, PageOptions: PageOptions{Limit: 1}})
	if err != nil || !r.CodeAvailable || r.Method.Index != 2 || r.Method.Descriptor != "()I" || r.NextOffset == nil || *r.NextOffset != 1 {
		t.Fatalf("selected page: %+v %v", r, err)
	}
	next, err := InspectDEX(p, DEXOptions{View: "instructions", MethodIndex: &method, PageOptions: PageOptions{Offset: 1, Limit: 1, ExpectedSHA256: r.SHA256}})
	if err != nil || next.Instructions[0].Offset != 1 {
		t.Fatalf("fenced next page: %+v %v", next, err)
	}
	if _, err := InspectDEX(p, DEXOptions{View: "instructions", MethodIndex: &method, PageOptions: PageOptions{Offset: 1}}); err == nil {
		t.Fatal("unfenced code page")
	}
	for _, view := range []string{"cfg", "edges"} {
		if _, err := InspectDEX(p, DEXOptions{View: view, MethodIndex: &method}); err != nil {
			t.Fatal(err)
		}
	}
	native := 1
	r, err = InspectDEX(p, DEXOptions{View: "instructions", MethodIndex: &native})
	if err != nil || r.CodeAvailable || !r.Method.NativeDeclared {
		t.Fatalf("native no body: %+v %v", r, err)
	}
	referenced := 3
	if _, err := InspectDEX(p, DEXOptions{View: "instructions", MethodIndex: &referenced}); err == nil {
		t.Fatal("reference attributed a body")
	}
	if _, err := InspectDEX(p, DEXOptions{View: "methods", MethodIndex: &method}); err == nil {
		t.Fatal("selector ignored by wrong view")
	}
	bad := bytes.Clone(body)
	binary.LittleEndian.PutUint32(bad[8:], 0)
	if _, err := parseDEX(bad); err == nil {
		t.Fatal("raw identity checksum bypassed")
	}
}
