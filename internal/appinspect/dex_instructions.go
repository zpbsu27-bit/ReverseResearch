package appinspect

import (
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
)

const (
	dexSelectedCodeUnits    = 1 << 20
	dexSelectedInstructions = 65536
	dexSelectedEdges        = 262144
)

type DEXReference struct {
	Kind  string `json:"kind"`
	Index uint32 `json:"index"`
}

type DEXInstruction struct {
	Offset        uint32         `json:"code_unit_offset"`
	ByteOffset    uint32         `json:"dex_byte_offset"`
	CodeUnits     uint32         `json:"code_units"`
	Opcode        uint8          `json:"opcode"`
	Mnemonic      string         `json:"mnemonic"`
	Format        string         `json:"format"`
	RawPrefix     string         `json:"raw_prefix_hex"`
	RawSHA256     string         `json:"raw_sha256"`
	Registers     []uint16       `json:"registers,omitempty"`
	RangeStart    *uint16        `json:"register_range_start,omitempty"`
	RangeCount    uint16         `json:"register_range_count,omitempty"`
	Literal       *int64         `json:"literal,string,omitempty"`
	References    []DEXReference `json:"references,omitempty"`
	Target        *uint32        `json:"branch_target_code_unit,omitempty"`
	PayloadOffset *uint32        `json:"payload_code_unit_offset,omitempty"`
	Payload       bool           `json:"is_payload"`
	PayloadCount  uint32         `json:"payload_count,omitempty"`
	ElementWidth  uint16         `json:"element_width,omitempty"`
}

type DEXBlock struct {
	Index            int    `json:"block_index"`
	Start            uint32 `json:"start_code_unit"`
	End              uint32 `json:"end_code_unit_exclusive"`
	InstructionCount int    `json:"instruction_count"`
	Reachable        bool   `json:"reachable_from_entry"`
	EdgeOffset       int    `json:"edge_offset"`
	EdgeCount        int    `json:"edge_count"`
}

type DEXEdge struct {
	FromBlock int     `json:"from_block"`
	ToBlock   int     `json:"to_block"`
	At        uint32  `json:"instruction_code_unit"`
	Target    uint32  `json:"target_code_unit"`
	Kind      string  `json:"kind"`
	CaseKey   *int32  `json:"case_key,omitempty"`
	CatchType *uint32 `json:"catch_type_index,omitempty"`
}

type dexCatch struct {
	typ     *uint32
	address uint32
}
type dexTry struct {
	start, end uint32
	catches    []dexCatch
}
type dexPayload struct {
	keys, targets []int32
	kind          uint16
}
type dexFlow struct {
	from, target uint32
	kind         string
	key          *int32
	typ          *uint32
}

func (d *dexImage) methodReport(index int) (DEXMethod, error) {
	m := d.methods[index]
	proto := d.protos[m.proto]
	var descriptor strings.Builder
	descriptor.WriteByte('(')
	for _, t := range proto.parameters {
		descriptor.WriteString(d.types[t])
		if descriptor.Len() > 32768 {
			return DEXMethod{}, errors.New("DEX selected method descriptor exceeds 32 KiB")
		}
	}
	descriptor.WriteByte(')')
	descriptor.WriteString(d.types[proto.result])
	c := d.codes[m.code]
	return DEXMethod{Index: index, Class: d.types[m.class], Name: d.strings[m.name].text, Descriptor: descriptor.String(), Defined: m.defined, AccessFlags: m.flags, NativeDeclared: m.defined && m.flags&0x100 != 0, MethodKind: m.kind, CodeOffset: m.code, CodeUnits: c.units, InstructionsSHA256: c.hash}, nil
}

func (d *dexImage) codeReport(r DEXReport, o DEXOptions) (DEXReport, error) {
	i := *o.MethodIndex
	if i < 0 || i >= len(d.methods) {
		return r, errors.New("DEX method_index outside inventory")
	}
	m, err := d.methodReport(i)
	if err != nil {
		return r, err
	}
	r.Method = &m
	if !m.Defined {
		return r, errors.New("DEX method is a reference, not a definition")
	}
	if m.CodeOffset == 0 {
		if _, _, err := page(o.PageOptions, 0); err != nil {
			return r, err
		}
		r.CoverageComplete = true
		r.Limitations = append(r.Limitations, "selected native/abstract declaration has no DEX code body")
		return r, projectionLimit(r)
	}
	c := d.codes[m.CodeOffset]
	instructions, blocks, edges, err := d.decodeCode(m.CodeOffset, c)
	if err != nil {
		return r, err
	}
	r.CodeAvailable = true
	r.Registers, r.IncomingRegisters, r.OutgoingRegisters = c.registers, c.incoming, c.outgoing
	r.TotalInstructions, r.TotalBlocks, r.TotalEdges = len(instructions), len(blocks), len(edges)
	total := len(instructions)
	if o.View == "cfg" {
		total = len(blocks)
	}
	if o.View == "edges" {
		total = len(edges)
	}
	start, end, err := page(o.PageOptions, total)
	if err != nil {
		return r, err
	}
	r.Offset, r.CoverageComplete = start, start == 0 && end == total
	if end < total {
		r.NextOffset = &end
	}
	switch o.View {
	case "instructions":
		r.Instructions = instructions[start:end]
	case "cfg":
		r.Blocks = blocks[start:end]
	case "edges":
		r.Edges = edges[start:end]
	}
	r.EvidenceAuthority = "build-local selected method instruction bytes and structural control-flow; conservative possible exception edges"
	r.Limitations = append(r.Limitations, "instruction rows include explicit data payload rows; branch targets use code units, byte offsets use DEX-member bytes", "CFG is structural; unreachable code remains visible, exceptions are possible edges and do not prove exception types or runtime reachability", "ART typed verification, register value/alias analysis and full application semantics are not performed")
	return r, projectionLimit(r)
}

func (d *dexImage) instructionReference(kind string, index uint32) (DEXReference, error) {
	var count int
	switch kind {
	case "StringRef":
		count = len(d.strings)
	case "TypeRef":
		count = len(d.types)
	case "FieldRef":
		count = len(d.fields)
	case "MethodRef":
		count = len(d.methods)
	case "ProtoRef":
		count = len(d.protos)
	case "CallSiteRef":
		count = int(d.optionalIDs[7])
	case "MethodHandleRef":
		count = int(d.optionalIDs[8])
	default:
		return DEXReference{}, errors.New("DEX instruction reference kind unsupported")
	}
	if uint64(index) >= uint64(count) {
		return DEXReference{}, fmt.Errorf("DEX %s index outside table: %d", kind, index)
	}
	return DEXReference{kind, index}, nil
}

func (d *dexImage) decodeCode(codeOffset uint32, c dexCode) ([]DEXInstruction, []DEXBlock, []DEXEdge, error) {
	if c.units == 0 || c.units > dexSelectedCodeUnits {
		return nil, nil, nil, errors.New("DEX selected code size outside 1..1M code units")
	}
	raw, err := d.take(codeOffset+16, uint64(c.units), 2, 0, true)
	if err != nil {
		return nil, nil, nil, err
	}
	word := func(pc uint32) uint16 { return u16(raw[uint64(pc)*2:]) }
	read32 := func(pc uint32) uint32 { return uint32(word(pc)) | uint32(word(pc+1))<<16 }
	var instructions []DEXInstruction
	boundaries := map[uint32]int{}
	payloads := map[uint32]dexPayload{}
	for pc := uint32(0); pc < c.units; {
		if len(instructions) >= dexSelectedInstructions {
			return nil, nil, nil, errors.New("DEX selected method exceeds 65536 decoded instruction/payload rows")
		}
		first := word(pc)
		op := uint8(first)
		info := dexOpcodes[op]
		v := DEXInstruction{Offset: pc, ByteOffset: codeOffset + 16 + pc*2, Opcode: op, Mnemonic: info.name, Format: info.format, CodeUnits: uint32(info.width)}
		if op == 0 && first != 0 {
			if pc%2 != 0 || first < 0x100 || first > 0x300 || first%0x100 != 0 {
				return nil, nil, nil, fmt.Errorf("DEX payload header/alignment invalid at %d", pc)
			}
			if pc+2 > c.units || first != 0x200 && pc+4 > c.units {
				return nil, nil, nil, errors.New("DEX payload header truncated")
			}
			v.Payload, v.Format = true, "payload"
			p := dexPayload{kind: first}
			size := uint32(word(pc + 1))
			switch first {
			case 0x100:
				v.Mnemonic, v.PayloadCount, v.CodeUnits = "packed-switch-payload", size, 4+size*2
				if uint64(pc)+uint64(v.CodeUnits) > uint64(c.units) {
					return nil, nil, nil, errors.New("DEX packed-switch payload truncated")
				}
				key := int64(int32(read32(pc + 2)))
				if size > 0 && key+int64(size)-1 > 1<<31-1 {
					return nil, nil, nil, errors.New("DEX packed-switch key overflow")
				}
				for j := uint32(0); j < size; j++ {
					p.keys = append(p.keys, int32(key+int64(j)))
					p.targets = append(p.targets, int32(read32(pc+4+j*2)))
				}
			case 0x200:
				v.Mnemonic, v.PayloadCount, v.CodeUnits = "sparse-switch-payload", size, 2+size*4
				if uint64(pc)+uint64(v.CodeUnits) > uint64(c.units) {
					return nil, nil, nil, errors.New("DEX sparse-switch payload truncated")
				}
				for j := uint32(0); j < size; j++ {
					key := int32(read32(pc + 2 + j*2))
					if j > 0 && key <= p.keys[j-1] {
						return nil, nil, nil, errors.New("DEX sparse-switch keys not strictly ordered")
					}
					p.keys = append(p.keys, key)
					p.targets = append(p.targets, int32(read32(pc+2+size*2+j*2)))
				}
			case 0x300:
				v.Mnemonic, v.ElementWidth, v.PayloadCount = "fill-array-data-payload", word(pc+1), read32(pc+2)
				if v.ElementWidth != 1 && v.ElementWidth != 2 && v.ElementWidth != 4 && v.ElementWidth != 8 {
					return nil, nil, nil, errors.New("DEX array payload element width invalid")
				}
				width := uint64(4) + (uint64(v.PayloadCount)*uint64(v.ElementWidth)+1)/2
				if width > uint64(c.units-pc) {
					return nil, nil, nil, errors.New("DEX array payload size exceeds code")
				}
				v.CodeUnits = uint32(width)
			}
			payloads[pc] = p
		} else {
			if info.width == 0 || info.index == "Unknown" || strings.HasPrefix(info.name, "unused") {
				return nil, nil, nil, fmt.Errorf("DEX reserved/quickened opcode 0x%02x at %d", op, pc)
			}
			if uint64(pc)+uint64(v.CodeUnits) > uint64(c.units) {
				return nil, nil, nil, fmt.Errorf("DEX instruction truncated at %d", pc)
			}
			if op >= 0xfa && (d.version < "038" || op >= 0xfe && d.version < "039") {
				return nil, nil, nil, errors.New("DEX instruction requires a newer DEX version")
			}
			a8, a4, b4 := uint16(first>>8), uint16(first>>8&15), uint16(first>>12)
			var delta *int64
			var reference *uint32
			literal := func(n int64) { v.Literal = &n }
			branch := func(n int64) { delta = &n }
			ref := func(n uint32) { reference = &n }
			switch info.format {
			case "10x":
				if a8 != 0 {
					return nil, nil, nil, errors.New("DEX reserved instruction bits nonzero")
				}
			case "12x":
				v.Registers = []uint16{a4, b4}
			case "11x":
				v.Registers = []uint16{a8}
			case "11n":
				v.Registers = []uint16{a4}
				n := int64(b4)
				if n >= 8 {
					n -= 16
				}
				literal(n)
			case "10t":
				branch(int64(int8(a8)))
			case "20t":
				if a8 != 0 {
					return nil, nil, nil, errors.New("DEX goto reserved bits nonzero")
				}
				branch(int64(int16(word(pc + 1))))
			case "30t":
				if a8 != 0 {
					return nil, nil, nil, errors.New("DEX goto/32 reserved bits nonzero")
				}
				branch(int64(int32(read32(pc + 1))))
			case "22x":
				v.Registers = []uint16{a8, word(pc + 1)}
			case "32x":
				if a8 != 0 {
					return nil, nil, nil, errors.New("DEX move/16 reserved bits nonzero")
				}
				v.Registers = []uint16{word(pc + 1), word(pc + 2)}
			case "21t":
				v.Registers = []uint16{a8}
				branch(int64(int16(word(pc + 1))))
			case "21s":
				v.Registers = []uint16{a8}
				literal(int64(int16(word(pc + 1))))
			case "21h":
				v.Registers = []uint16{a8}
				n := int64(int16(word(pc + 1)))
				if op == 0x19 {
					n <<= 48
				} else {
					n <<= 16
				}
				literal(n)
			case "21c":
				v.Registers = []uint16{a8}
				ref(uint32(word(pc + 1)))
			case "31c":
				v.Registers = []uint16{a8}
				ref(read32(pc + 1))
			case "31i":
				v.Registers = []uint16{a8}
				literal(int64(int32(read32(pc + 1))))
			case "51l":
				v.Registers = []uint16{a8}
				literal(int64(uint64(read32(pc+1)) | uint64(read32(pc+3))<<32))
			case "23x":
				v.Registers = []uint16{a8, word(pc+1) & 255, word(pc+1) >> 8}
			case "22b":
				v.Registers = []uint16{a8, word(pc+1) & 255}
				literal(int64(int8(word(pc+1) >> 8)))
			case "22t":
				v.Registers = []uint16{a4, b4}
				branch(int64(int16(word(pc + 1))))
			case "22s":
				v.Registers = []uint16{a4, b4}
				literal(int64(int16(word(pc + 1))))
			case "22c":
				v.Registers = []uint16{a4, b4}
				ref(uint32(word(pc + 1)))
			case "31t":
				v.Registers = []uint16{a8}
				branch(int64(int32(read32(pc + 1))))
			case "35c", "45cc":
				count := b4
				if count > 5 {
					return nil, nil, nil, errors.New("DEX invoke register count exceeds format")
				}
				packed := word(pc + 2)
				regs := []uint16{packed & 15, packed >> 4 & 15, packed >> 8 & 15, packed >> 12, a4}
				v.Registers = regs[:count]
				ref(uint32(word(pc + 1)))
				if info.format == "45cc" {
					extra, err := d.instructionReference("ProtoRef", uint32(word(pc+3)))
					if err != nil {
						return nil, nil, nil, err
					}
					v.References = append(v.References, extra)
				}
			case "3rc", "4rcc":
				start := word(pc + 2)
				v.RangeStart = &start
				v.RangeCount = a8
				ref(uint32(word(pc + 1)))
				if uint32(start)+uint32(a8) > uint32(c.registers) {
					return nil, nil, nil, errors.New("DEX register range exceeds method registers")
				}
				if info.format == "4rcc" {
					extra, err := d.instructionReference("ProtoRef", uint32(word(pc+3)))
					if err != nil {
						return nil, nil, nil, err
					}
					v.References = append(v.References, extra)
				}
			default:
				return nil, nil, nil, errors.New("DEX instruction format unsupported")
			}
			for i, reg := range v.Registers {
				wide := uint32(1)
				if i < 3 && info.wide&(1<<i) != 0 {
					wide = 2
				}
				if uint32(reg)+wide > uint32(c.registers) {
					return nil, nil, nil, fmt.Errorf("DEX register operand outside code header at %d", pc)
				}
			}
			if (op >= 0x6e && op <= 0x78 || op >= 0xfa && op <= 0xfd) && uint32(len(v.Registers))+uint32(v.RangeCount) > uint32(c.outgoing) {
				return nil, nil, nil, errors.New("DEX invocation words exceed outs_size")
			}
			if reference != nil {
				kind := info.index
				if kind == "MethodAndProtoRef" {
					kind = "MethodRef"
				}
				value, err := d.instructionReference(kind, *reference)
				if err != nil {
					return nil, nil, nil, err
				}
				v.References = append([]DEXReference{value}, v.References...)
			}
			if delta != nil {
				target := int64(pc) + *delta
				if target < 0 || target >= int64(c.units) {
					return nil, nil, nil, errors.New("DEX branch/payload target outside code")
				}
				if *delta == 0 && op != 0x2a && info.format != "31t" {
					return nil, nil, nil, errors.New("DEX zero branch offset forbidden by format")
				}
				t := uint32(target)
				if info.format == "31t" {
					v.PayloadOffset = &t
				} else {
					v.Target = &t
				}
			}
		}
		chunk := raw[uint64(pc)*2 : uint64(pc+v.CodeUnits)*2]
		v.RawSHA256 = digest(chunk)
		v.RawPrefix = hex.EncodeToString(chunk[:min(len(chunk), 10)])
		boundaries[pc] = len(instructions)
		instructions = append(instructions, v)
		pc += v.CodeUnits
	}
	if instructions[0].Payload {
		return nil, nil, nil, errors.New("DEX entry starts in a data payload")
	}
	validTarget := func(pc uint32) bool { i, ok := boundaries[pc]; return ok && !instructions[i].Payload }
	var flows []dexFlow
	leaders := map[uint32]bool{0: true}
	add := func(from, target uint32, kind string, key *int32, typ *uint32) error {
		if !validTarget(target) {
			return errors.New("DEX control-flow target is not an instruction boundary")
		}
		if len(flows) >= dexSelectedEdges {
			return errors.New("DEX CFG edge work exceeds 262144")
		}
		flows = append(flows, dexFlow{from, target, kind, key, typ})
		leaders[target] = true
		return nil
	}
	for _, tr := range c.tries {
		if !validTarget(tr.start) || tr.end != c.units && !validTarget(tr.end) {
			return nil, nil, nil, errors.New("DEX try range does not use instruction boundaries")
		}
		leaders[tr.start] = true
		if tr.end < c.units {
			leaders[tr.end] = true
		}
		for _, catch := range tr.catches {
			if !validTarget(catch.address) {
				return nil, nil, nil, errors.New("DEX handler enters operand or payload")
			}
			leaders[catch.address] = true
		}
	}
	tryPosition := 0
	for _, v := range instructions {
		if v.Payload {
			if validTarget(v.Offset + v.CodeUnits) {
				leaders[v.Offset+v.CodeUnits] = true
			}
			continue
		}
		info := dexOpcodes[v.Opcode]
		if v.Target != nil {
			if err := add(v.Offset, *v.Target, "branch", nil, nil); err != nil {
				return nil, nil, nil, err
			}
		}
		if v.PayloadOffset != nil {
			p, ok := payloads[*v.PayloadOffset]
			wanted := uint16(0x300)
			if v.Opcode == 0x2b {
				wanted = 0x100
			}
			if v.Opcode == 0x2c {
				wanted = 0x200
			}
			if !ok || p.kind != wanted {
				return nil, nil, nil, errors.New("DEX payload kind/target boundary mismatch")
			}
			for i, delta := range p.targets {
				target := int64(v.Offset) + int64(delta)
				if target < 0 || target >= int64(c.units) {
					return nil, nil, nil, errors.New("DEX switch case target outside code")
				}
				key := p.keys[i]
				if err := add(v.Offset, uint32(target), "switch", &key, nil); err != nil {
					return nil, nil, nil, err
				}
			}
		}
		next := v.Offset + v.CodeUnits
		if info.flags&dexContinues != 0 && validTarget(next) {
			if len(flows) >= dexSelectedEdges {
				return nil, nil, nil, errors.New("DEX CFG edge work exceeds 262144")
			}
			flows = append(flows, dexFlow{v.Offset, next, "fallthrough", nil, nil})
		}
		if v.Target != nil || v.PayloadOffset != nil && v.Opcode != 0x26 || info.flags&dexContinues == 0 {
			if validTarget(next) {
				leaders[next] = true
			}
		}
		if info.flags&dexMayThrow != 0 {
			for tryPosition < len(c.tries) && c.tries[tryPosition].end <= v.Offset {
				tryPosition++
			}
			if tryPosition < len(c.tries) {
				tr := c.tries[tryPosition]
				if v.Offset >= tr.start && v.Offset < tr.end {
					for _, catch := range tr.catches {
						if err := add(v.Offset, catch.address, "exception_possible", nil, catch.typ); err != nil {
							return nil, nil, nil, err
						}
					}
				}
			}
		}
	}
	// Only reachable fallthrough into a payload/end is rejected; alignment nops
	// after an unconditional return remain visible as unreachable decoded bytes.
	adj := map[uint32][]uint32{}
	for _, edge := range flows {
		adj[edge.from] = append(adj[edge.from], edge.target)
	}
	reachable := map[uint32]bool{0: true}
	queue := []uint32{0}
	for len(queue) > 0 {
		pc := queue[0]
		queue = queue[1:]
		v := instructions[boundaries[pc]]
		if dexOpcodes[v.Opcode].flags&dexContinues != 0 && !validTarget(pc+v.CodeUnits) {
			return nil, nil, nil, errors.New("DEX reachable instruction falls off code or into payload")
		}
		for _, target := range adj[pc] {
			if !reachable[target] {
				reachable[target] = true
				queue = append(queue, target)
			}
		}
	}
	var blocks []DEXBlock
	blockAt := map[uint32]int{}
	for _, v := range instructions {
		if v.Payload {
			continue
		}
		if len(blocks) == 0 || leaders[v.Offset] || blocks[len(blocks)-1].End != v.Offset {
			blocks = append(blocks, DEXBlock{Index: len(blocks), Start: v.Offset, Reachable: reachable[v.Offset]})
		}
		b := &blocks[len(blocks)-1]
		b.End = v.Offset + v.CodeUnits
		b.InstructionCount++
		blockAt[v.Offset] = b.Index
	}
	var edges []DEXEdge
	for _, flow := range flows {
		from, to := blockAt[flow.from], blockAt[flow.target]
		if flow.kind == "fallthrough" && from == to {
			continue
		}
		edges = append(edges, DEXEdge{from, to, flow.from, flow.target, flow.kind, flow.key, flow.typ})
	}
	slices.SortFunc(edges, func(a, b DEXEdge) int {
		if a.FromBlock != b.FromBlock {
			return a.FromBlock - b.FromBlock
		}
		if a.At < b.At {
			return -1
		}
		if a.At > b.At {
			return 1
		}
		if a.Target < b.Target {
			return -1
		}
		if a.Target > b.Target {
			return 1
		}
		return strings.Compare(a.Kind, b.Kind)
	})
	position := 0
	for i := range blocks {
		blocks[i].EdgeOffset = position
		for position < len(edges) && edges[position].FromBlock == i {
			blocks[i].EdgeCount++
			position++
		}
	}
	return instructions, blocks, edges, nil
}
