package appinspect

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type CILInstruction struct {
	Offset        int    `json:"offset"`
	Opcode        string `json:"opcode"`
	OperandKind   string `json:"operand_kind"`
	OperandHex    string `json:"operand_hex,omitempty"`
	Token         string `json:"token,omitempty"`
	TargetName    string `json:"target_name,omitempty"`
	Relationship  string `json:"relationship,omitempty"`
	BranchTargets []int  `json:"branch_targets,omitempty"`
}

func (m *metadata) tokenName(token uint32, kind string) (string, error) {
	table, id := int(token>>24), int(token&0xffffff)
	allowed := map[string][]int{"InlineMethod": {6, 10, 43}, "InlineField": {4, 10}, "InlineType": {1, 2, 27}, "InlineTok": {1, 2, 4, 6, 10, 27, 43}, "InlineSig": {17}}
	if kind == "InlineString" {
		if table != 0x70 || id >= len(m.streams["#US"]) {
			return "", errors.New("CIL user-string token outside heap")
		}
		return "", nil
	}
	valid := false
	for _, t := range allowed[kind] {
		if table == t {
			valid = true
		}
	}
	if !valid || id < 1 || id > m.rows[table] {
		return "", errors.New("CIL token kind/row is invalid")
	}
	row, _ := m.row(table, id)
	switch table {
	case 6:
		return m.text(row[3])
	case 4, 10:
		return m.text(row[1])
	case 1, 2:
		name, err := m.text(row[1])
		if err != nil {
			return "", err
		}
		ns, err := m.text(row[2])
		if ns != "" {
			name = ns + "." + name
		}
		return name, err
	case 43:
		target := row[0] >> 1
		t := uint32(6)
		if row[0]&1 != 0 {
			t = 10
		}
		return m.tokenName(t<<24|target, "InlineMethod")
	}
	return "", nil
}
func (m *metadata) decodeCIL(il []byte) ([]CILInstruction, error) {
	var result []CILInstruction
	starts := map[int]bool{}
	for pos := 0; pos < len(il); {
		if len(result) >= 250000 {
			return nil, errors.New("CIL instruction count exceeds limit")
		}
		start := pos
		starts[start] = true
		code := uint16(il[pos])
		pos++
		if code == 0xfe {
			if pos == len(il) {
				return nil, errors.New("truncated CIL opcode prefix")
			}
			code = 0xfe00 | uint16(il[pos])
			pos++
		}
		op, ok := cilOpcodes[code]
		if !ok {
			return nil, errors.New("unknown/reserved CIL opcode")
		}
		n := 0
		switch op.operand {
		case "InlineNone":
		case "ShortInlineI", "ShortInlineVar", "ShortInlineBrTarget":
			n = 1
		case "InlineVar":
			n = 2
		case "InlineI", "ShortInlineR", "InlineBrTarget", "InlineString", "InlineSig", "InlineMethod", "InlineField", "InlineType", "InlineTok":
			n = 4
		case "InlineI8", "InlineR":
			n = 8
		case "InlineSwitch":
			if len(il)-pos < 4 {
				return nil, errors.New("truncated CIL switch")
			}
			count := int(u32(il[pos : pos+4]))
			if count > 2048 || count > (len(il)-pos-4)/4 {
				return nil, errors.New("CIL switch size is invalid or exceeds limit")
			}
			n = 4 + 4*count
		default:
			return nil, errors.New("unsupported CIL operand kind")
		}
		if n > len(il)-pos {
			return nil, errors.New("truncated CIL operand")
		}
		operand := il[pos : pos+n]
		pos += n
		inst := CILInstruction{Offset: start, Opcode: op.name, OperandKind: op.operand, OperandHex: hex.EncodeToString(operand)}
		if _, ok := map[string]bool{"InlineString": true, "InlineSig": true, "InlineMethod": true, "InlineField": true, "InlineType": true, "InlineTok": true}[op.operand]; ok {
			token := u32(operand)
			name, err := m.tokenName(token, op.operand)
			if err != nil {
				return nil, err
			}
			inst.Token = fmt.Sprintf("0x%08x", token)
			inst.TargetName = name
			if op.operand == "InlineMethod" {
				inst.Relationship = "method-reference"
				if op.name == "call" || op.name == "callvirt" || op.name == "newobj" || op.name == "jmp" {
					inst.Relationship = "declared-call"
				}
			}
			if op.operand == "InlineField" {
				inst.Relationship = "field-reference"
			}
		}
		switch op.operand {
		case "ShortInlineBrTarget":
			inst.BranchTargets = []int{pos + int(int8(operand[0]))}
		case "InlineBrTarget":
			inst.BranchTargets = []int{pos + int(int32(u32(operand)))}
		case "InlineSwitch":
			for i := 4; i < len(operand); i += 4 {
				inst.BranchTargets = append(inst.BranchTargets, pos+int(int32(u32(operand[i:i+4]))))
			}
		}
		result = append(result, inst)
	}
	for _, i := range result {
		for _, target := range i.BranchTargets {
			if !starts[target] {
				return nil, errors.New("CIL branch target is not an instruction boundary")
			}
		}
	}
	return result, nil
}

type ManagedMethodOptions struct {
	Token string `json:"token"`
	PageOptions
}
type ManagedMethodReport struct {
	Path               string           `json:"path"`
	SHA256             string           `json:"sha256"`
	MVID               string           `json:"mvid"`
	Method             ManagedMethod    `json:"method"`
	BodyAvailable      bool             `json:"body_available"`
	UnavailableReason  string           `json:"unavailable_reason,omitempty"`
	ILSHA256           string           `json:"il_sha256,omitempty"`
	ILBytes            int              `json:"il_bytes"`
	ExceptionClauses   int              `json:"exception_clauses"`
	TotalInstructions  int              `json:"total_instructions"`
	Offset             int              `json:"offset"`
	Instructions       []CILInstruction `json:"instructions"`
	NextOffset         *int             `json:"next_offset,omitempty"`
	CoverageComplete   bool             `json:"coverage_complete"`
	EvidenceAuthority  string           `json:"evidence_authority"`
	Limitations        []string         `json:"limitations"`
	ExecutionPerformed bool             `json:"execution_performed"`
	NetworkInteraction bool             `json:"network_interaction"`
}

func InspectManagedMethod(path string, o ManagedMethodOptions) (ManagedMethodReport, error) {
	token, err := strconv.ParseUint(strings.TrimPrefix(o.Token, "0x"), 16, 32)
	if err != nil || token>>24 != 6 || token&0xffffff == 0 {
		return ManagedMethodReport{}, errors.New("token must be a MethodDef hex token, for example 0x06000001")
	}
	body, abs, hash, err := readArtifact(path, MaxArtifactBytes, o.ExpectedSHA256)
	if err != nil {
		return ManagedMethodReport{}, err
	}
	m, err := parseMetadata(body)
	if err != nil {
		return ManagedMethodReport{}, err
	}
	if m.table == nil {
		return ManagedMethodReport{}, errors.New("PE has no admitted CLI metadata")
	}
	methods, err := m.methods()
	if err != nil {
		return ManagedMethodReport{}, err
	}
	id := int(token & 0xffffff)
	if id > len(methods) {
		return ManagedMethodReport{}, errors.New("method token outside admitted build")
	}
	module, _ := m.row(0, 1)
	mvid, err := m.guid(module[2])
	if err != nil {
		return ManagedMethodReport{}, err
	}
	r := ManagedMethodReport{Path: abs, SHA256: hash, MVID: mvid, Method: methods[id-1], Instructions: []CILInstruction{}, EvidenceAuthority: "artifact-bytes", Limitations: []string{"selected-method static decoding only; no execution, type/stack verification or C# reconstruction", "declared call/field references do not prove runtime calls or native-body identity", "exception section framing/count is inspected; exception semantics are not reconstructed", "IL digest covers raw instructions only, excluding method headers, locals and exception sections"}}
	il, clauses, err := m.methodBody(r.Method)
	if err != nil {
		return r, err
	}
	if il == nil {
		if _, _, err := page(o.PageOptions, 0); err != nil {
			return r, err
		}
		r.UnavailableReason = "method has no admitted IL body (RVA zero or non-IL implementation)"
		return r, nil
	}
	instructions, err := m.decodeCIL(il)
	if err != nil {
		return r, err
	}
	start, end, err := page(o.PageOptions, len(instructions))
	if err != nil {
		return r, err
	}
	r.BodyAvailable = true
	r.ILSHA256 = digest(il)
	r.ILBytes = len(il)
	r.ExceptionClauses = clauses
	r.TotalInstructions = len(instructions)
	r.Offset = start
	r.Instructions = instructions[start:end]
	r.CoverageComplete = start == 0 && end == len(instructions)
	if end < len(instructions) {
		r.NextOffset = &end
	}
	return r, projectionLimit(r)
}
