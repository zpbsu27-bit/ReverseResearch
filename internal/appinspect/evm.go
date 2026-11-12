package appinspect

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"unicode/utf8"

	"reverseresearch/internal/evmengine"
)

type EVMOptions struct {
	PageOptions
	Encoding             string `json:"encoding"`
	View                 string `json:"view"`
	ExpectedResultSHA256 string `json:"expected_result_sha256,omitempty"`
}
type EVMInstruction struct {
	Offset     int    `json:"offset"`
	Opcode     string `json:"opcode"`
	OperandHex string `json:"operand_hex,omitempty"`
}
type EVMSelector struct {
	Offset   int    `json:"offset"`
	Value    string `json:"value"`
	Strength string `json:"strength"`
}
type EVMReport struct {
	Path           string `json:"path"`
	SHA256         string `json:"sha256"`
	BytecodeSHA256 string `json:"bytecode_sha256"`
	BytecodeBytes  int    `json:"bytecode_bytes"`
	Encoding       string `json:"encoding"`
	View           string `json:"view"`
	*EVMInstructionReport
	Interface          *EVMInterfaceReport `json:"interface,omitempty"`
	Result             *EVMResultPage      `json:"result,omitempty"`
	CoverageComplete   bool                `json:"coverage_complete"`
	ExecutionPerformed bool                `json:"execution_performed"`
	EvidenceAuthority  string              `json:"evidence_authority"`
	Limitations        []string            `json:"limitations"`
}
type EVMInstructionReport struct {
	TotalInstructions       int              `json:"total_instructions"`
	Offset                  int              `json:"offset"`
	Instructions            []EVMInstruction `json:"instructions"`
	NextOffset              *int             `json:"next_offset,omitempty"`
	Selectors               []EVMSelector    `json:"selector_candidates"`
	TotalSelectorCandidates int              `json:"total_selector_candidates"`
	SelectorsTruncated      bool             `json:"selectors_truncated"`
}

var evmNames = map[byte]string{
	0x00: "STOP", 0x01: "ADD", 0x02: "MUL", 0x03: "SUB", 0x04: "DIV", 0x05: "SDIV", 0x06: "MOD", 0x07: "SMOD", 0x08: "ADDMOD", 0x09: "MULMOD", 0x0a: "EXP", 0x0b: "SIGNEXTEND",
	0x10: "LT", 0x11: "GT", 0x12: "SLT", 0x13: "SGT", 0x14: "EQ", 0x15: "ISZERO", 0x16: "AND", 0x17: "OR", 0x18: "XOR", 0x19: "NOT", 0x1a: "BYTE", 0x1b: "SHL", 0x1c: "SHR", 0x1d: "SAR", 0x20: "KECCAK256",
	0x30: "ADDRESS", 0x31: "BALANCE", 0x32: "ORIGIN", 0x33: "CALLER", 0x34: "CALLVALUE", 0x35: "CALLDATALOAD", 0x36: "CALLDATASIZE", 0x37: "CALLDATACOPY", 0x38: "CODESIZE", 0x39: "CODECOPY", 0x3a: "GASPRICE", 0x3b: "EXTCODESIZE", 0x3c: "EXTCODECOPY", 0x3d: "RETURNDATASIZE", 0x3e: "RETURNDATACOPY", 0x3f: "EXTCODEHASH",
	0x40: "BLOCKHASH", 0x41: "COINBASE", 0x42: "TIMESTAMP", 0x43: "NUMBER", 0x44: "PREVRANDAO", 0x45: "GASLIMIT", 0x46: "CHAINID", 0x47: "SELFBALANCE", 0x48: "BASEFEE", 0x49: "BLOBHASH", 0x4a: "BLOBBASEFEE",
	0x50: "POP", 0x51: "MLOAD", 0x52: "MSTORE", 0x53: "MSTORE8", 0x54: "SLOAD", 0x55: "SSTORE", 0x56: "JUMP", 0x57: "JUMPI", 0x58: "PC", 0x59: "MSIZE", 0x5a: "GAS", 0x5b: "JUMPDEST", 0x5c: "TLOAD", 0x5d: "TSTORE", 0x5e: "MCOPY", 0x5f: "PUSH0",
	0xf0: "CREATE", 0xf1: "CALL", 0xf2: "CALLCODE", 0xf3: "RETURN", 0xf4: "DELEGATECALL", 0xf5: "CREATE2", 0xfa: "STATICCALL", 0xfd: "REVERT", 0xfe: "INVALID", 0xff: "SELFDESTRUCT",
}

func InspectEVM(ctx context.Context, path string, o EVMOptions) (EVMReport, error) {
	if err := ctx.Err(); err != nil {
		return EVMReport{}, err
	}
	if o.View == "" {
		o.View = "instructions"
	}
	if o.View != "instructions" && o.View != "interface" && o.View != "interface-bytes" {
		return EVMReport{}, errors.New("EVM view must be instructions, interface or interface-bytes")
	}
	if o.View == "instructions" && o.ExpectedResultSHA256 != "" {
		return EVMReport{}, errors.New("expected_result_sha256 applies only to interface views")
	}
	if o.View != "instructions" && o.Offset > 0 && (o.ExpectedSHA256 == "" || o.ExpectedResultSHA256 == "") {
		return EVMReport{}, errors.New("subsequent EVM interface pages require expected_sha256 and expected_result_sha256")
	}
	if o.Encoding == "" {
		o.Encoding = "hex"
	}
	if o.Encoding != "raw" && o.Encoding != "hex" {
		return EVMReport{}, errors.New("encoding must be explicit raw or hex")
	}
	maxCarrier := int64(2 << 20)
	maxCode := 1 << 20
	if o.View != "instructions" {
		maxCarrier = 4 << 20
		maxCode = evmengine.MaxInputBytes
	}
	body, abs, hash, err := readArtifact(path, maxCarrier, o.ExpectedSHA256)
	if err != nil {
		return EVMReport{}, err
	}
	code, err := decodeEVMCarrier(body, o.Encoding, maxCode)
	if err != nil {
		return EVMReport{}, err
	}
	if o.View != "instructions" {
		return inspectEVMInterface(ctx, abs, hash, code, o)
	}
	instructions := []EVMInstruction{}
	selectors := []EVMSelector{}
	totalSelectors := 0
	for pos := 0; pos < len(code); {
		start := pos
		op := code[pos]
		pos++
		name := evmNames[op]
		n := 0
		switch {
		case op >= 0x60 && op <= 0x7f:
			n = int(op - 0x5f)
			name = fmt.Sprintf("PUSH%d", n)
		case op >= 0x80 && op <= 0x8f:
			name = fmt.Sprintf("DUP%d", op-0x7f)
		case op >= 0x90 && op <= 0x9f:
			name = fmt.Sprintf("SWAP%d", op-0x8f)
		case op >= 0xa0 && op <= 0xa4:
			name = fmt.Sprintf("LOG%d", op-0xa0)
		}
		if name == "" {
			name = fmt.Sprintf("UNASSIGNED_0x%02x", op)
		}
		if n > len(code)-pos {
			return EVMReport{}, errors.New("truncated EVM PUSH immediate")
		}
		operand := hex.EncodeToString(code[pos : pos+n])
		pos += n
		instructions = append(instructions, EVMInstruction{Offset: start, Opcode: name, OperandHex: operand})
		if op == 0x63 && pos < len(code) && code[pos] == 0x14 {
			totalSelectors++
			if len(selectors) < 50 {
				selectors = append(selectors, EVMSelector{Offset: start, Value: "0x" + operand, Strength: "inferred"})
			}
		}
		if len(instructions) > 250000 {
			return EVMReport{}, errors.New("EVM instruction count exceeds limit")
		}
	}
	start, end, err := page(o.PageOptions, len(instructions))
	if err != nil {
		return EVMReport{}, err
	}
	r := EVMReport{Path: abs, SHA256: hash, BytecodeSHA256: digest(code), BytecodeBytes: len(code), Encoding: o.Encoding, View: o.View, EVMInstructionReport: &EVMInstructionReport{TotalInstructions: len(instructions), Offset: start, Instructions: instructions[start:end], Selectors: selectors, TotalSelectorCandidates: totalSelectors, SelectorsTruncated: totalSelectors > len(selectors)}, CoverageComplete: start == 0 && end == len(instructions), EvidenceAuthority: "artifact-bytes", Limitations: []string{"linear byte decoding includes unreachable code and metadata/data; not a control-flow or deployed-contract proof", "PUSH4 followed by EQ is a selector candidate only; ABI arguments/mutability, selector dispatch and branch reachability are not established", "opcode names cover the declared modern vocabulary; hardfork applicability and stack validity are not verified"}}
	if end < len(instructions) {
		r.NextOffset = &end
	}
	return r, projectionLimit(r)
}

func decodeEVMCarrier(body []byte, encoding string, maxCode int) ([]byte, error) {
	code := body
	if encoding == "hex" {
		if !utf8.Valid(body) {
			return nil, errors.New("hex carrier must be valid UTF-8")
		}
		clean := bytes.Trim(body, " \t\r\n\v\f")
		if bytes.HasPrefix(clean, []byte("0x")) || bytes.HasPrefix(clean, []byte("0X")) {
			clean = clean[2:]
		}
		if len(clean)%2 != 0 {
			return nil, errors.New("hex carrier must contain one contiguous even-length hex value")
		}
		if hex.DecodedLen(len(clean)) > maxCode {
			return nil, errors.New("EVM bytecode exceeds the selected view's byte budget")
		}
		code = make([]byte, hex.DecodedLen(len(clean)))
		if _, err := hex.Decode(code, clean); err != nil {
			return nil, errors.New("hex carrier must contain one contiguous even-length hex value")
		}
	}
	if len(code) > maxCode {
		return nil, errors.New("EVM bytecode exceeds the selected view's byte budget")
	}
	return code, nil
}
