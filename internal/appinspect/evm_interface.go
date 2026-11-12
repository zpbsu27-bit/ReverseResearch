package appinspect

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"unicode/utf8"

	"reverseresearch/internal/evmengine"
	"reverseresearch/internal/recordio"
)

type EVMInferredFunction struct {
	Selector                string  `json:"selector"`
	BytecodeOffset          int     `json:"bytecode_offset"`
	Dispatch                string  `json:"dispatch"`
	InferredArguments       *string `json:"inferred_arguments"`
	InferredStateMutability *string `json:"inferred_state_mutability"`
}
type EVMFunctionPage struct {
	Offset     int                   `json:"offset"`
	Functions  []EVMInferredFunction `json:"functions"`
	NextOffset *int                  `json:"next_offset,omitempty"`
}
type EVMMetadataReport struct {
	BytecodeOffset   int             `json:"bytecode_offset"`
	CBORLength       int             `json:"cbor_length"`
	CBORSHA256       string          `json:"cbor_sha256"`
	TotalEntries     int             `json:"total_entries"`
	Entries          json.RawMessage `json:"entries,omitempty"`
	EntriesTruncated bool            `json:"entries_truncated"`
}
type EVMInterfaceReport struct {
	Engine                     string             `json:"engine"`
	EngineVersion              string             `json:"engine_version"`
	EngineWASMSHA256           string             `json:"engine_wasm_sha256"`
	WASMLinearMemoryLimitBytes int                `json:"wasm_linear_memory_limit_bytes"`
	AnalysisDeadlineMS         int64              `json:"analysis_deadline_ms"`
	ResultSHA256               string             `json:"result_sha256"`
	ResultBytes                int                `json:"result_bytes"`
	EvidenceKind               string             `json:"evidence_kind"`
	DigestAlgorithm            string             `json:"digest_algorithm"`
	BytecodeKind               string             `json:"bytecode_kind"`
	Hardfork                   string             `json:"hardfork"`
	DeploymentAuthenticity     string             `json:"deployment_authenticity"`
	DiscoveryCompleteness      string             `json:"discovery_completeness"`
	TotalFunctions             int                `json:"total_functions"`
	FunctionPage               *EVMFunctionPage   `json:"function_page,omitempty"`
	Metadata                   *EVMMetadataReport `json:"metadata,omitempty"`
}
type EVMResultPage struct {
	Offset     int    `json:"offset"`
	Bytes      int    `json:"bytes"`
	TotalBytes int    `json:"total_bytes"`
	SHA256     string `json:"sha256"`
	Base64     string `json:"base64"`
	NextOffset *int   `json:"next_offset,omitempty"`
}

type evmRawFunction struct {
	Selector        *string `json:"selector"`
	BytecodeOffset  *int    `json:"bytecode_offset"`
	Dispatch        *string `json:"dispatch"`
	Arguments       *string `json:"arguments"`
	StateMutability *string `json:"state_mutability"`
}
type evmRawCBORValue struct {
	Type  *string         `json:"type"`
	Value json.RawMessage `json:"value"`
}
type evmRawCBOREntry struct {
	Key   *string         `json:"key"`
	Value evmRawCBORValue `json:"value"`
}
type evmRawMetadata struct {
	BytecodeOffset *int              `json:"bytecodeOffset"`
	CBORLength     *int              `json:"cborLength"`
	Entries        []evmRawCBOREntry `json:"entries"`
}
type evmRawInterface struct {
	Functions []evmRawFunction `json:"functions"`
	Metadata  *evmRawMetadata  `json:"metadata"`
}

func inspectEVMInterface(ctx context.Context, path, artifactSHA string, code []byte, o EVMOptions) (EVMReport, error) {
	if len(code) >= 2 && code[0] == 0xef && code[1] == 0 {
		return EVMReport{}, errors.New("EF00 container is outside the supported flat-bytecode interface profile")
	}
	if o.Offset < 0 || o.Limit < 0 || (o.View == "interface" && o.Limit > 200) || (o.View == "interface-bytes" && o.Limit > 16384) {
		return EVMReport{}, errors.New("invalid interface page: item limit 1..200 or byte limit 1..16384")
	}
	result, err := evmengine.Analyze(ctx, code)
	if err != nil {
		return EVMReport{}, err
	}
	if err := ctx.Err(); err != nil {
		return EVMReport{}, err
	}
	resultSHA := digest(result)
	if err := recordio.CheckExpectedSHA256(resultSHA, o.ExpectedResultSHA256); err != nil {
		return EVMReport{}, fmt.Errorf("EVM interface result: %w", err)
	}
	functions, metadata, err := projectEVMInterface(result, code)
	if err != nil {
		return EVMReport{}, err
	}
	if err := ctx.Err(); err != nil {
		return EVMReport{}, err
	}
	info := &EVMInterfaceReport{
		Engine: "evmole", EngineVersion: evmengine.Version, EngineWASMSHA256: evmengine.WASMSHA256,
		WASMLinearMemoryLimitBytes: evmengine.MemoryLimitBytes, AnalysisDeadlineMS: evmengine.Deadline.Milliseconds(),
		ResultSHA256: resultSHA, ResultBytes: len(result), EvidenceKind: "inferred", DigestAlgorithm: "sha256",
		BytecodeKind: "unknown", Hardfork: "unknown", DeploymentAuthenticity: "unknown", DiscoveryCompleteness: "unknown",
		TotalFunctions: len(functions), Metadata: metadata,
	}
	r := EVMReport{Path: path, SHA256: artifactSHA, BytecodeSHA256: digest(code), BytecodeBytes: len(code), Encoding: o.Encoding, View: o.View, Interface: info,
		EvidenceAuthority: "artifact-bytes-and-engine-inference", Limitations: []string{
			"function selectors, offsets, arguments, mutability and dispatch are engine inferences; names, verified ABI and runtime reachability are not established",
			"bytecode kind, deployment authenticity, hardfork and discovery completeness are unknown; SHA-256 is a byte digest, not an Ethereum code hash",
			"only the bundled analyzer executes in an import-free WASM runtime; no EVM target execution, RPC, network or deployment occurs",
			"coverage_complete describes the returned page only; terminal CBOR entries expose the engine's text-keyed projection, not proof of complete metadata semantics",
			"the full engine JSON is available with interface-bytes; bytecode offsets address decoded bytes rather than positions in a hex carrier",
			"256 MiB caps WASM linear memory, not total Go process RSS; the original MCP admission gate remains the concurrent-call owner",
		}}
	if o.View == "interface-bytes" {
		limit := o.Limit
		if limit == 0 {
			limit = 8192
		}
		if o.Offset > len(result) {
			return EVMReport{}, errors.New("interface byte offset exceeds complete engine result")
		}
		end := min(len(result), o.Offset+limit)
		r.Result = &EVMResultPage{Offset: o.Offset, Bytes: end - o.Offset, TotalBytes: len(result), SHA256: resultSHA, Base64: base64.StdEncoding.EncodeToString(result[o.Offset:end])}
		if end < len(result) {
			r.Result.NextOffset = &end
		}
		r.CoverageComplete = o.Offset == 0 && end == len(result)
		return r, projectionLimit(r)
	}
	start, end, err := page(o.PageOptions, len(functions))
	if err != nil {
		return EVMReport{}, err
	}
	for {
		info.FunctionPage = &EVMFunctionPage{Offset: start, Functions: functions[start:end]}
		if end < len(functions) {
			next := end
			info.FunctionPage.NextOffset = &next
		}
		r.CoverageComplete = start == 0 && end == len(functions)
		if err = projectionLimit(r); err == nil {
			return r, nil
		}
		if end-start <= 1 {
			return EVMReport{}, errors.New("one interface projection exceeds 48 KiB; use interface-bytes to retrieve the full result")
		}
		end--
	}
}

func projectEVMInterface(result, code []byte) ([]EVMInferredFunction, *EVMMetadataReport, error) {
	if !utf8.Valid(result) || len(bytes.TrimSpace(result)) == 0 || bytes.TrimSpace(result)[0] != '{' {
		return nil, nil, errors.New("EVMole returned a non-object or invalid UTF-8 result")
	}
	var raw evmRawInterface
	decoder := json.NewDecoder(bytes.NewReader(result))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&raw); err != nil {
		return nil, nil, fmt.Errorf("EVMole interface schema: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, nil, errors.New("EVMole returned trailing JSON")
	}
	functions := make([]EVMInferredFunction, 0, len(raw.Functions))
	for _, f := range raw.Functions {
		if f.Selector == nil || len(*f.Selector) != 8 || f.BytecodeOffset == nil || *f.BytecodeOffset < 0 || *f.BytecodeOffset >= len(code) || f.Dispatch == nil || (*f.Dispatch != "abi" && *f.Dispatch != "fallback") {
			return nil, nil, errors.New("EVMole function identity/dispatch lies outside the supported profile")
		}
		for _, b := range []byte(*f.Selector) {
			if !((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f')) {
				return nil, nil, errors.New("EVMole selector must contain eight lowercase hex digits")
			}
		}
		functions = append(functions, EVMInferredFunction{Selector: "0x" + *f.Selector, BytecodeOffset: *f.BytecodeOffset, Dispatch: *f.Dispatch, InferredArguments: f.Arguments, InferredStateMutability: f.StateMutability})
	}
	if raw.Metadata == nil {
		return functions, nil, nil
	}
	m := raw.Metadata
	if m.BytecodeOffset == nil || m.CBORLength == nil || *m.BytecodeOffset < 0 || *m.CBORLength < 0 || *m.CBORLength > 65535 || len(code) < 2 || *m.BytecodeOffset > len(code)-2 || *m.CBORLength != len(code)-2-*m.BytecodeOffset || int(binary.BigEndian.Uint16(code[len(code)-2:])) != *m.CBORLength || m.Entries == nil {
		return nil, nil, errors.New("EVMole terminal metadata range does not match selected bytecode")
	}
	for _, entry := range m.Entries {
		if entry.Key == nil || !validEVMMetadataValue(entry.Value) {
			return nil, nil, errors.New("EVMole terminal metadata entry violates its tagged-value profile")
		}
	}
	entries, err := json.Marshal(m.Entries)
	if err != nil {
		return nil, nil, err
	}
	metadata := &EVMMetadataReport{BytecodeOffset: *m.BytecodeOffset, CBORLength: *m.CBORLength, CBORSHA256: digest(code[*m.BytecodeOffset : len(code)-2]), TotalEntries: len(m.Entries), EntriesTruncated: len(entries) > 8192}
	if !metadata.EntriesTruncated {
		metadata.Entries = entries
	}
	return functions, metadata, nil
}

func validEVMMetadataValue(v evmRawCBORValue) bool {
	if v.Type == nil || len(v.Value) == 0 || bytes.Equal(v.Value, []byte("null")) {
		return false
	}
	switch *v.Type {
	case "integer":
		_, ok := new(big.Int).SetString(string(v.Value), 10)
		return ok
	case "string":
		var x string
		return json.Unmarshal(v.Value, &x) == nil
	case "bool":
		return bytes.Equal(v.Value, []byte("true")) || bytes.Equal(v.Value, []byte("false"))
	case "bytes", "undecoded":
		var x []uint8
		return v.Value[0] == '[' && json.Unmarshal(v.Value, &x) == nil
	default:
		return false
	}
}
