package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"reverseresearch/internal/appinspect"
	"reverseresearch/internal/appinspect/testfixture"
	"reverseresearch/internal/evmengine"
	"reverseresearch/internal/targetidentity"
)

func (h *harness) evmInterfaceCase(target, receiptPath string) error {
	target, err := filepath.Abs(target)
	if err != nil {
		return err
	}
	receiptPath, err = filepath.Abs(receiptPath)
	if err != nil {
		return err
	}
	carrier, _, carrierSHA, err := targetidentity.CaptureFile(target, 4<<20)
	if err != nil {
		return err
	}
	code, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(string(carrier)), "0x"))
	if err != nil {
		return err
	}
	receiptBytes, _, _, err := targetidentity.CaptureFile(receiptPath, 1<<20)
	if err != nil {
		return err
	}
	var producer struct {
		CompilerSHA256    string            `json:"compiler_sha256"`
		SourceSHA256      string            `json:"source_sha256"`
		TargetSHA256      string            `json:"target_sha256"`
		BytecodeSHA256    string            `json:"bytecode_sha256"`
		MethodIdentifiers map[string]string `json:"method_identifiers"`
		ABI               []struct {
			Type, Name, StateMutability string
			Inputs                      []struct{ Type string }
		} `json:"abi"`
		TargetExecutionPerformed bool `json:"target_execution_performed"`
	}
	if err = json.Unmarshal(receiptBytes, &producer); err != nil {
		return err
	}
	if producer.CompilerSHA256 != "76a71001309810aafd0462d9b2f2612bf19b89550c866140edca26e533de06bc" || producer.SourceSHA256 != "75e8911611901feea55da3884ab2c8d221adbb6d1eeebb361fb2cf28ebb20f82" || producer.TargetSHA256 != carrierSHA || producer.BytecodeSHA256 != goBytesSHA(code) || producer.TargetExecutionPerformed || len(producer.MethodIdentifiers) != 5 {
		return errors.New("EVM target differs from owned pinned compiler producer")
	}
	var result appinspect.EVMReport
	p, err := h.call("app_evm_inspect", map[string]any{"path": target, "view": "interface", "encoding": "hex", "expected_sha256": carrierSHA, "limit": 2}, &result)
	if err != nil {
		return err
	}
	paths := []string{receiptPath, p}
	i := result.Interface
	if i == nil || i.EngineVersion != evmengine.Version || i.EngineWASMSHA256 != evmengine.WASMSHA256 || i.TotalFunctions != 6 || i.FunctionPage == nil || len(i.FunctionPage.Functions) != 2 || result.CoverageComplete || result.ExecutionPerformed || result.BytecodeSHA256 != producer.BytecodeSHA256 || i.DiscoveryCompleteness != "unknown" || i.DeploymentAuthenticity != "unknown" || i.Metadata == nil || i.Metadata.CBORLength != 10 {
		return errors.New("actual MCP EVM profile or inference boundary differs")
	}
	functions := append([]appinspect.EVMInferredFunction{}, i.FunctionPage.Functions...)
	for next := i.FunctionPage.NextOffset; next != nil; {
		var page appinspect.EVMReport
		p, err = h.call("app_evm_inspect", map[string]any{"path": target, "view": "interface", "encoding": "hex", "offset": *next, "limit": 2, "expected_sha256": carrierSHA, "expected_result_sha256": i.ResultSHA256}, &page)
		if err != nil {
			return err
		}
		paths = append(paths, p)
		if page.Interface == nil || page.Interface.FunctionPage == nil || page.Interface.ResultSHA256 != i.ResultSHA256 || page.Interface.FunctionPage.Offset != len(functions) || len(page.Interface.FunctionPage.Functions) == 0 {
			return errors.New("EVM function pages lost currentness/progress")
		}
		functions = append(functions, page.Interface.FunctionPage.Functions...)
		next = page.Interface.FunctionPage.NextOffset
	}
	if len(functions) != 6 {
		return errors.New("inferred function page total differs")
	}
	bySelector := map[string]appinspect.EVMInferredFunction{}
	for _, f := range functions {
		if _, exists := bySelector[f.Selector]; exists || f.BytecodeOffset < 0 || f.BytecodeOffset >= len(code) {
			return errors.New("owned EVM selector identity differs")
		}
		bySelector[f.Selector] = f
	}
	// Engine inference is compared to this exact source, without upgrading it to
	// ABI authority. This engine conservatively calls these two pure functions
	// view; that discrepancy is recorded rather than overwritten or hidden.
	engineMutability := map[string]string{"pureProbe": "view", "dynamicProbe": "view", "viewProbe": "view", "writeProbe": "nonpayable", "payableProbe": "payable"}
	comparisons := []map[string]any{}
	for _, abi := range producer.ABI {
		if abi.Type != "function" {
			continue
		}
		arguments := []string{}
		for _, arg := range abi.Inputs {
			arguments = append(arguments, arg.Type)
		}
		signature := abi.Name + "(" + strings.Join(arguments, ",") + ")"
		selector, ok := producer.MethodIdentifiers[signature]
		if !ok {
			return fmt.Errorf("compiler selector absent: %s", signature)
		}
		f, ok := bySelector["0x"+selector]
		if !ok || f.Dispatch != "abi" || f.InferredArguments == nil || *f.InferredArguments != strings.Join(arguments, ",") || f.InferredStateMutability == nil || *f.InferredStateMutability != engineMutability[abi.Name] {
			return fmt.Errorf("actual EVM inference differs for owned %s: %+v", signature, f)
		}
		comparisons = append(comparisons, map[string]any{"compiler_signature": signature, "selector": f.Selector, "compiler_mutability": abi.StateMutability, "inferred_mutability": *f.InferredStateMutability, "mutability_equal": abi.StateMutability == *f.InferredStateMutability, "arguments_equal": true})
	}
	if f, ok := bySelector["0x11223344"]; !ok || f.Dispatch != "fallback" || f.InferredArguments == nil || *f.InferredArguments != "uint256" || f.InferredStateMutability == nil || *f.InferredStateMutability != "payable" {
		return errors.New("actual fallback dispatch not inferred")
	}
	comparisonPath := filepath.Join(h.work, "calls", "evm-compiler-abi-comparison.json")
	if err = writeJSON(comparisonPath, map[string]any{"comparisons": comparisons, "complete_abi_verified": false, "target_execution_performed": false}); err != nil {
		return err
	}
	paths = append(paths, comparisonPath)
	var joined []byte
	for offset := 0; ; {
		var page appinspect.EVMReport
		p, err = h.call("app_evm_inspect", map[string]any{"path": target, "view": "interface-bytes", "encoding": "hex", "offset": offset, "limit": 128, "expected_sha256": carrierSHA, "expected_result_sha256": i.ResultSHA256}, &page)
		if err != nil {
			return err
		}
		paths = append(paths, p)
		if page.Result == nil || page.Result.Offset != offset || page.Result.SHA256 != i.ResultSHA256 || page.Result.TotalBytes != i.ResultBytes {
			return errors.New("EVM complete engine byte page lost identity")
		}
		chunk, e := base64.StdEncoding.DecodeString(page.Result.Base64)
		if e != nil || len(chunk) != page.Result.Bytes {
			return errors.New("EVM complete engine byte page is invalid")
		}
		joined = append(joined, chunk...)
		if page.Result.NextOffset == nil {
			break
		}
		if *page.Result.NextOffset != len(joined) || len(chunk) == 0 {
			return errors.New("EVM byte pages made no progress")
		}
		offset = *page.Result.NextOffset
	}
	if len(joined) != i.ResultBytes || goBytesSHA(joined) != i.ResultSHA256 || !json.Valid(joined) || !bytes.Contains(joined, []byte(`"fallback"`)) {
		return errors.New("full EVM engine JSON was not reconstructed")
	}
	// Separately exercise a genuinely pure result in the independent published
	// engine vector. This does not repair the compiler corpus's conservative view.
	probePath := filepath.Join(h.work, "inputs", "evm-published-probe.raw")
	if err = os.WriteFile(probePath, testfixture.EVMInterfaceProbe(), 0600); err != nil {
		return err
	}
	var pure appinspect.EVMReport
	p, err = h.call("app_evm_inspect", map[string]any{"path": probePath, "view": "interface", "encoding": "raw"}, &pure)
	if err != nil {
		return err
	}
	paths = append(paths, p, probePath)
	if pure.Interface == nil || pure.Interface.TotalFunctions != 1 || pure.Interface.FunctionPage.Functions[0].InferredStateMutability == nil || *pure.Interface.FunctionPage.Functions[0].InferredStateMutability != "pure" {
		return errors.New("published pure vector did not produce actual engine evidence")
	}
	after, _, afterSHA, err := targetidentity.CaptureFile(target, 4<<20)
	if err != nil || afterSHA != carrierSHA || !bytes.Equal(after, carrier) {
		return errors.Join(errors.New("owned EVM carrier changed"), err)
	}
	return h.closeCase("EVM 静态接口推断研究", "分析 native binary 的结构，保留静态证据并生成研究报告，复核 EVM 静态接口推断", "native-static", []string{target}, paths, "Actual pinned EVMole inferred five compiler-produced ABI selector/argument candidates and one fallback selector, with original artifact/result SHA-fenced paging. Compiler pure declarations were conservatively inferred as view in this corpus; the independent published pure vector remained pure. Inferences were preserved without asserting verified ABI, complete discovery, deployment or runtime reachability. No EVM target was executed.")
}
