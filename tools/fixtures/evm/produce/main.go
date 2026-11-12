// produce compiles source-owned EVM fixtures with one exact official compiler.
// Compiler execution is distinct from target execution; targets are never run.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"reverseresearch/internal/toolprocess"
)

const compilerSHA = "76a71001309810aafd0462d9b2f2612bf19b89550c866140edca26e533de06bc"

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: produce <exact-solc-exe> <owned-source.sol> <fresh-output-directory>")
		os.Exit(2)
	}
	if err := produce(os.Args[1], os.Args[2], os.Args[3]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func sha(body []byte) string { x := sha256.Sum256(body); return hex.EncodeToString(x[:]) }
func writeJSON(path string, value any) error {
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(body, '\n'), 0600)
}
func produce(compiler, source, out string) error {
	var err error
	for _, path := range []*string{&compiler, &source, &out} {
		*path, err = filepath.Abs(*path)
		if err != nil {
			return err
		}
	}
	compilerBytes, err := os.ReadFile(compiler)
	if err != nil {
		return err
	}
	if sha(compilerBytes) != compilerSHA {
		return errors.New("compiler does not match pinned official Windows solc 0.8.28")
	}
	sourceBytes, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	if err = os.Mkdir(out, 0700); err != nil {
		return fmt.Errorf("fresh producer directory required: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	version := toolprocess.Run(ctx, compiler, []string{"--version"}, 128<<10, 128<<10, out)
	if version.Err != nil || version.Truncated || !strings.Contains(string(version.Stdout), "0.8.28+commit.7893614a") {
		return errors.Join(errors.New("unexpected compiler version"), version.Err)
	}
	input := map[string]any{"language": "Solidity", "sources": map[string]any{"InterfaceProbe.sol": map[string]any{"content": string(sourceBytes)}}, "settings": map[string]any{"optimizer": map[string]any{"enabled": true, "runs": 200}, "evmVersion": "cancun", "metadata": map[string]any{"bytecodeHash": "none", "appendCBOR": true}, "outputSelection": map[string]any{"*": map[string]any{"*": []string{"abi", "evm.deployedBytecode.object", "evm.methodIdentifiers", "evm.bytecode.object"}}}}}
	inputPath := filepath.Join(out, "compiler-input.json")
	if err = writeJSON(inputPath, input); err != nil {
		return err
	}
	run := toolprocess.Run(ctx, compiler, []string{"--standard-json", inputPath}, 16<<20, 1<<20, out)
	if err = os.WriteFile(filepath.Join(out, "compiler-output.json"), run.Stdout, 0600); err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(out, "compiler-stderr.log"), run.Stderr, 0600); err != nil {
		return err
	}
	if run.Err != nil || run.Truncated {
		return errors.Join(errors.New("compiler failed or output was truncated"), run.Err)
	}
	var result struct {
		Errors []struct {
			Severity         string
			FormattedMessage string
		} `json:"errors"`
		Contracts map[string]map[string]struct {
			ABI json.RawMessage `json:"abi"`
			EVM struct {
				DeployedBytecode struct {
					Object string `json:"object"`
				} `json:"deployedBytecode"`
				MethodIdentifiers map[string]string `json:"methodIdentifiers"`
			} `json:"evm"`
		} `json:"contracts"`
	}
	if err = json.Unmarshal(run.Stdout, &result); err != nil {
		return err
	}
	for _, e := range result.Errors {
		if e.Severity == "error" {
			return errors.New(e.FormattedMessage)
		}
	}
	contract, ok := result.Contracts["InterfaceProbe.sol"]["RRInterfaceProbe"]
	if !ok {
		return errors.New("owned contract absent from compiler output")
	}
	code, err := hex.DecodeString(contract.EVM.DeployedBytecode.Object)
	if err != nil || len(code) == 0 {
		return errors.Join(errors.New("invalid compiler runtime bytecode"), err)
	}
	targetPath := filepath.Join(out, "InterfaceProbe.hex")
	carrier := []byte("0x" + contract.EVM.DeployedBytecode.Object + "\n")
	if err = os.WriteFile(targetPath, carrier, 0600); err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(out, "InterfaceProbe.raw"), code, 0600); err != nil {
		return err
	}
	after, err := os.ReadFile(compiler)
	if err != nil || sha(after) != compilerSHA {
		return errors.Join(errors.New("compiler supply changed"), err)
	}
	receipt := map[string]any{"compiler_path": compiler, "compiler_sha256": compilerSHA, "compiler_version": strings.TrimSpace(string(version.Stdout)), "source_path": source, "source_sha256": sha(sourceBytes), "target_path": targetPath, "target_sha256": sha(carrier), "bytecode_sha256": sha(code), "bytecode_bytes": len(code), "abi": contract.ABI, "method_identifiers": contract.EVM.MethodIdentifiers, "compiler_output_sha256": sha(run.Stdout), "target_execution_performed": false, "deployment_performed": false}
	if err = writeJSON(filepath.Join(out, "receipt.json"), receipt); err != nil {
		return err
	}
	fmt.Printf("PASS source_sha256=%s bytecode_bytes=%d methods=%d receipt=%s\n", sha(sourceBytes), len(code), len(contract.EVM.MethodIdentifiers), filepath.Join(out, "receipt.json"))
	return nil
}
