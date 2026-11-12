// Package evmengine hosts the pinned EVMole analysis engine. The inspected EVM
// bytes are data; only the bundled analyzer is instantiated, without imports.
package evmengine

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

const (
	Version          = "0.9.3"
	WASMSHA256       = "86b743afa235d84e90030ff2b33f2eb4628b72c42dba30c5be382700a7254983"
	GzipSHA256       = "dc1924ddf5f841bfb7b0b192ec2675f7cae76a8a67b19ee3c9d6ec00e191d4cb"
	MaxInputBytes    = 4 << 20
	MaxResultBytes   = 16 << 20
	MemoryLimitBytes = 256 << 20
	Deadline         = 30 * time.Second
	// Official Go/Rust ABI: selectors | arguments | state_mutability | metadata.
	interfaceOptions = uint32(1 | 2 | 4 | 128)
)

//go:embed evmole.wasm.gz
var compressedEngine []byte

var engineOnce = sync.OnceValues(func() ([]byte, error) {
	sum := sha256.Sum256(compressedEngine)
	if hex.EncodeToString(sum[:]) != GzipSHA256 {
		return nil, errors.New("bundled EVMole compressed digest mismatch")
	}
	z, err := gzip.NewReader(bytes.NewReader(compressedEngine))
	if err != nil {
		return nil, err
	}
	defer z.Close()
	body, err := io.ReadAll(io.LimitReader(z, (1<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(body) > 1<<20 {
		return nil, errors.New("bundled EVMole module exceeds 1 MiB")
	}
	sum = sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != WASMSHA256 {
		return nil, errors.New("bundled EVMole module digest mismatch")
	}
	return body, nil
})

// Analyze owns a fresh VM through close. It has no process, filesystem, network,
// cache, or target-execution authority. The memory ceiling is WASM linear memory,
// not a promise about the surrounding Go process's total RSS.
func Analyze(ctx context.Context, code []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(code) == 0 || len(code) > MaxInputBytes {
		return nil, errors.New("EVM interface bytecode must contain 1..4194304 bytes")
	}
	wasm, err := engineOnce()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, Deadline)
	defer cancel()
	return analyzeModule(ctx, wasm, code)
}

func runtimeConfig() wazero.RuntimeConfig {
	return wazero.NewRuntimeConfig().WithMemoryLimitPages(MemoryLimitBytes / 65536).
		WithCloseOnContextDone(true).WithDebugInfoEnabled(false)
}

func analyzeModule(ctx context.Context, wasm, code []byte) (result []byte, resultErr error) {
	r := wazero.NewRuntimeWithConfig(ctx, runtimeConfig())
	defer func() {
		// Cancellation must not cancel cleanup or hide a failed close.
		if err := r.Close(context.Background()); err != nil {
			result = nil
			resultErr = errors.Join(resultErr, fmt.Errorf("EVMole runtime close: %w", err))
		}
		if err := ctx.Err(); err != nil {
			result = nil
			resultErr = errors.Join(resultErr, err)
		}
	}()
	compiled, err := r.CompileModule(ctx, wasm)
	if err != nil {
		return nil, fmt.Errorf("EVMole compile: %w", err)
	}
	if len(compiled.ImportedFunctions()) != 0 || len(compiled.ImportedMemories()) != 0 {
		return nil, errors.New("EVMole profile must not import host capabilities")
	}
	module, err := r.InstantiateModule(ctx, compiled, wazero.NewModuleConfig().WithStartFunctions())
	if err != nil {
		return nil, fmt.Errorf("EVMole instantiate: %w", err)
	}
	alloc, analyze := module.ExportedFunction("wasm_alloc"), module.ExportedFunction("contract_info")
	if !functionSignature(alloc, 1) || !functionSignature(analyze, 3) || module.Memory() == nil {
		return nil, errors.New("EVMole profile has unexpected exports")
	}
	ptrs, err := alloc.Call(ctx, uint64(len(code)))
	if err != nil {
		return nil, fmt.Errorf("EVMole input allocation: %w", err)
	}
	if len(ptrs) != 1 || ptrs[0] == 0 || ptrs[0] > math.MaxUint32 {
		return nil, errors.New("EVMole input allocation returned an invalid pointer")
	}
	if !module.Memory().Write(uint32(ptrs[0]), code) {
		return nil, errors.New("EVMole input exceeds allocated linear memory")
	}
	ptrs, err = analyze.Call(ctx, ptrs[0], uint64(len(code)), uint64(interfaceOptions))
	if err != nil {
		return nil, fmt.Errorf("EVMole analysis: %w", err)
	}
	if len(ptrs) != 1 || ptrs[0] == 0 || ptrs[0] > math.MaxUint32-4 {
		return nil, errors.New("EVMole result has an invalid pointer")
	}
	ptr := uint32(ptrs[0])
	prefix, ok := module.Memory().Read(ptr, 4)
	if !ok {
		return nil, errors.New("EVMole result length is outside linear memory")
	}
	size := binary.LittleEndian.Uint32(prefix)
	if size == 0 || size > MaxResultBytes {
		return nil, errors.New("complete EVMole result exceeds the 16 MiB result budget or is empty")
	}
	body, ok := module.Memory().Read(ptr+4, size)
	if !ok {
		return nil, errors.New("EVMole result is outside linear memory")
	}
	// No engine deallocation calls are needed: the single request's entire VM is
	// closed before this copied result can escape. There is no reused heap.
	return bytes.Clone(body), nil
}

func functionSignature(f api.Function, parameterCount int) bool {
	if f == nil {
		return false
	}
	d := f.Definition()
	if len(d.ParamTypes()) != parameterCount || len(d.ResultTypes()) != 1 || d.ResultTypes()[0] != api.ValueTypeI32 {
		return false
	}
	for _, typ := range d.ParamTypes() {
		if typ != api.ValueTypeI32 {
			return false
		}
	}
	return true
}
