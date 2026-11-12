package evmengine

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"
	"reverseresearch/internal/appinspect/testfixture"
)

func TestEVMEnginePublishedInterfaceVector(t *testing.T) {
	body, err := Analyze(context.Background(), testfixture.EVMInterfaceProbe())
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Functions []struct {
			Selector   string `json:"selector"`
			Dispatch   string `json:"dispatch"`
			Arguments  string `json:"arguments"`
			Mutability string `json:"state_mutability"`
		} `json:"functions"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Functions) != 1 || result.Functions[0].Selector != "fae7ab82" || result.Functions[0].Dispatch != "abi" || result.Functions[0].Arguments != "uint32" || result.Functions[0].Mutability != "pure" {
		t.Fatalf("unexpected actual engine result: %s", body)
	}
	t.Logf("actual pinned engine result: %s", body)
}

// Independently assembled inert WASM exercises the host's guards rather than
// trusting the real engine to happen to exhaust a particular resource.
func guardWASM(analyzeBody, payload []byte) []byte {
	leb := func(n int) []byte {
		var out []byte
		for {
			b := byte(n & 127)
			n >>= 7
			if n != 0 {
				b |= 128
			}
			out = append(out, b)
			if n == 0 {
				return out
			}
		}
	}
	module := []byte{0, 97, 115, 109, 1, 0, 0, 0}
	section := func(id byte, body []byte) {
		module = append(module, id)
		module = append(module, leb(len(body))...)
		module = append(module, body...)
	}
	section(1, []byte{2, 0x60, 1, 0x7f, 1, 0x7f, 0x60, 3, 0x7f, 0x7f, 0x7f, 1, 0x7f})
	section(3, []byte{2, 0, 1})
	section(5, []byte{1, 0, 1})
	exports := []byte{3}
	for i, name := range []string{"wasm_alloc", "contract_info", "memory"} {
		exports = append(exports, byte(len(name)))
		exports = append(exports, []byte(name)...)
		if i == 2 {
			exports = append(exports, 2, 0)
		} else {
			exports = append(exports, 0, byte(i))
		}
	}
	section(7, exports)
	function := append([]byte{0}, analyzeBody...)
	function = append(function, 0x0b)
	code := []byte{2, 4, 0, 0x41, 16, 0x0b}
	code = append(code, leb(len(function))...)
	code = append(code, function...)
	section(10, code)
	if payload != nil {
		data := []byte{1, 0, 0x41, 32, 0x0b}
		data = append(data, leb(len(payload))...)
		data = append(data, payload...)
		section(11, data)
	}
	return module
}

func TestEVMHostInterruptsActualInfiniteWASMAndRecovers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	// loop { br 0 }; unreachable, so this would never return without the host guard.
	_, err := analyzeModule(ctx, guardWASM([]byte{0x03, 0x40, 0x0c, 0, 0x0b, 0}, nil), []byte{0})
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "EVMole analysis") || time.Since(started) > 2*time.Second {
		t.Fatalf("deadline did not terminate VM: %v %s", err, time.Since(started))
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	if _, err := Analyze(ctx2, testfixture.EVMInterfaceProbe()); !errors.Is(err, context.Canceled) {
		t.Fatalf("lost caller cancellation: %v", err)
	}
	if _, err := Analyze(context.Background(), testfixture.EVMInterfaceProbe()); err != nil {
		t.Fatalf("failed request poisoned subsequent fresh VM: %v", err)
	}
}

func TestEVMHostLinearMemoryCeilingRejectsGrowth(t *testing.T) {
	ctx := context.Background()
	r := wazero.NewRuntimeWithConfig(ctx, runtimeConfig())
	defer r.Close(ctx)
	// Starting from one page, request 4096 additional pages: exceeds 256 MiB.
	m, err := r.Instantiate(ctx, guardWASM([]byte{0x41, 0x80, 0x20, 0x40, 0}, nil))
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.ExportedFunction("contract_info").Call(ctx, 0, 0, 0)
	if err != nil || len(got) != 1 || got[0] != uint64(0xffffffff) || m.Memory().Size() != 65536 {
		t.Fatalf("linear memory ceiling not enforced: %v %v %d", got, err, m.Memory().Size())
	}
	if err := m.Close(ctx); err != nil || !m.IsClosed() {
		t.Fatalf("module not closed: %v", err)
	}
}

func TestEVMHostRejectsBadPointersTrapsAndOversizeReply(t *testing.T) {
	prefix := make([]byte, 4)
	binary.LittleEndian.PutUint32(prefix, MaxResultBytes+1)
	for _, tc := range []struct {
		name          string
		body, payload []byte
		want          string
	}{
		{"null", []byte{0x41, 0}, nil, "invalid pointer"},
		{"overflow", []byte{0x41, 0x7f}, nil, "invalid pointer"},
		{"trap", []byte{0}, nil, "analysis"},
		{"oversize", []byte{0x41, 32}, prefix, "16 MiB"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, err := analyzeModule(context.Background(), guardWASM(tc.body, tc.payload), []byte{0})
			if err == nil || body != nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("bad engine response accepted: %s %v", body, err)
			}
		})
	}
	for _, code := range [][]byte{nil, make([]byte, MaxInputBytes+1)} {
		if _, err := Analyze(context.Background(), code); err == nil {
			t.Fatal("unbounded/empty bytecode accepted")
		}
	}
}
