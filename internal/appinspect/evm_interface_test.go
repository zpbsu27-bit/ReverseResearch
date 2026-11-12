package appinspect

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"reverseresearch/internal/appinspect/testfixture"
)

func TestEVMActualInterfacePreservesInferenceAndReconstructsRawEngineBytes(t *testing.T) {
	code := testfixture.EVMInterfaceProbe()
	carrier := []byte(" \t0X" + strings.ToUpper(hex.EncodeToString(code)) + "\r\n")
	path := input(t, "probe.hex", carrier)
	ctx := context.Background()
	r, err := InspectEVM(ctx, path, EVMOptions{View: "interface"})
	if err != nil {
		t.Fatal(err)
	}
	if r.SHA256 != digest(carrier) || r.BytecodeSHA256 != digest(code) || r.SHA256 == r.BytecodeSHA256 || r.EVMInstructionReport != nil || r.ExecutionPerformed || !r.CoverageComplete || r.Interface == nil {
		t.Fatalf("identity/profile mixed: %+v", r)
	}
	i := r.Interface
	if i.TotalFunctions != 1 || i.DiscoveryCompleteness != "unknown" || i.DeploymentAuthenticity != "unknown" || i.Hardfork != "unknown" || i.BytecodeKind != "unknown" || i.EvidenceKind != "inferred" || i.FunctionPage == nil || len(i.FunctionPage.Functions) != 1 {
		t.Fatalf("unsupported certainty: %+v", i)
	}
	f := i.FunctionPage.Functions[0]
	if f.Selector != "0xfae7ab82" || f.BytecodeOffset != 42 || f.Dispatch != "abi" || f.InferredArguments == nil || *f.InferredArguments != "uint32" || f.InferredStateMutability == nil || *f.InferredStateMutability != "pure" {
		t.Fatalf("engine result changed: %+v", f)
	}
	var joined []byte
	for offset := 0; ; {
		p, e := InspectEVM(ctx, path, EVMOptions{PageOptions: PageOptions{Offset: offset, Limit: 17, ExpectedSHA256: r.SHA256}, View: "interface-bytes", ExpectedResultSHA256: i.ResultSHA256})
		if e != nil {
			t.Fatal(e)
		}
		if p.Result == nil || p.Result.Offset != offset || p.Result.TotalBytes != i.ResultBytes || p.Result.SHA256 != i.ResultSHA256 || p.Interface.ResultSHA256 != i.ResultSHA256 || p.Interface.FunctionPage != nil {
			t.Fatalf("raw result/currentness lost: %+v", p)
		}
		b, e := base64.StdEncoding.DecodeString(p.Result.Base64)
		if e != nil || len(b) != p.Result.Bytes {
			t.Fatal("wrong byte page")
		}
		joined = append(joined, b...)
		if p.Result.NextOffset == nil {
			break
		}
		offset = *p.Result.NextOffset
	}
	if len(joined) != i.ResultBytes || digest(joined) != i.ResultSHA256 || !json.Valid(joined) || !bytes.Contains(joined, []byte(`"bytecode_offset":42`)) {
		t.Fatalf("full engine bytes not reconstructed: %s", joined)
	}
	rawPath := input(t, "probe.raw", code)
	raw, e := InspectEVM(ctx, rawPath, EVMOptions{Encoding: "raw", View: "interface"})
	if e != nil || raw.BytecodeSHA256 != r.BytecodeSHA256 || raw.Interface.ResultSHA256 != i.ResultSHA256 {
		t.Fatalf("carrier representations disagree: %+v %v", raw, e)
	}
}

func TestEVMCarrierAndInterfaceFailuresStayExplicit(t *testing.T) {
	ctx := context.Background()
	for _, carrier := range [][]byte{[]byte("0x0"), []byte("00 01"), []byte("\u00a000\u00a0"), []byte("\ufeff00"), {0xff, '0', '0'}} {
		if _, err := InspectEVM(ctx, input(t, "bad.hex", carrier), EVMOptions{View: "interface"}); err == nil {
			t.Fatalf("accepted invalid carrier %q", carrier)
		}
	}
	path := input(t, "ok.raw", testfixture.EVMInterfaceProbe())
	for _, o := range []EVMOptions{
		{Encoding: "guess", View: "interface"}, {Encoding: "raw", View: "guess"}, {Encoding: "raw", View: "interface", PageOptions: PageOptions{Offset: 1}},
		{Encoding: "raw", View: "interface", PageOptions: PageOptions{Limit: 201}}, {Encoding: "raw", View: "interface-bytes", PageOptions: PageOptions{Limit: 16385}},
		{Encoding: "raw", ExpectedResultSHA256: strings.Repeat("0", 64)},
		{Encoding: "raw", View: "interface", ExpectedResultSHA256: strings.Repeat("0", 64)},
		{Encoding: "raw", View: "interface", PageOptions: PageOptions{ExpectedSHA256: strings.Repeat("0", 64)}},
	} {
		if _, err := InspectEVM(ctx, path, o); err == nil {
			t.Fatalf("accepted invalid options %+v", o)
		}
	}
	for _, code := range [][]byte{nil, {0xef, 0, 1}} {
		if _, err := InspectEVM(ctx, input(t, "bad.raw", code), EVMOptions{Encoding: "raw", View: "interface"}); err == nil {
			t.Fatal("accepted empty/container interface")
		}
	}
	// Interface input does not depend on the linear decoder's PUSH/data policy.
	truncated := input(t, "data.hex", []byte("63ab"))
	if _, err := InspectEVM(ctx, truncated, EVMOptions{View: "interface"}); err != nil {
		t.Fatalf("linear policy improperly blocked engine profile: %v", err)
	}
	if _, err := InspectEVM(ctx, truncated, EVMOptions{}); err == nil {
		t.Fatal("linear truncated PUSH guard removed")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := InspectEVM(canceled, path, EVMOptions{Encoding: "raw", View: "interface"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("lost cancellation: %v", err)
	}
	r, err := InspectEVM(ctx, path, EVMOptions{Encoding: "raw", View: "interface"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte{0}, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectEVM(ctx, path, EVMOptions{Encoding: "raw", View: "interface-bytes", PageOptions: PageOptions{Offset: 1, ExpectedSHA256: r.SHA256}, ExpectedResultSHA256: r.Interface.ResultSHA256}); err == nil {
		t.Fatal("accepted stale artifact page")
	}
}

func TestEVMActualTerminalCBORPreservesEncodedLargeIntegerAndUndecodedValue(t *testing.T) {
	// Independent CBOR: integer exceeds JS's exact number range; array remains
	// undecoded rather than inventing a richer interpretation.
	cbor := []byte{0xa5, 0x64, 't', 'e', 'x', 't', 0x62, 'h', 'i', 0x63, 'b', 'i', 'g', 0x1b, 0, 0x20, 0, 0, 0, 0, 0, 1, 0x64, 'd', 'a', 't', 'a', 0x42, 0, 0xff, 0x64, 'f', 'l', 'a', 'g', 0xf5, 0x63, 'a', 'r', 'r', 0x82, 1, 2}
	code := append([]byte{0}, cbor...)
	code = append(code, byte(len(cbor)>>8), byte(len(cbor)))
	r, err := InspectEVM(context.Background(), input(t, "metadata.raw", code), EVMOptions{Encoding: "raw", View: "interface"})
	if err != nil {
		t.Fatal(err)
	}
	m := r.Interface.Metadata
	if m == nil || m.BytecodeOffset != 1 || m.CBORLength != len(cbor) || m.CBORSHA256 != digest(cbor) || m.TotalEntries != 5 || m.EntriesTruncated {
		t.Fatalf("CBOR projection lost original evidence: %+v", m)
	}
	var entries []evmRawCBOREntry
	if err := json.Unmarshal(m.Entries, &entries); err != nil {
		t.Fatal(err)
	}
	foundBig, foundArray := false, false
	for _, entry := range entries {
		if *entry.Key == "big" || *entry.Key == "arr" {
			var encoded []byte
			if *entry.Value.Type != "undecoded" || json.Unmarshal(entry.Value.Value, &encoded) != nil {
				t.Fatalf("engine's undecoded value was coerced: %+v", entry)
			}
			if *entry.Key == "big" {
				foundBig = bytes.Equal(encoded, []byte{0x1b, 0, 0x20, 0, 0, 0, 0, 0, 1})
			} else {
				foundArray = bytes.Equal(encoded, []byte{0x82, 1, 2})
			}
		}
	}
	if !foundBig || !foundArray {
		t.Fatalf("undecoded CBOR bytes lost: %s", m.Entries)
	}
}

func TestEVMProjectionPreservesDuplicatesUnknownAndVerbatimTypeSpelling(t *testing.T) {
	raw := []byte(`{"functions":[{"selector":"12345678","bytecode_offset":0,"dispatch":"abi"},{"selector":"12345678","bytecode_offset":1,"dispatch":"fallback","arguments":"future(type)","state_mutability":"future-state"}]}`)
	f, _, err := projectEVMInterface(raw, []byte{0, 0})
	if err != nil || len(f) != 2 || f[0].InferredArguments != nil || f[0].InferredStateMutability != nil || f[1].Dispatch != "fallback" || *f[1].InferredArguments != "future(type)" || *f[1].InferredStateMutability != "future-state" {
		t.Fatalf("projection normalized or invented values: %+v %v", f, err)
	}
	for _, raw := range []string{
		`null`, `{"functions":[{"selector":"12345678","bytecode_offset":2,"dispatch":"abi"}]}`,
		`{"functions":[{"selector":"12345678","dispatch":"abi"}]}`,
		`{"functions":[{"selector":"ABCDef01","bytecode_offset":0,"dispatch":"abi"}]}`,
		`{"functions":[{"selector":"12345678","bytecode_offset":0,"dispatch":"unknown"}]}`,
		`{"functions":[{"selector":"12345678","bytecode_offset":0,"dispatch":"abi","arguments":7}]}`,
		`{"storage":[]}`, `{} {}`,
		`{"metadata":{"bytecodeOffset":0,"cborLength":5,"entries":[]}}`,
	} {
		if _, _, err := projectEVMInterface([]byte(raw), []byte{0, 0}); err == nil {
			t.Fatalf("malformed engine schema accepted: %s", raw)
		}
	}
}
