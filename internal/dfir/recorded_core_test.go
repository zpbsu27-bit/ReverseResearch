package dfir

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"reverseresearch/internal/dfir/testfixture"
)

func coreInput(t *testing.T, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "recorded.core")
	if err := os.WriteFile(p, b, 0600); err != nil {
		t.Fatal(err)
	}
	return p
}
func TestRecordedCoreThreadsBindEveryRegisterToBytes(t *testing.T) {
	b := testfixture.Core()
	p := coreInput(t, b)
	r, err := InspectRecordedCore(p, CoreOptions{View: "threads"})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Threads) != 2 || r.TotalNotes != 4 || r.Threads[0].HistoricalPID != 4242 || r.LiveProcessSelected || r.ExecutionPerformed || r.NoteInterpretationComplete {
		t.Fatalf("recorded core %+v", r)
	}
	for i, thread := range r.Threads {
		if len(thread.Registers) != 27 {
			t.Fatal("incomplete ABI registers")
		}
		for j, reg := range thread.Registers {
			if reg.Range.Size != 8 || binary.LittleEndian.Uint64(b[reg.Range.Offset:reg.Range.Offset+8]) != 0xffff000000000000+uint64(i*100+j) {
				t.Fatalf("register source %+v", reg)
			}
		}
		if thread.Registers[16].Name != "rip" || thread.Registers[26].Name != "gs" {
			t.Fatal("ABI order changed")
		}
	}
	s, err := InspectRecordedCore(p, CoreOptions{View: "signals"})
	if err != nil || s.Signals[0].FaultAddress == nil || *s.Signals[0].FaultAddress != "0xfffff123456789ab" || s.Signals[0].Code != 2 {
		t.Fatalf("SIGINFO %+v %v", s, err)
	}
	segments, err := InspectRecordedCore(p, CoreOptions{View: "segments"})
	if err != nil || segments.Segments[1].UndumpedBytes != "0xffc" {
		t.Fatalf("segments %+v %v", segments, err)
	}
	notes, err := InspectRecordedCore(p, CoreOptions{Offset: 3, Limit: 1})
	if err != nil || notes.Notes[0].Interpretation != "unknown" || notes.Notes[0].OwnerBase64 != "/wA=" {
		t.Fatalf("opaque %+v %v", notes, err)
	}
	v, err := ReadCoreNote(p, CoreNoteReadOptions{NoteIndex: 3, CoreOptions: CoreOptions{ExpectedSHA256: r.SHA256, Limit: 2}})
	if err != nil || v.DataBase64 != "AQI=" || v.NextOffset == nil {
		t.Fatalf("raw %+v %v", v, err)
	}
	if _, err := InspectRecordedCore(p, CoreOptions{ExpectedSHA256: strings.Repeat("0", 64)}); err == nil {
		t.Fatal("stale core accepted")
	}
	after, _ := os.ReadFile(p)
	if !bytes.Equal(b, after) {
		t.Fatal("snapshot was changed")
	}
	owner, err := ReadCoreNote(p, CoreNoteReadOptions{NoteIndex: 3, Part: "owner"})
	if err != nil || owner.DataBase64 != base64.StdEncoding.EncodeToString([]byte{0xff, 0}) {
		t.Fatal("owner bytes lost")
	}
}
func TestRecordedCoreHiddenMalformedNotesAndProfiles(t *testing.T) {
	good := testfixture.Core()
	for name, change := range map[string]func([]byte){"abi": func(b []byte) { b[7] = 9 }, "arch": func(b []byte) { b[18] = 3 }, "class": func(b []byte) { b[4] = 1 }, "endian": func(b []byte) { b[5] = 2 }, "hidden-note": func(b []byte) { binary.LittleEndian.PutUint32(b[176+356+356:], 0xffffffff) }, "short-prstatus": func(b []byte) { binary.LittleEndian.PutUint32(b[180:], 328) }, "load-range": func(b []byte) { binary.LittleEndian.PutUint64(b[152:], 0xffffffffffffffff) }, "program-count": func(b []byte) { binary.LittleEndian.PutUint16(b[56:], 5000) }, "align": func(b []byte) { binary.LittleEndian.PutUint64(b[112:], 8) }, "overlap": func(b []byte) { copy(b[120:176], b[64:120]) }} {
		t.Run(name, func(t *testing.T) {
			b := append([]byte{}, good...)
			change(b)
			if _, err := InspectRecordedCore(coreInput(t, b), CoreOptions{Limit: 1}); err == nil {
				t.Fatal("malformed core accepted")
			}
		})
	}
	if _, err := InspectRecordedCore(coreInput(t, good[:len(good)-5]), CoreOptions{}); err == nil {
		t.Fatal("truncated segment accepted")
	}
}
func TestRecordedCoreMissingNotesAndSignalUnionUnknown(t *testing.T) {
	b := testfixture.Core()
	binary.LittleEndian.PutUint32(b[64:], 1)
	r, err := InspectRecordedCore(coreInput(t, b), CoreOptions{View: "threads"})
	if err != nil || r.TotalThreads != 0 || r.TotalNotes != 0 || r.NoteInterpretationComplete {
		t.Fatalf("missing is unknown %+v %v", r, err)
	}
	b = testfixture.Core()
	signalDesc := 176 + 356 + 356 + 20
	binary.LittleEndian.PutUint32(b[signalDesc+8:], 0xfffffffa)
	r, err = InspectRecordedCore(coreInput(t, b), CoreOptions{View: "signals"})
	if err != nil || r.Signals[0].Code != -6 || r.Signals[0].FaultAddress != nil || r.Signals[0].UnionInterpretation != "unknown" {
		t.Fatalf("signal union %+v %v", r, err)
	}
}
