package dfir

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"reverseresearch/internal/recordio"
	"reverseresearch/internal/targetidentity"
)

const maxCoreBytes = 32 << 20

type CoreOptions struct {
	Offset         int    `json:"offset,omitempty"`
	Limit          int    `json:"limit,omitempty"`
	ExpectedSHA256 string `json:"expected_sha256,omitempty"`
	View           string `json:"view,omitempty"`
}
type CoreRange struct {
	Offset uint64 `json:"offset"`
	Size   uint64 `json:"size"`
}
type CoreSegment struct {
	Index          int       `json:"index"`
	HeaderRange    CoreRange `json:"header_range"`
	Type           string    `json:"type"`
	Flags          string    `json:"flags"`
	FileRange      CoreRange `json:"file_range"`
	VirtualAddress string    `json:"virtual_address"`
	MemorySize     string    `json:"memory_size"`
	UndumpedBytes  string    `json:"undumped_bytes"`
}
type CoreNote struct {
	Index            int       `json:"index"`
	SegmentIndex     int       `json:"segment_index"`
	Type             uint32    `json:"type"`
	Range            CoreRange `json:"range"`
	OwnerRange       CoreRange `json:"owner_range"`
	DescriptorRange  CoreRange `json:"descriptor_range"`
	OwnerBase64      string    `json:"owner_base64"`
	DescriptorSHA256 string    `json:"descriptor_sha256"`
	Interpretation   string    `json:"interpretation"`
}
type CoreRegister struct {
	Name  string    `json:"name"`
	Value string    `json:"value"`
	Range CoreRange `json:"range"`
}
type CoreThread struct {
	NoteIndex             int            `json:"note_index"`
	HistoricalPID         int32          `json:"historical_pid"`
	PIDRange              CoreRange      `json:"pid_range"`
	RecordedCurrentSignal uint16         `json:"recorded_current_signal"`
	SignalRange           CoreRange      `json:"signal_range"`
	Registers             []CoreRegister `json:"registers"`
}
type CoreSignal struct {
	NoteIndex           int        `json:"note_index"`
	Number              int32      `json:"number"`
	Code                int32      `json:"code"`
	Errno               int32      `json:"errno"`
	NumberRange         CoreRange  `json:"number_range"`
	CodeRange           CoreRange  `json:"code_range"`
	ErrnoRange          CoreRange  `json:"errno_range"`
	FaultAddress        *string    `json:"fault_address,omitempty"`
	FaultAddressRange   *CoreRange `json:"fault_address_range,omitempty"`
	UnionInterpretation string     `json:"union_interpretation"`
}
type CoreReport struct {
	Path                       string        `json:"path"`
	SHA256                     string        `json:"sha256"`
	Size                       int           `json:"size"`
	Profile                    string        `json:"profile"`
	DeclaredOSABI              string        `json:"declared_osabi"`
	HeaderSHA256               string        `json:"header_sha256"`
	ProgramHeadersSHA256       string        `json:"program_headers_sha256"`
	View                       string        `json:"view"`
	TotalSegments              int           `json:"total_segments"`
	TotalNotes                 int           `json:"total_notes"`
	TotalThreads               int           `json:"total_threads"`
	TotalSignals               int           `json:"total_signals"`
	Offset                     int           `json:"offset"`
	Segments                   []CoreSegment `json:"segments,omitempty"`
	Notes                      []CoreNote    `json:"notes,omitempty"`
	Threads                    []CoreThread  `json:"threads,omitempty"`
	Signals                    []CoreSignal  `json:"signals,omitempty"`
	NextOffset                 *int          `json:"next_offset,omitempty"`
	CoverageComplete           bool          `json:"coverage_complete"`
	NoteInterpretationComplete bool          `json:"note_interpretation_complete"`
	ExecutionPerformed         bool          `json:"execution_performed"`
	LiveProcessSelected        bool          `json:"live_process_selected"`
	Limitations                []string      `json:"limitations"`
}

func coreHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func coreProjection(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > 48<<10 {
		return errors.New("core projection exceeds 48 KiB; request a smaller page")
	}
	return nil
}
func corePage(o CoreOptions, total int) (int, int, error) {
	if o.Limit == 0 {
		o.Limit = 20
	}
	if o.Offset < 0 || o.Offset > total || o.Limit < 1 || o.Limit > 200 {
		return 0, 0, errors.New("core offset/limit outside bounded inventory")
	}
	return o.Offset, min(total, o.Offset+o.Limit), nil
}

type coreDocument struct {
	segments                       []CoreSegment
	notes                          []CoreNote
	threads                        []CoreThread
	signals                        []CoreSignal
	headerHash, programHash, osabi string
}

func captureCore(p, expected string) ([]byte, string, string, error) {
	b, abs, hash, err := targetidentity.CaptureFile(p, maxCoreBytes)
	if err != nil {
		return nil, "", "", err
	}
	if err := recordio.CheckExpectedSHA256(hash, expected); err != nil {
		return nil, "", "", err
	}
	return b, abs, hash, nil
}

func parseRecordedCore(b []byte) (coreDocument, error) {
	d := coreDocument{segments: []CoreSegment{}, notes: []CoreNote{}, threads: []CoreThread{}, signals: []CoreSignal{}}
	if len(b) < 64 || !bytes.Equal(b[:4], []byte("\x7fELF")) || b[4] != 2 || b[5] != 1 || b[6] != 1 || b[8] != 0 || (b[7] != 0 && b[7] != 3) {
		return d, errors.New("recorded core supports ELF64 little-endian System V/Linux ABI version 0 only")
	}
	if err := targetidentity.ValidateContainerBudget(bytes.NewReader(b), int64(len(b))); err != nil {
		return d, err
	}
	f, err := elf.NewFile(bytes.NewReader(b))
	if err != nil {
		return d, err
	}
	defer f.Close()
	if f.Type != elf.ET_CORE || f.Machine != elf.EM_X86_64 {
		return d, errors.New("recorded core requires ET_CORE x86-64")
	}
	order := binary.LittleEndian
	phoff := order.Uint64(b[32:40])
	width := uint64(order.Uint16(b[54:56]))
	count := uint64(len(f.Progs))
	if order.Uint16(b[52:54]) != 64 || width < 56 || count > 4096 || phoff > uint64(len(b)) || count*width > uint64(len(b))-phoff {
		return d, errors.New("ELF header/program table outside bounded profile")
	}
	d.headerHash = coreHash(b[:64])
	d.programHash = coreHash(b[phoff : phoff+count*width])
	d.osabi = f.OSABI.String()
	noteRanges := [][2]uint64{}
	// Reject overlapping note segments before hashing/decoding any descriptor.
	// Otherwise duplicated physical bytes could multiply work before rejection.
	for _, p := range f.Progs {
		if p.Type != elf.PT_NOTE || p.Filesz == 0 {
			continue
		}
		if p.Off > uint64(len(b)) || p.Filesz > uint64(len(b))-p.Off {
			return d, errors.New("ELF note segment range outside artifact")
		}
		noteRanges = append(noteRanges, [2]uint64{p.Off, p.Off + p.Filesz})
	}
	sort.Slice(noteRanges, func(i, j int) bool { return noteRanges[i][0] < noteRanges[j][0] })
	for i := 1; i < len(noteRanges); i++ {
		if noteRanges[i][0] < noteRanges[i-1][1] {
			return d, errors.New("ELF note segments overlap")
		}
	}
	for i, p := range f.Progs {
		if p.Off > uint64(len(b)) || p.Filesz > uint64(len(b))-p.Off || p.Vaddr > ^uint64(0)-p.Memsz || (p.Type == elf.PT_LOAD && p.Filesz > p.Memsz) {
			return d, errors.New("ELF segment has invalid recorded file/memory range")
		}
		undumped := uint64(0)
		if p.Memsz > p.Filesz {
			undumped = p.Memsz - p.Filesz
		}
		d.segments = append(d.segments, CoreSegment{Index: i, HeaderRange: CoreRange{phoff + uint64(i)*width, width}, Type: p.Type.String(), Flags: p.Flags.String(), FileRange: CoreRange{p.Off, p.Filesz}, VirtualAddress: fmt.Sprintf("0x%016x", p.Vaddr), MemorySize: fmt.Sprintf("0x%x", p.Memsz), UndumpedBytes: fmt.Sprintf("0x%x", undumped)})
		if p.Type != elf.PT_NOTE || p.Filesz == 0 {
			continue
		}
		if p.Align != 0 && p.Align != 4 {
			return d, errors.New("ELF note segment alignment unsupported")
		}
		pos, end := p.Off, p.Off+p.Filesz
		for pos < end {
			if end-pos < 12 {
				for _, v := range b[pos:end] {
					if v != 0 {
						return d, errors.New("nonzero incomplete ELF note header")
					}
				}
				break
			}
			if len(d.notes) >= 20000 {
				return d, errors.New("ELF note count exceeds limit")
			}
			nameSize, descSize, kind := uint64(order.Uint32(b[pos:pos+4])), uint64(order.Uint32(b[pos+4:pos+8])), order.Uint32(b[pos+8:pos+12])
			ownerStart := pos + 12
			descStart := ownerStart + (nameSize+3)&^uint64(3)
			next := descStart + (descSize+3)&^uint64(3)
			if nameSize > 4096 || next > end || descStart > end || nameSize > end-ownerStart || descSize > end-descStart {
				return d, errors.New("ELF note owner/descriptor range is truncated or excessive")
			}
			owner, desc := b[ownerStart:ownerStart+nameSize], b[descStart:descStart+descSize]
			n := CoreNote{Index: len(d.notes), SegmentIndex: i, Type: kind, Range: CoreRange{pos, next - pos}, OwnerRange: CoreRange{ownerStart, nameSize}, DescriptorRange: CoreRange{descStart, descSize}, OwnerBase64: base64.StdEncoding.EncodeToString(owner), DescriptorSHA256: coreHash(desc), Interpretation: "unknown"}
			if bytes.Equal(owner, []byte("CORE\x00")) {
				switch kind {
				case 1:
					if len(desc) < 336 {
						return d, errors.New("Linux amd64 PRSTATUS descriptor is truncated")
					}
					n.Interpretation = "linux-amd64-prstatus"
					thread := CoreThread{NoteIndex: n.Index, HistoricalPID: int32(order.Uint32(desc[32:36])), PIDRange: CoreRange{descStart + 32, 4}, RecordedCurrentSignal: order.Uint16(desc[12:14]), SignalRange: CoreRange{descStart + 12, 2}, Registers: []CoreRegister{}}
					names := []string{"r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8", "rax", "rcx", "rdx", "rsi", "rdi", "orig_rax", "rip", "cs", "eflags", "rsp", "ss", "fs_base", "gs_base", "ds", "es", "fs", "gs"}
					for j, name := range names {
						relative := 112 + j*8
						thread.Registers = append(thread.Registers, CoreRegister{Name: name, Value: fmt.Sprintf("0x%016x", order.Uint64(desc[relative:relative+8])), Range: CoreRange{descStart + uint64(relative), 8}})
					}
					d.threads = append(d.threads, thread)
				case 0x53494749:
					if len(desc) < 128 {
						return d, errors.New("Linux amd64 SIGINFO descriptor is truncated")
					}
					n.Interpretation = "linux-amd64-siginfo"
					s := CoreSignal{NoteIndex: n.Index, Number: int32(order.Uint32(desc[:4])), Errno: int32(order.Uint32(desc[4:8])), Code: int32(order.Uint32(desc[8:12])), NumberRange: CoreRange{descStart, 4}, ErrnoRange: CoreRange{descStart + 4, 4}, CodeRange: CoreRange{descStart + 8, 4}, UnionInterpretation: "unknown"}
					if s.Number == 11 && (s.Code == 1 || s.Code == 2) {
						value := fmt.Sprintf("0x%016x", order.Uint64(desc[16:24]))
						rng := CoreRange{descStart + 16, 8}
						s.FaultAddress = &value
						s.FaultAddressRange = &rng
						s.UnionInterpretation = "sigsegv-maperr-or-accerr-fault-address"
					}
					d.signals = append(d.signals, s)
				}
			}
			d.notes = append(d.notes, n)
			pos = next
		}
	}
	return d, nil
}

func InspectRecordedCore(p string, o CoreOptions) (CoreReport, error) {
	b, abs, hash, err := captureCore(p, o.ExpectedSHA256)
	if err != nil {
		return CoreReport{}, err
	}
	d, err := parseRecordedCore(b)
	if err != nil {
		return CoreReport{}, err
	}
	if o.View == "" {
		o.View = "notes"
	}
	total := len(d.notes)
	switch o.View {
	case "notes":
	case "segments":
		total = len(d.segments)
	case "threads":
		total = len(d.threads)
	case "signals":
		total = len(d.signals)
	default:
		return CoreReport{}, errors.New("core view must be notes, segments, threads or signals")
	}
	start, end, err := corePage(o, total)
	if err != nil {
		return CoreReport{}, err
	}
	r := CoreReport{Path: abs, SHA256: hash, Size: len(b), Profile: "linux-elf64-amd64-le-recorded-notes", DeclaredOSABI: d.osabi, HeaderSHA256: d.headerHash, ProgramHeadersSHA256: d.programHash, View: o.View, TotalSegments: len(d.segments), TotalNotes: len(d.notes), TotalThreads: len(d.threads), TotalSignals: len(d.signals), Offset: start, CoverageComplete: start == 0 && end == total, Limitations: []string{"historical PIDs and register/signal values never select, authorize or attach to a live process", "only exact CORE NUL owner PRSTATUS/SIGINFO notes are interpreted; other owner/types remain unknown and source-readable", "note interpretation completeness, crash-thread association, unwind, executable identity and exploitability remain unknown", "undumped memory is unavailable; no GDB/pwndbg/pwntools/Unicorn process or target execution", "System V/unspecified OSABI does not prove Linux origin; this is an explicit Linux amd64 interpretation profile"}}
	switch o.View {
	case "notes":
		r.Notes = d.notes[start:end]
	case "segments":
		r.Segments = d.segments[start:end]
	case "threads":
		r.Threads = d.threads[start:end]
	case "signals":
		r.Signals = d.signals[start:end]
	}
	if end < total {
		r.NextOffset = &end
	}
	return r, coreProjection(r)
}

type CoreNoteReadOptions struct {
	CoreOptions
	NoteIndex int    `json:"note_index"`
	Part      string `json:"part,omitempty"`
}
type CoreNoteReadReport struct {
	Path                string    `json:"path"`
	SHA256              string    `json:"sha256"`
	NoteIndex           int       `json:"note_index"`
	Part                string    `json:"part"`
	Range               CoreRange `json:"range"`
	ContentSHA256       string    `json:"content_sha256"`
	Offset              int       `json:"offset"`
	ReadBytes           int       `json:"read_bytes"`
	DataBase64          string    `json:"data_base64"`
	NextOffset          *int      `json:"next_offset,omitempty"`
	CoverageComplete    bool      `json:"coverage_complete"`
	LiveProcessSelected bool      `json:"live_process_selected"`
}

func ReadCoreNote(p string, o CoreNoteReadOptions) (CoreNoteReadReport, error) {
	if o.Limit == 0 {
		o.Limit = 8192
	}
	if o.Offset < 0 || o.Limit < 1 || o.Limit > 16384 {
		return CoreNoteReadReport{}, errors.New("core note offset must be nonnegative; limit must be 1..16384 bytes")
	}
	b, abs, hash, err := captureCore(p, o.ExpectedSHA256)
	if err != nil {
		return CoreNoteReadReport{}, err
	}
	d, err := parseRecordedCore(b)
	if err != nil {
		return CoreNoteReadReport{}, err
	}
	if o.NoteIndex < 0 || o.NoteIndex >= len(d.notes) {
		return CoreNoteReadReport{}, errors.New("core note index outside inventory")
	}
	if o.Part == "" {
		o.Part = "descriptor"
	}
	var rng CoreRange
	switch o.Part {
	case "descriptor":
		rng = d.notes[o.NoteIndex].DescriptorRange
	case "owner":
		rng = d.notes[o.NoteIndex].OwnerRange
	default:
		return CoreNoteReadReport{}, errors.New("core note part must be owner or descriptor")
	}
	data := b[rng.Offset : rng.Offset+rng.Size]
	if o.Offset > len(data) {
		return CoreNoteReadReport{}, errors.New("offset outside core note bytes")
	}
	end := min(len(data), o.Offset+o.Limit)
	r := CoreNoteReadReport{Path: abs, SHA256: hash, NoteIndex: o.NoteIndex, Part: o.Part, Range: rng, ContentSHA256: coreHash(data), Offset: o.Offset, ReadBytes: end - o.Offset, DataBase64: base64.StdEncoding.EncodeToString(data[o.Offset:end]), CoverageComplete: o.Offset == 0 && end == len(data)}
	if end < len(data) {
		r.NextOffset = &end
	}
	return r, coreProjection(r)
}
