package appinspect

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math"
)

type ManagedMethod struct {
	Token               string `json:"token"`
	Name                string `json:"name"`
	DeclaringType       string `json:"declaring_type"`
	RVA                 uint32 `json:"rva"`
	Flags               uint32 `json:"flags"`
	ImplementationFlags uint32 `json:"implementation_flags"`
	SignatureSHA256     string `json:"signature_sha256"`
	SignatureHex        string `json:"signature_hex,omitempty"`
}
type ManagedImport struct {
	MemberToken string `json:"member_token"`
	Module      string `json:"module"`
	EntryPoint  string `json:"entry_point"`
	Flags       uint32 `json:"flags"`
}
type ManagedReport struct {
	Path                   string          `json:"path"`
	SHA256                 string          `json:"sha256"`
	Format                 string          `json:"format"`
	MetadataAvailable      bool            `json:"metadata_available"`
	UnavailableReason      string          `json:"unavailable_reason,omitempty"`
	Module                 string          `json:"module,omitempty"`
	MVID                   string          `json:"mvid,omitempty"`
	Assembly               string          `json:"assembly,omitempty"`
	MetadataVersion        string          `json:"metadata_version,omitempty"`
	CLIFlags               uint32          `json:"cli_flags"`
	HasNativeHeader        bool            `json:"has_native_header"`
	TypeCount              int             `json:"type_count"`
	TotalMethods           int             `json:"total_methods"`
	Offset                 int             `json:"offset"`
	Methods                []ManagedMethod `json:"methods"`
	NextOffset             *int            `json:"next_offset,omitempty"`
	NativeImports          []ManagedImport `json:"native_imports"`
	TotalNativeImports     int             `json:"total_native_imports"`
	NativeImportsTruncated bool            `json:"native_imports_truncated"`
	CoverageComplete       bool            `json:"coverage_complete"`
	EvidenceAuthority      string          `json:"evidence_authority"`
	Limitations            []string        `json:"limitations"`
	ExecutionPerformed     bool            `json:"execution_performed"`
	NetworkInteraction     bool            `json:"network_interaction"`
}

func (m *metadata) methods() ([]ManagedMethod, error) {
	types := make([]string, m.rows[2]+1)
	starts := make([]int, m.rows[2]+1)
	methodTable := 6
	if m.rows[5] > 0 {
		methodTable = 5
	}
	for i := 1; i <= m.rows[2]; i++ {
		r, _ := m.row(2, i)
		name, err := m.text(r[1])
		if err != nil {
			return nil, err
		}
		ns, err := m.text(r[2])
		if err != nil {
			return nil, err
		}
		types[i] = name
		if ns != "" {
			types[i] = ns + "." + name
		}
		starts[i] = int(r[5])
		if starts[i] < 1 || starts[i] > m.rows[methodTable]+1 || i > 1 && starts[i] < starts[i-1] {
			return nil, errors.New("invalid TypeDef method-list range")
		}
	}
	parents := map[int]int{}
	for i := 1; i <= m.rows[41]; i++ {
		r, _ := m.row(41, i)
		child, parent := int(r[0]), int(r[1])
		if child < 1 || child > m.rows[2] || parent < 1 || parent > m.rows[2] || parents[child] != 0 {
			return nil, errors.New("invalid nested type owner")
		}
		parents[child] = parent
	}
	var typeName func(int, map[int]bool) (string, error)
	typeName = func(id int, seen map[int]bool) (string, error) {
		if seen[id] || len(seen) > 32 {
			return "", errors.New("nested type identity cycle/depth overflow")
		}
		seen[id] = true
		if p := parents[id]; p != 0 {
			outer, err := typeName(p, seen)
			if err != nil {
				return "", err
			}
			return outer + "+" + types[id], nil
		}
		return types[id], nil
	}
	owners := make([]string, m.rows[6]+1)
	for i := 1; i <= m.rows[2]; i++ {
		end := m.rows[methodTable] + 1
		if i < m.rows[2] {
			end = starts[i+1]
		}
		name, err := typeName(i, map[int]bool{})
		if err != nil || len(name) > 4096 {
			return nil, errors.New("invalid nested type identity")
		}
		for k := starts[i]; k < end; k++ {
			id := k
			if methodTable == 5 {
				ptr, _ := m.row(5, k)
				id = int(ptr[0])
			}
			if id < 1 || id > m.rows[6] || owners[id] != "" {
				return nil, errors.New("ambiguous or invalid MethodPtr ownership")
			}
			owners[id] = name
		}
	}
	methods := make([]ManagedMethod, 0, m.rows[6])
	for i := 1; i <= m.rows[6]; i++ {
		r, _ := m.row(6, i)
		name, err := m.text(r[3])
		if err != nil {
			return nil, err
		}
		sig, err := m.blob(r[4])
		if err != nil {
			return nil, err
		}
		if len(sig) == 0 {
			return nil, errors.New("method signature is unavailable")
		}
		v := ManagedMethod{Token: fmt.Sprintf("0x%08x", 0x06000000+i), Name: name, DeclaringType: owners[i], RVA: r[0], Flags: r[2], ImplementationFlags: r[1], SignatureSHA256: digest(sig)}
		if len(sig) <= 256 {
			v.SignatureHex = hex.EncodeToString(sig)
		}
		methods = append(methods, v)
	}
	return methods, nil
}
func InspectManaged(path string, o PageOptions) (ManagedReport, error) {
	body, abs, hash, err := readArtifact(path, MaxArtifactBytes, o.ExpectedSHA256)
	if err != nil {
		return ManagedReport{}, err
	}
	m, err := parseMetadata(body)
	if err != nil {
		return ManagedReport{}, err
	}
	r := ManagedReport{Path: abs, SHA256: hash, Format: "native-pe", EvidenceAuthority: "artifact-bytes", Methods: []ManagedMethod{}, NativeImports: []ManagedImport{}, Limitations: []string{"static PE/CLI metadata only; runtime family and behavior are not established", "tokens and RVAs are local to this SHA-256/MVID; no cross-build identity inference", "CIL decoding is selected-method inspection; this inventory does not validate every method body", "no NativeAOT/IL2CPP/single-file unpacking, CLR loading or C# reconstruction"}}
	if m.table == nil {
		if _, _, err := page(o, 0); err != nil {
			return r, err
		}
		r.UnavailableReason = "PE has no admitted CLI metadata; managed identity is unavailable"
		return r, nil
	}
	r.Format = "pe-cli"
	r.MetadataAvailable = true
	r.CLIFlags = m.cliFlags
	r.HasNativeHeader = m.nativeHeader
	r.MetadataVersion = m.version
	module, _ := m.row(0, 1)
	if r.Module, err = m.text(module[1]); err != nil {
		return r, err
	}
	if r.MVID, err = m.guid(module[2]); err != nil {
		return r, err
	}
	if m.rows[32] == 1 {
		assembly, _ := m.row(32, 1)
		if r.Assembly, err = m.text(assembly[7]); err != nil {
			return r, err
		}
	}
	methods, err := m.methods()
	if err != nil {
		return r, err
	}
	start, end, err := page(o, len(methods))
	if err != nil {
		return r, err
	}
	r.TypeCount = m.rows[2]
	r.TotalMethods = len(methods)
	r.Offset = start
	r.Methods = methods[start:end]
	r.CoverageComplete = start == 0 && end == len(methods) && m.rows[28] <= 50
	if end < len(methods) {
		r.NextOffset = &end
	}
	r.TotalNativeImports = m.rows[28]
	r.NativeImportsTruncated = m.rows[28] > 50
	for i := 1; i <= m.rows[28]; i++ {
		v, _ := m.row(28, i)
		member := v[1] >> 1
		table := 4
		if v[1]&1 != 0 {
			table = 6
		}
		if member == 0 || int(member) > m.rows[table] {
			return r, errors.New("P/Invoke member reference outside table")
		}
		scope, err := m.row(26, int(v[3]))
		if err != nil {
			return r, err
		}
		module, err := m.text(scope[0])
		if err != nil {
			return r, err
		}
		entry, err := m.text(v[2])
		if err != nil {
			return r, err
		}
		if i <= 50 {
			r.NativeImports = append(r.NativeImports, ManagedImport{MemberToken: fmt.Sprintf("0x%08x", uint32(table)<<24|member), Module: module, EntryPoint: entry, Flags: v[0]})
		}
	}
	return r, projectionLimit(r)
}
func (m *metadata) methodBody(method ManagedMethod) ([]byte, int, error) {
	if method.RVA == 0 || method.ImplementationFlags&3 != 0 {
		return nil, 0, nil
	}
	head, err := m.rva(method.RVA, 1)
	if err != nil {
		return nil, 0, err
	}
	size, header := uint32(0), uint32(1)
	extra := false
	switch head[0] & 3 {
	case 2:
		size = uint32(head[0] >> 2)
	case 3:
		h, err := m.rva(method.RVA, 12)
		if err != nil {
			return nil, 0, err
		}
		header = uint32(u16(h[:2])>>12) * 4
		if header < 12 || header > 60 {
			return nil, 0, errors.New("invalid fat CIL header")
		}
		extra = u16(h[:2])&8 != 0
		size = u32(h[4:8])
		if token := u32(h[8:12]); token != 0 {
			if token>>24 != 17 || int(token&0xffffff) > m.rows[17] || token&0xffffff == 0 {
				return nil, 0, errors.New("invalid locals signature token")
			}
		}
	default:
		return nil, 0, errors.New("unsupported or malformed CIL method header")
	}
	if size > 1<<20 || uint64(method.RVA)+uint64(header)+uint64(size) > math.MaxUint32 {
		return nil, 0, errors.New("method CIL size exceeds limit")
	}
	all, err := m.rva(method.RVA, header+size)
	if err != nil {
		return nil, 0, err
	}
	clauses := 0
	if extra {
		offset := (uint64(method.RVA) + uint64(header) + uint64(size) + 3) &^ 3
		for sections := 0; ; sections++ {
			if sections >= 64 || offset > math.MaxUint32 {
				return nil, 0, errors.New("CIL section limit exceeded")
			}
			h, err := m.rva(uint32(offset), 4)
			if err != nil {
				return nil, 0, err
			}
			fat := h[0]&0x40 != 0
			n := uint32(h[1])
			clauseSize := uint32(12)
			if fat {
				n = uint32(h[1]) | uint32(h[2])<<8 | uint32(h[3])<<16
				clauseSize = 24
			}
			if h[0]&0x3f != 1 || n < 4 || (n-4)%clauseSize != 0 || n > 1<<20 {
				return nil, 0, errors.New("invalid/unsupported CIL exception section")
			}
			if _, err = m.rva(uint32(offset), n); err != nil {
				return nil, 0, err
			}
			clauses += int((n - 4) / clauseSize)
			if h[0]&0x80 == 0 {
				break
			}
			offset = (offset + uint64(n) + 3) &^ 3
		}
	}
	return all[header:], clauses, nil
}
