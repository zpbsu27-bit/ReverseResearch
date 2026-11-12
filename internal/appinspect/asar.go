package appinspect

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"reverseresearch/internal/recordio"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

const MaxASARHeaderBytes = 2 << 20

type asarNode struct {
	Files     map[string]asarNode `json:"files"`
	Size      *int64              `json:"size"`
	Offset    *string             `json:"offset"`
	Unpacked  bool                `json:"unpacked"`
	Link      *string             `json:"link"`
	Integrity *struct {
		Algorithm string   `json:"algorithm"`
		Hash      string   `json:"hash"`
		BlockSize int64    `json:"blockSize"`
		Blocks    []string `json:"blocks"`
	} `json:"integrity"`
}
type ASAREntry struct {
	Path              string `json:"path"`
	Kind              string `json:"kind"`
	Size              int64  `json:"size"`
	Available         bool   `json:"available"`
	UnavailableReason string `json:"unavailable_reason,omitempty"`
	ByteOffset        int64  `json:"byte_offset,omitempty"`
	IntegrityState    string `json:"integrity_state"`
}

func parseASAR(body []byte) ([]ASAREntry, error) {
	if len(body) < 16 || binary.LittleEndian.Uint32(body[:4]) != 4 {
		return nil, errors.New("invalid ASAR size pickle")
	}
	headerSize := int64(binary.LittleEndian.Uint32(body[4:8]))
	payloadSize := int64(binary.LittleEndian.Uint32(body[8:12]))
	jsonSize := int64(binary.LittleEndian.Uint32(body[12:16]))
	if headerSize < 8 || headerSize%4 != 0 || headerSize > MaxASARHeaderBytes || headerSize > int64(len(body))-8 || payloadSize != headerSize-4 || jsonSize > headerSize-8 {
		return nil, errors.New("ASAR header size is invalid or exceeds limit")
	}
	var root asarNode
	if err := recordio.DecodeJSON(body[16:16+jsonSize], &root); err != nil {
		return nil, fmt.Errorf("ASAR header: %w", err)
	}
	if root.Files == nil || root.Link != nil || root.Size != nil || root.Offset != nil || root.Integrity != nil {
		return nil, errors.New("ASAR root requires files object without file/link data")
	}
	dataStart := 8 + headerSize
	var entries []ASAREntry
	var walk func(asarNode, string, int) error
	walk = func(n asarNode, prefix string, depth int) error {
		if depth > 64 {
			return errors.New("ASAR directory depth exceeds 64")
		}
		names := make([]string, 0, len(n.Files))
		for name := range n.Files {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if name == "" || name == "." || name == ".." || len(name) > 1024 || strings.ContainsAny(name, "/\\:") || strings.IndexFunc(name, unicode.IsControl) >= 0 {
				return errors.New("ASAR entry has ambiguous or unsafe name")
			}
			path := name
			if prefix != "" {
				path = prefix + "/" + name
			}
			if len(path) > 4096 || len(entries) >= 100000 {
				return errors.New("ASAR inventory exceeds path/count limit")
			}
			v := n.Files[name]
			e := ASAREntry{Path: path, Kind: "file", IntegrityState: "not-declared"}
			if v.Files != nil {
				if v.Link != nil || v.Size != nil || v.Offset != nil || v.Unpacked || v.Integrity != nil {
					return errors.New("ASAR directory also declares file/link data")
				}
				e.Kind = "directory"
				entries = append(entries, e)
				if err := walk(v, path, depth+1); err != nil {
					return err
				}
				continue
			}
			if v.Link != nil {
				if v.Size != nil || v.Offset != nil || v.Unpacked {
					return errors.New("ASAR link also declares file data")
				}
				e.Kind = "link"
				e.UnavailableReason = "link targets are not followed"
			} else {
				if v.Size == nil || *v.Size < 0 {
					return errors.New("ASAR file requires nonnegative size")
				}
				e.Size = *v.Size
				if v.Unpacked {
					if v.Offset != nil {
						return errors.New("unpacked ASAR entry also declares packed offset")
					}
					e.Kind = "unpacked"
					e.UnavailableReason = "external unpacked files are not read"
				} else {
					if v.Offset == nil || *v.Offset == "" || strings.IndexFunc(*v.Offset, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
						return errors.New("ASAR packed entry requires decimal offset")
					}
					offset, err := strconv.ParseUint(*v.Offset, 10, 63)
					if err != nil || int64(offset) > int64(len(body))-dataStart || e.Size > int64(len(body))-dataStart-int64(offset) {
						return errors.New("ASAR entry lies outside archive bytes")
					}
					e.ByteOffset = dataStart + int64(offset)
					e.Available = true
				}
			}
			if v.Integrity != nil {
				e.IntegrityState = "unavailable"
				if e.Available {
					integrity := v.Integrity
					decoded, err := hex.DecodeString(integrity.Hash)
					if integrity.Algorithm != "SHA256" || err != nil || len(decoded) != 32 {
						return errors.New("unsupported or malformed ASAR integrity declaration")
					}
					content := body[e.ByteOffset : e.ByteOffset+e.Size]
					if !strings.EqualFold(digest(content), integrity.Hash) {
						return errors.New("ASAR declared integrity hash differs from admitted bytes")
					}
					if integrity.Blocks != nil {
						if integrity.BlockSize < 1 || integrity.BlockSize > 16<<20 || len(integrity.Blocks) > 100000 {
							return errors.New("invalid ASAR integrity block size/count")
						}
						count := max(int64(1), (e.Size+integrity.BlockSize-1)/integrity.BlockSize)
						if int64(len(integrity.Blocks)) != count {
							return errors.New("ASAR integrity block count differs from file size")
						}
						for i, wanted := range integrity.Blocks {
							start := int64(i) * integrity.BlockSize
							end := min(e.Size, start+integrity.BlockSize)
							if !strings.EqualFold(digest(content[start:end]), wanted) {
								return errors.New("ASAR integrity block hash differs from bytes")
							}
						}
					}
					e.IntegrityState = "declared-sha256-verified"
				}
			}
			entries = append(entries, e)
		}
		return nil
	}
	if err := walk(root, "", 0); err != nil {
		return nil, err
	}
	var ranges []ASAREntry
	for _, e := range entries {
		if e.Available && e.Size > 0 {
			ranges = append(ranges, e)
		}
	}
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].ByteOffset < ranges[j].ByteOffset })
	for i := 1; i < len(ranges); i++ {
		if ranges[i].ByteOffset < ranges[i-1].ByteOffset+ranges[i-1].Size {
			return nil, errors.New("ASAR packed entry ranges overlap")
		}
	}
	return entries, nil
}

type ASARReport struct {
	Path               string      `json:"path"`
	SHA256             string      `json:"sha256"`
	TotalEntries       int         `json:"total_entries"`
	Offset             int         `json:"offset"`
	Entries            []ASAREntry `json:"entries"`
	NextOffset         *int        `json:"next_offset,omitempty"`
	CoverageComplete   bool        `json:"coverage_complete"`
	EvidenceAuthority  string      `json:"evidence_authority"`
	ExecutionPerformed bool        `json:"execution_performed"`
	NetworkInteraction bool        `json:"network_interaction"`
}

func InspectASAR(path string, o PageOptions) (ASARReport, error) {
	body, abs, hash, err := readArtifact(path, MaxArtifactBytes, o.ExpectedSHA256)
	if err != nil {
		return ASARReport{}, err
	}
	entries, err := parseASAR(body)
	if err != nil {
		return ASARReport{}, err
	}
	start, end, err := page(o, len(entries))
	if err != nil {
		return ASARReport{}, err
	}
	r := ASARReport{Path: abs, SHA256: hash, TotalEntries: len(entries), Offset: start, Entries: entries[start:end], CoverageComplete: start == 0 && end == len(entries), EvidenceAuthority: "artifact-bytes"}
	if end < len(entries) {
		r.NextOffset = &end
	}
	return r, projectionLimit(r)
}

type EntryReadOptions struct {
	Entry          string `json:"entry"`
	Offset         int    `json:"offset"`
	Limit          int    `json:"limit"`
	ExpectedSHA256 string `json:"expected_sha256,omitempty"`
}
type ASARReadReport struct {
	Path               string    `json:"path"`
	SHA256             string    `json:"sha256"`
	Entry              ASAREntry `json:"entry"`
	ContentSHA256      string    `json:"content_sha256,omitempty"`
	Offset             int       `json:"offset"`
	ReadBytes          int       `json:"read_bytes"`
	DataBase64         string    `json:"data_base64"`
	NextOffset         *int      `json:"next_offset,omitempty"`
	CoverageComplete   bool      `json:"coverage_complete"`
	ExecutionPerformed bool      `json:"execution_performed"`
	NetworkInteraction bool      `json:"network_interaction"`
}

func selectASAREntry(body []byte, name string) (ASAREntry, []byte, error) {
	entries, err := parseASAR(body)
	if err != nil {
		return ASAREntry{}, nil, err
	}
	for _, e := range entries {
		if e.Path == name {
			if !e.Available {
				return e, nil, nil
			}
			return e, body[e.ByteOffset : e.ByteOffset+e.Size], nil
		}
	}
	return ASAREntry{}, nil, errors.New("entry not found in ASAR inventory")
}
func ReadASAR(path string, o EntryReadOptions) (ASARReadReport, error) {
	if o.Limit == 0 {
		o.Limit = 8192
	}
	if o.Offset < 0 || o.Limit < 1 || o.Limit > 16384 {
		return ASARReadReport{}, errors.New("offset must be nonnegative; limit must be 1..16384 bytes")
	}
	body, abs, hash, err := readArtifact(path, MaxArtifactBytes, o.ExpectedSHA256)
	if err != nil {
		return ASARReadReport{}, err
	}
	e, content, err := selectASAREntry(body, o.Entry)
	if err != nil {
		return ASARReadReport{}, err
	}
	r := ASARReadReport{Path: abs, SHA256: hash, Entry: e, Offset: o.Offset}
	if !e.Available {
		if o.Offset != 0 {
			return r, errors.New("offset must be zero for unavailable entry")
		}
		return r, nil
	}
	if o.Offset > len(content) {
		return r, errors.New("offset outside ASAR entry")
	}
	end := min(len(content), o.Offset+o.Limit)
	r.ContentSHA256 = digest(content)
	r.DataBase64 = base64.StdEncoding.EncodeToString(content[o.Offset:end])
	r.ReadBytes = end - o.Offset
	r.CoverageComplete = o.Offset == 0 && end == len(content)
	if end < len(content) {
		r.NextOffset = &end
	}
	return r, nil
}
