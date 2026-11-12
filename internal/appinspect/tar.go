package appinspect

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"io"
	"strings"
)

type TAREntry struct {
	Ordinal           int    `json:"ordinal"`
	Path              string `json:"path"`
	Kind              string `json:"kind"`
	Size              int64  `json:"size"`
	DataOffset        int    `json:"data_offset"`
	LinkName          string `json:"link_name,omitempty"`
	Available         bool   `json:"available"`
	UnavailableReason string `json:"unavailable_reason,omitempty"`
}

func parseTAR(body []byte) ([]byte, string, []TAREntry, error) {
	plain, carrier := body, "tar"
	if len(body) >= 2 && body[0] == 0x1f && body[1] == 0x8b {
		z, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, "", nil, err
		}
		var readErr error
		plain, readErr = io.ReadAll(io.LimitReader(z, MaxArtifactBytes+1))
		if err := errors.Join(readErr, z.Close()); err != nil {
			return nil, "", nil, err
		}
		if len(plain) > MaxArtifactBytes {
			return nil, "", nil, errors.New("gzip TAR exceeds 128 MiB decoded limit")
		}
		carrier = "gzip-tar"
	}
	if len(plain) < 1024 || len(plain)%512 != 0 {
		return nil, "", nil, errors.New("TAR requires complete 512-byte records and end markers")
	}
	raw := bytes.NewReader(plain)
	r := tar.NewReader(raw)
	seen := map[string]bool{}
	entries := []TAREntry{}
	var totalSize int64
	for {
		before := raw.Len()
		h, err := r.Next()
		if err == io.EOF {
			if before-raw.Len() < 1024 {
				return nil, "", nil, errors.New("TAR is missing two end-marker records")
			}
			if !allZero(plain[len(plain)-raw.Len():]) {
				return nil, "", nil, errors.New("TAR has nonzero trailing data")
			}
			break
		}
		if err != nil {
			return nil, "", nil, err
		}
		if len(entries) >= 100000 {
			return nil, "", nil, errors.New("TAR entry inventory exceeds limit")
		}
		name, err := safeArchivePath(h.Name)
		if err != nil || seen[name] {
			return nil, "", nil, errors.New("TAR entry path is unsafe or ambiguous")
		}
		seen[name] = true
		if h.Size < 0 || h.Size > int64(len(plain)) {
			return nil, "", nil, errors.New("TAR member size outside bounded artifact")
		}
		totalSize += h.Size
		if totalSize > MaxArtifactBytes {
			return nil, "", nil, errors.New("TAR aggregate member size exceeds 128 MiB")
		}
		e := TAREntry{Ordinal: len(entries), Path: h.Name, Size: h.Size, DataOffset: len(plain) - raw.Len(), LinkName: h.Linkname}
		switch h.Typeflag {
		case tar.TypeReg, tar.TypeRegA:
			e.Kind = "file"
			e.Available = true
		case tar.TypeDir:
			e.Kind = "directory"
			e.UnavailableReason = "directory has no admitted entry bytes"
		case tar.TypeLink, tar.TypeSymlink:
			e.Kind = "link"
			e.UnavailableReason = "links are not followed"
		case tar.TypeGNUSparse:
			e.Kind = "sparse"
			e.UnavailableReason = "sparse entry reconstruction is unsupported"
		default:
			e.Kind = "special"
			e.UnavailableReason = "special files are not read"
		}
		for key := range h.PAXRecords {
			if strings.HasPrefix(key, "GNU.sparse.") || key == "SCHILY.realsize" {
				e.Kind = "sparse"
				e.Available = false
				e.UnavailableReason = "sparse entry reconstruction is unsupported"
			}
		}
		// Consume through the standard reader, including its padding/size checks.
		// Sparse expansion is never materialized and is bounded by h.Size above.
		n, err := io.Copy(io.Discard, r)
		if err != nil || n != h.Size {
			return nil, "", nil, errors.New("TAR member data is truncated or inconsistent")
		}
		if e.Available && (e.DataOffset > len(plain) || h.Size > int64(len(plain)-e.DataOffset)) {
			return nil, "", nil, errors.New("TAR data range outside snapshot")
		}
		entries = append(entries, e)
	}
	return plain, carrier, entries, nil
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

type TARReport struct {
	Path               string     `json:"path"`
	SHA256             string     `json:"sha256"`
	Carrier            string     `json:"carrier"`
	DecodedSHA256      string     `json:"decoded_sha256"`
	TotalEntries       int        `json:"total_entries"`
	Offset             int        `json:"offset"`
	Entries            []TAREntry `json:"entries"`
	NextOffset         *int       `json:"next_offset,omitempty"`
	CoverageComplete   bool       `json:"coverage_complete"`
	ExecutionPerformed bool       `json:"execution_performed"`
	Limitations        []string   `json:"limitations"`
}

func InspectTAR(p string, o PageOptions) (TARReport, error) {
	body, abs, hash, err := readArtifact(p, MaxArtifactBytes, o.ExpectedSHA256)
	if err != nil {
		return TARReport{}, err
	}
	plain, carrier, entries, err := parseTAR(body)
	if err != nil {
		return TARReport{}, err
	}
	start, end, err := page(o, len(entries))
	if err != nil {
		return TARReport{}, err
	}
	r := TARReport{Path: abs, SHA256: hash, Carrier: carrier, DecodedSHA256: digest(plain), TotalEntries: len(entries), Offset: start, Entries: entries[start:end], CoverageComplete: start == 0 && end == len(entries), Limitations: []string{"data offsets refer to the decoded TAR, not gzip carrier bytes", "headers and gzip CRC are checked; TAR has no per-member content checksum", "no extraction, link resolution, sparse reconstruction or target execution"}}
	if end < len(entries) {
		r.NextOffset = &end
	}
	return r, projectionLimit(r)
}

type TARReadReport struct {
	Path               string   `json:"path"`
	SHA256             string   `json:"sha256"`
	Carrier            string   `json:"carrier"`
	Entry              TAREntry `json:"entry"`
	ContentSHA256      string   `json:"content_sha256,omitempty"`
	Offset             int      `json:"offset"`
	ReadBytes          int      `json:"read_bytes"`
	DataBase64         string   `json:"data_base64"`
	NextOffset         *int     `json:"next_offset,omitempty"`
	CoverageComplete   bool     `json:"coverage_complete"`
	ExecutionPerformed bool     `json:"execution_performed"`
}

func ReadTAR(p string, o EntryReadOptions) (TARReadReport, error) {
	if o.Limit == 0 {
		o.Limit = 8192
	}
	if o.Offset < 0 || o.Limit < 1 || o.Limit > 16384 {
		return TARReadReport{}, errors.New("offset must be nonnegative; limit must be 1..16384 bytes")
	}
	body, abs, hash, err := readArtifact(p, MaxArtifactBytes, o.ExpectedSHA256)
	if err != nil {
		return TARReadReport{}, err
	}
	plain, carrier, entries, err := parseTAR(body)
	if err != nil {
		return TARReadReport{}, err
	}
	for _, e := range entries {
		if e.Path != o.Entry {
			continue
		}
		r := TARReadReport{Path: abs, SHA256: hash, Carrier: carrier, Entry: e, Offset: o.Offset}
		if !e.Available {
			if o.Offset != 0 {
				return r, errors.New("unavailable entry requires zero offset")
			}
			return r, nil
		}
		content := plain[e.DataOffset : e.DataOffset+int(e.Size)]
		if o.Offset > len(content) {
			return r, errors.New("offset outside TAR entry")
		}
		end := min(len(content), o.Offset+o.Limit)
		r.ContentSHA256 = digest(content)
		r.ReadBytes = end - o.Offset
		r.DataBase64 = base64.StdEncoding.EncodeToString(content[o.Offset:end])
		r.CoverageComplete = o.Offset == 0 && end == len(content)
		if end < len(content) {
			r.NextOffset = &end
		}
		return r, projectionLimit(r)
	}
	return TARReadReport{}, errors.New("entry not found in TAR inventory")
}
