package appinspect

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"errors"
	"io"
)

type ZIPEntry struct {
	Ordinal           int    `json:"ordinal"`
	Path              string `json:"path"`
	Kind              string `json:"kind"`
	CompressedBytes   uint64 `json:"compressed_bytes"`
	Size              uint64 `json:"size"`
	CRC32             uint32 `json:"crc32"`
	Method            uint16 `json:"method"`
	Available         bool   `json:"available"`
	UnavailableReason string `json:"unavailable_reason,omitempty"`
}

func parseZIP(body []byte) ([]*zip.File, []ZIPEntry, error) {
	f, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, nil, err
	}
	if len(f.File) > 100000 {
		return nil, nil, errors.New("ZIP entry inventory exceeds limit")
	}
	seen := map[string]bool{}
	entries := []ZIPEntry{}
	for i, e := range f.File {
		name, pathErr := safeArchivePath(e.Name)
		if pathErr != nil || seen[name] {
			return nil, nil, errors.New("ZIP entry path is unsafe or ambiguous")
		}
		seen[name] = true
		v := ZIPEntry{Ordinal: i, Path: e.Name, Kind: "file", Size: e.UncompressedSize64, CompressedBytes: e.CompressedSize64, CRC32: e.CRC32, Method: e.Method}
		switch {
		case e.FileInfo().IsDir():
			v.Kind = "directory"
			v.UnavailableReason = "directory has no admitted entry bytes"
		case !e.Mode().IsRegular():
			v.Kind = "link-or-special"
			v.UnavailableReason = "links and special files are not followed"
		case e.Flags&1 != 0:
			v.UnavailableReason = "encrypted entry is unsupported"
		case e.Method != zip.Store && e.Method != zip.Deflate:
			v.UnavailableReason = "compression method is unsupported"
		default:
			v.Available = true
		}
		offset, err := e.DataOffset()
		if err != nil {
			return nil, nil, err
		}
		if offset < 0 || uint64(offset) > uint64(len(body)) || e.CompressedSize64 > uint64(len(body))-uint64(offset) {
			return nil, nil, errors.New("ZIP compressed range outside artifact")
		}
		entries = append(entries, v)
	}
	return f.File, entries, nil
}

type ZIPReport struct {
	Path               string     `json:"path"`
	SHA256             string     `json:"sha256"`
	TotalEntries       int        `json:"total_entries"`
	Offset             int        `json:"offset"`
	Entries            []ZIPEntry `json:"entries"`
	NextOffset         *int       `json:"next_offset,omitempty"`
	CoverageComplete   bool       `json:"coverage_complete"`
	EvidenceAuthority  string     `json:"evidence_authority"`
	ExecutionPerformed bool       `json:"execution_performed"`
	Limitations        []string   `json:"limitations"`
}

func InspectZIP(p string, o PageOptions) (ZIPReport, error) {
	body, abs, hash, err := readArtifact(p, MaxArtifactBytes, o.ExpectedSHA256)
	if err != nil {
		return ZIPReport{}, err
	}
	_, entries, err := parseZIP(body)
	if err != nil {
		return ZIPReport{}, err
	}
	start, end, err := page(o, len(entries))
	if err != nil {
		return ZIPReport{}, err
	}
	r := ZIPReport{Path: abs, SHA256: hash, TotalEntries: len(entries), Offset: start, Entries: entries[start:end], CoverageComplete: start == 0 && end == len(entries), EvidenceAuthority: "zip-directory-declarations", Limitations: []string{"inventory validates paths and compressed ranges, not every entry's decompression/CRC", "no extraction, APK/IPA signature verification or target execution"}}
	if end < len(entries) {
		r.NextOffset = &end
	}
	return r, projectionLimit(r)
}

type ZIPReadReport struct {
	Path               string   `json:"path"`
	SHA256             string   `json:"sha256"`
	Entry              ZIPEntry `json:"entry"`
	ContentSHA256      string   `json:"content_sha256,omitempty"`
	CRCVerified        bool     `json:"crc_verified"`
	Offset             int      `json:"offset"`
	ReadBytes          int      `json:"read_bytes"`
	DataBase64         string   `json:"data_base64"`
	NextOffset         *int     `json:"next_offset,omitempty"`
	CoverageComplete   bool     `json:"coverage_complete"`
	ExecutionPerformed bool     `json:"execution_performed"`
}

// readZIPContent is the only selected-member decompression/CRC path shared by
// byte reads and package projections. Admission is fixed by parseZIP first.
func readZIPContent(file *zip.File, e ZIPEntry, limit int) ([]byte, error) {
	if !e.Available {
		return nil, errors.New("ZIP entry is unavailable")
	}
	if e.Size > uint64(limit) {
		return nil, errors.New("selected ZIP entry exceeds decompression limit")
	}
	r, err := file.Open()
	if err != nil {
		return nil, err
	}
	content, readErr := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	closeErr := r.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return nil, err
	}
	if len(content) > limit || uint64(len(content)) != e.Size {
		return nil, errors.New("ZIP entry size differs from declared size or exceeds limit")
	}
	return content, nil
}

func ReadZIP(p string, o EntryReadOptions) (ZIPReadReport, error) {
	if o.Limit == 0 {
		o.Limit = 8192
	}
	if o.Offset < 0 || o.Limit < 1 || o.Limit > 16384 {
		return ZIPReadReport{}, errors.New("offset must be nonnegative; limit must be 1..16384 bytes")
	}
	body, abs, hash, err := readArtifact(p, MaxArtifactBytes, o.ExpectedSHA256)
	if err != nil {
		return ZIPReadReport{}, err
	}
	files, entries, err := parseZIP(body)
	if err != nil {
		return ZIPReadReport{}, err
	}
	for i, e := range entries {
		if e.Path != o.Entry {
			continue
		}
		r := ZIPReadReport{Path: abs, SHA256: hash, Entry: e, Offset: o.Offset}
		if !e.Available {
			if o.Offset != 0 {
				return r, errors.New("unavailable entry requires zero offset")
			}
			return r, nil
		}
		if e.Size > 16<<20 {
			return r, errors.New("selected ZIP entry exceeds 16 MiB decompression limit")
		}
		content, err := readZIPContent(files[i], e, 16<<20)
		if err != nil {
			return r, err
		}
		if o.Offset > len(content) {
			return r, errors.New("offset outside ZIP entry")
		}
		end := min(len(content), o.Offset+o.Limit)
		r.CRCVerified = true
		r.ContentSHA256 = digest(content)
		r.ReadBytes = end - o.Offset
		r.DataBase64 = base64.StdEncoding.EncodeToString(content[o.Offset:end])
		r.CoverageComplete = o.Offset == 0 && end == len(content)
		if end < len(content) {
			r.NextOffset = &end
		}
		return r, projectionLimit(r)
	}
	return ZIPReadReport{}, errors.New("entry not found in ZIP inventory")
}
