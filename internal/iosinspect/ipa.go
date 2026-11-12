package iosinspect

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"reverseresearch/internal/targetidentity"
)

const MaxEntries = 20000
const MaxProbeBytes int64 = 1 << 20

type MachOCandidate struct {
	Path  string `json:"path"`
	Magic string `json:"magic"`
	Size  uint64 `json:"size"`
}
type Report struct {
	Source     targetidentity.Identity `json:"source"`
	AppRoots   []string                `json:"app_roots"`
	InfoPlists []string                `json:"info_plists"`
	MachO      []MachOCandidate        `json:"macho_candidates"`
	Frameworks []string                `json:"frameworks,omitempty"`
	ReadOnly   bool                    `json:"read_only"`
}

func InspectIPA(path string) (Report, error) {
	return InspectIPAContext(context.Background(), path)
}

func InspectIPAContext(ctx context.Context, path string) (Report, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	src, err := targetidentity.InspectContext(ctx, path)
	if err != nil {
		return Report{}, err
	}
	z, err := zip.OpenReader(src.Path)
	if err != nil {
		return Report{}, fmt.Errorf("open IPA zip: %w", err)
	}
	defer z.Close()
	if len(z.File) > MaxEntries {
		return Report{}, errors.New("IPA entry limit exceeded")
	}
	r := Report{Source: src, ReadOnly: true}
	roots := map[string]bool{}
	for _, f := range z.File {
		if err := ctx.Err(); err != nil {
			return Report{}, err
		}
		name := strings.ReplaceAll(f.Name, "\\", "/")
		if strings.HasPrefix(name, "Payload/") {
			parts := strings.Split(name, "/")
			if len(parts) >= 2 && strings.HasSuffix(parts[1], ".app") {
				roots["Payload/"+parts[1]] = true
			}
		}
		if strings.HasSuffix(name, "Info.plist") {
			r.InfoPlists = append(r.InfoPlists, name)
		}
		if strings.Contains(name, ".framework/") {
			r.Frameworks = append(r.Frameworks, name)
		}
		if f.FileInfo().IsDir() || f.UncompressedSize64 == 0 || f.UncompressedSize64 > uint64(MaxProbeBytes) {
			continue
		}
		rc, e := f.Open()
		if e != nil {
			continue
		}
		buf := make([]byte, 4)
		_, e = io.ReadFull(rc, buf)
		rc.Close()
		if e != nil {
			continue
		}
		if magic := machoMagic(buf); magic != "" {
			r.MachO = append(r.MachO, MachOCandidate{Path: name, Magic: magic, Size: f.UncompressedSize64})
		}
	}
	for root := range roots {
		r.AppRoots = append(r.AppRoots, root)
	}
	if len(r.AppRoots) == 0 {
		return Report{}, errors.New("IPA has no Payload/*.app root")
	}
	after, err := targetidentity.InspectContext(ctx, src.Path)
	if err != nil {
		return Report{}, err
	}
	if after.ID != src.ID || after.Size != src.Size || after.ModifiedUTC != src.ModifiedUTC {
		return Report{}, errors.New("IPA changed during inspection")
	}
	return r, nil
}
func machoMagic(b []byte) string {
	if len(b) < 4 {
		return ""
	}
	switch {
	case b[0] == 0xfe && b[1] == 0xed && b[2] == 0xfa && b[3] == 0xce:
		return "mach-o-32-be"
	case b[0] == 0xce && b[1] == 0xfa && b[2] == 0xed && b[3] == 0xfe:
		return "mach-o-32-le"
	case b[0] == 0xfe && b[1] == 0xed && b[2] == 0xfa && b[3] == 0xcf:
		return "mach-o-64-be"
	case b[0] == 0xcf && b[1] == 0xfa && b[2] == 0xed && b[3] == 0xfe:
		return "mach-o-64-le"
	case b[0] == 0xca && b[1] == 0xfe && b[2] == 0xba && b[3] == 0xbe:
		return "fat"
	case b[0] == 0xbe && b[1] == 0xba && b[2] == 0xfe && b[3] == 0xca:
		return "fat-swapped"
	default:
		return ""
	}
}
