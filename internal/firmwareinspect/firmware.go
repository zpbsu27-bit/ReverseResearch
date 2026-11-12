package firmwareinspect

import (
	"context"
	"errors"
	"os"

	"reverseresearch/internal/targetidentity"
)

type Report struct {
	Source           targetidentity.Identity `json:"source"`
	Format           string                  `json:"format"`
	RecommendedTools []string                `json:"recommended_tools"`
	ReadOnly         bool                    `json:"read_only"`
}

func Inspect(path string) (Report, error) {
	return InspectContext(context.Background(), path)
}

func InspectContext(ctx context.Context, path string) (Report, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	src, err := targetidentity.InspectContext(ctx, path)
	if err != nil {
		return Report{}, err
	}
	f, err := os.Open(src.Path)
	if err != nil {
		return Report{}, err
	}
	defer f.Close()
	buf := make([]byte, 4096)
	n, _ := f.Read(buf)
	buf = buf[:n]
	format := "unknown"
	tools := []string{"binwalk"}
	switch {
	case len(buf) >= 4 && string(buf[:4]) == "hsqs":
		format = "squashfs"
		tools = []string{"binwalk", "unsquashfs", "emba"}
	case len(buf) >= 4 && buf[0] == 0x27 && buf[1] == 0x05 && buf[2] == 0x19 && buf[3] == 0x56:
		format = "u-boot-uimage"
		tools = []string{"binwalk", "qemu"}
	case len(buf) >= 2 && buf[0] == 0x1f && buf[1] == 0x8b:
		format = "gzip"
		tools = []string{"binwalk"}
	case len(buf) >= 6 && buf[0] == 0xfd && buf[1] == 0x37 && buf[2] == 0x7a && buf[3] == 0x58 && buf[4] == 0x5a && buf[5] == 0x00:
		format = "xz"
		tools = []string{"binwalk"}
	case len(buf) >= 4 && buf[0] == 'P' && buf[1] == 'K' && buf[2] == 3 && buf[3] == 4:
		format = "zip"
		tools = []string{"binwalk"}
	case len(buf) >= 262 && string(buf[257:262]) == "ustar":
		format = "tar"
		tools = []string{"binwalk"}
	}
	after, err := targetidentity.InspectContext(ctx, src.Path)
	if err != nil {
		return Report{}, err
	}
	if after.ID != src.ID || after.Size != src.Size || after.ModifiedUTC != src.ModifiedUTC {
		return Report{}, errors.New("firmware changed during inspection")
	}
	return Report{Source: src, Format: format, RecommendedTools: tools, ReadOnly: true}, nil
}
