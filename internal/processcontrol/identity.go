package processcontrol

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"reverseresearch/internal/targetidentity"
)

var (
	ErrProcessChanged = errors.New("process identity changed")
	ErrControlled     = errors.New("process is controlled by another owner")
	ErrLeaseNotFound  = errors.New("process control lease not found")
	ErrLeaseChanged   = errors.New("process control lease changed")
	ErrUnsupported    = errors.New("process identity inspection is unsupported on this platform")
)

type Identity struct {
	PID              uint32                  `json:"pid"`
	CreationUTC      string                  `json:"creation_utc"`
	CreationUnixNano int64                   `json:"creation_unix_nano"`
	MainModuleBase   uint64                  `json:"main_module_base"`
	Image            targetidentity.Identity `json:"image"`
	Key              string                  `json:"key"`
}

func Validate(expected Identity) (Identity, error) {
	if expected.PID == 0 || strings.TrimSpace(expected.Key) == "" {
		return Identity{}, errors.New("expected process identity requires pid and key")
	}
	current, err := Inspect(expected.PID)
	if err != nil {
		return Identity{}, fmt.Errorf("%w: %v", ErrProcessChanged, err)
	}
	if !SameInstance(expected, current) {
		return current, fmt.Errorf("%w: expected %s current %s", ErrProcessChanged, expected.Key, current.Key)
	}
	return current, nil
}

func SameInstance(left, right Identity) bool {
	return left.PID != 0 &&
		left.PID == right.PID &&
		left.Key != "" &&
		left.Key == right.Key &&
		left.CreationUnixNano == right.CreationUnixNano &&
		left.MainModuleBase == right.MainModuleBase &&
		left.Image.SHA256 != "" &&
		left.Image.SHA256 == right.Image.SHA256
}

func buildIdentityKey(pid uint32, creation int64, moduleBase uint64, imageSHA string) string {
	hash := sha256.New()
	var number [8]byte
	binary.LittleEndian.PutUint32(number[:4], pid)
	_, _ = hash.Write(number[:4])
	binary.LittleEndian.PutUint64(number[:], uint64(creation))
	_, _ = hash.Write(number[:])
	binary.LittleEndian.PutUint64(number[:], moduleBase)
	_, _ = hash.Write(number[:])
	_, _ = hash.Write([]byte(strings.ToLower(imageSHA)))
	return hex.EncodeToString(hash.Sum(nil))
}
