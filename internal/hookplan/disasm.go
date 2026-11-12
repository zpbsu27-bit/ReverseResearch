package hookplan

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"reverseresearch/internal/targetidentity"
	"reverseresearch/internal/toolindex"
)

const (
	r2Timeout     = 20 * time.Second
	r2OutputLimit = 4 << 20
)

type r2Function struct {
	Addr    uint64 `json:"addr"`
	MinAddr uint64 `json:"minaddr"`
	MaxAddr uint64 `json:"maxaddr"`
	Size    int    `json:"size"`
	Bits    int    `json:"bits"`
	Name    string `json:"name"`
}

type r2Instruction struct {
	Addr   uint64 `json:"addr"`
	Size   int    `json:"size"`
	Bytes  string `json:"bytes"`
	Opcode string `json:"opcode"`
	Disasm string `json:"disasm"`
	Type   string `json:"type"`
}

func (m *Manager) proveInstructionBoundary(ctx context.Context, identity targetidentity.Identity, sourceRVA uint64, minimumBytes int) ([]Instruction, int, error) {
	if identity.PE == nil {
		return nil, 0, errors.New("hook boundary proof requires a PE target")
	}
	if minimumBytes < 1 || minimumBytes > MaxHookOverwriteBytes {
		return nil, 0, fmt.Errorf("invalid minimum overwrite size %d", minimumBytes)
	}
	if sourceRVA > ^uint64(0)-identity.PE.ImageBase {
		return nil, 0, errors.New("source address overflows image base")
	}
	sourceVA := identity.PE.ImageBase + sourceRVA

	r2Path, err := m.radare2Path()
	if err != nil {
		return nil, 0, err
	}
	functionJSON, err := runR2JSON(ctx, r2Path, identity.Path, fmt.Sprintf("aa; afij @ 0x%X", sourceVA))
	if err != nil {
		return nil, 0, err
	}
	var functions []r2Function
	if err := json.Unmarshal(functionJSON, &functions); err != nil {
		return nil, 0, fmt.Errorf("decode radare2 function boundary: %w", err)
	}
	var function r2Function
	found := false
	for _, candidate := range functions {
		start := candidate.MinAddr
		if start == 0 {
			start = candidate.Addr
		}
		end := candidate.MaxAddr
		if end == 0 && candidate.Size > 0 && start <= ^uint64(0)-uint64(candidate.Size) {
			end = start + uint64(candidate.Size)
		}
		if start <= sourceVA && sourceVA < end {
			candidate.MinAddr = start
			candidate.MaxAddr = end
			function = candidate
			found = true
			break
		}
	}
	if !found {
		return nil, 0, fmt.Errorf("source RVA 0x%X is not inside a radare2-analyzed function", sourceRVA)
	}
	if sourceVA < function.MinAddr {
		return nil, 0, errors.New("invalid function boundary")
	}
	distance := sourceVA - function.MinAddr
	if distance > MaxBoundaryProofBytes {
		return nil, 0, fmt.Errorf("source is %d bytes from function start; boundary proof limit is %d", distance, MaxBoundaryProofBytes)
	}
	requestBytes := distance + MaxHookOverwriteBytes
	if requestBytes < uint64(minimumBytes) {
		requestBytes = uint64(minimumBytes)
	}
	instructionJSON, err := runR2JSON(ctx, r2Path, identity.Path, fmt.Sprintf("aa; pDj %d @ 0x%X", requestBytes, function.MinAddr))
	if err != nil {
		return nil, 0, err
	}
	var decoded []r2Instruction
	if err := json.Unmarshal(instructionJSON, &decoded); err != nil {
		return nil, 0, fmt.Errorf("decode radare2 instruction stream: %w", err)
	}
	if len(decoded) == 0 {
		return nil, 0, errors.New("radare2 returned no instructions for boundary proof")
	}

	cursor := function.MinAddr
	started := false
	total := 0
	proof := make([]Instruction, 0, 8)
	for _, item := range decoded {
		if item.Addr != cursor {
			if !started && item.Addr > sourceVA {
				return nil, 0, fmt.Errorf("source RVA 0x%X falls inside an instruction", sourceRVA)
			}
			return nil, 0, fmt.Errorf("non-contiguous instruction stream at 0x%X: got 0x%X", cursor, item.Addr)
		}
		if item.Size <= 0 || item.Size > 15 {
			return nil, 0, fmt.Errorf("invalid instruction size %d at 0x%X", item.Size, item.Addr)
		}
		raw, err := hex.DecodeString(strings.TrimSpace(item.Bytes))
		if err != nil || len(raw) != item.Size {
			return nil, 0, fmt.Errorf("instruction bytes/size mismatch at 0x%X", item.Addr)
		}
		if item.Addr == sourceVA {
			started = true
		} else if !started && item.Addr > sourceVA {
			return nil, 0, fmt.Errorf("source RVA 0x%X falls inside an instruction", sourceRVA)
		}
		if started {
			opcode := strings.ToLower(strings.TrimSpace(item.Opcode))
			disasm := strings.ToLower(strings.TrimSpace(item.Disasm))
			if strings.EqualFold(item.Type, "ill") || strings.HasPrefix(opcode, "invalid") || strings.HasPrefix(disasm, "invalid") {
				return nil, 0, fmt.Errorf("invalid instruction at source span address 0x%X", item.Addr)
			}
			rva := item.Addr - identity.PE.ImageBase
			proof = append(proof, Instruction{
				Address:  item.Addr,
				RVA:      rva,
				Size:     item.Size,
				BytesHex: strings.ToUpper(item.Bytes),
				Opcode:   item.Opcode,
				Type:     item.Type,
			})
			total += item.Size
			if total > MaxHookOverwriteBytes {
				return nil, 0, fmt.Errorf("hook overwrite needs more than %d bytes of whole instructions", MaxHookOverwriteBytes)
			}
			if total >= minimumBytes {
				return proof, total, nil
			}
		}
		if item.Addr > ^uint64(0)-uint64(item.Size) {
			return nil, 0, errors.New("instruction address overflow")
		}
		cursor = item.Addr + uint64(item.Size)
	}
	if !started {
		return nil, 0, fmt.Errorf("source RVA 0x%X is not an instruction boundary", sourceRVA)
	}
	return nil, 0, fmt.Errorf("insufficient complete instructions at source RVA 0x%X", sourceRVA)
}

func (m *Manager) radare2Path() (string, error) {
	index, err := toolindex.Scan(m.root)
	if err != nil {
		return "", err
	}
	tool, ok := index.ByName("radare2")
	if !ok || !tool.Available || strings.TrimSpace(tool.Path) == "" {
		return "", errors.New("bundled radare2 runtime is unavailable")
	}
	return filepath.Clean(tool.Path), nil
}

func runR2JSON(parent context.Context, executable, target, command string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, r2Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, executable,
		"-q",
		"-e", "scr.color=false",
		"-e", "bin.relocs.apply=true",
		"-c", command,
		target,
	)
	cmd.Dir = filepath.Dir(executable)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &limitedBuffer{buffer: &stdout, limit: r2OutputLimit}
	cmd.Stderr = &limitedBuffer{buffer: &stderr, limit: 256 << 10}
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("radare2 boundary proof timed out: %w", ctx.Err())
		}
		return nil, fmt.Errorf("radare2 boundary proof failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	body := bytes.TrimSpace(stdout.Bytes())
	if len(body) == 0 {
		return nil, errors.New("radare2 boundary proof returned empty output")
	}
	if len(body) > r2OutputLimit {
		return nil, errors.New("radare2 boundary proof output exceeded limit")
	}
	return append([]byte(nil), body...), nil
}

type limitedBuffer struct {
	buffer *bytes.Buffer
	limit  int
}

func (w *limitedBuffer) Write(p []byte) (int, error) {
	if w.buffer.Len()+len(p) > w.limit {
		remaining := w.limit - w.buffer.Len()
		if remaining > 0 {
			_, _ = w.buffer.Write(p[:remaining])
		}
		return len(p), errors.New("output limit exceeded")
	}
	return w.buffer.Write(p)
}
