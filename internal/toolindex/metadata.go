package toolindex

import (
	"crypto/sha256"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"reverseresearch/internal/recordio"
)

type Metadata struct {
	Tool            string   `json:"tool"`
	Version         string   `json:"version,omitempty"`
	Provider        string   `json:"provider,omitempty"`
	CanonicalSource string   `json:"canonical_source,omitempty"`
	License         string   `json:"license,omitempty"`
	InstallScope    string   `json:"install_scope,omitempty"`
	TrustStatus     string   `json:"trust_status,omitempty"`
	Capabilities    []string `json:"capabilities,omitempty"`
	RequiresAdmin   bool     `json:"requires_admin,omitempty"`
	RequiresNetwork bool     `json:"requires_network,omitempty"`
	MutatesTarget   bool     `json:"mutates_target,omitempty"`
	Commercial      bool     `json:"commercial,omitempty"`
	Redistributable bool     `json:"redistributable,omitempty"`
}

type metadataManifest struct {
	Version int        `json:"version"`
	Tools   []Metadata `json:"tools"`
}

func enrichTools(root string, tools []Tool) ([]Tool, error) {
	metadata, err := loadMetadata(filepath.Join(root, "config", "tool-metadata.json"))
	if err != nil {
		return nil, err
	}
	result := make([]Tool, len(tools))
	for i, tool := range tools {
		meta := metadata[strings.ToLower(tool.Name)]
		tool.Version = nonEmpty(meta.Version, "unknown")
		tool.Provider = nonEmpty(meta.Provider, defaultProvider(tool))
		tool.CanonicalSource = nonEmpty(meta.CanonicalSource, "unknown")
		tool.License = nonEmpty(meta.License, "unknown")
		tool.InstallScope = nonEmpty(meta.InstallScope, defaultInstallScope(tool))
		tool.TrustStatus = nonEmpty(meta.TrustStatus, defaultTrustStatus(tool))
		tool.Capabilities = normalizeCapabilities(meta.Capabilities)
		tool.RequiresAdmin = meta.RequiresAdmin
		tool.RequiresNetwork = meta.RequiresNetwork
		tool.MutatesTarget = meta.MutatesTarget
		tool.Commercial = meta.Commercial
		tool.Redistributable = meta.Redistributable
		tool.Architecture = "unknown"
		tool.HealthStatus = "unavailable"
		if tool.Available {
			identity, identityErr := executableIdentity(tool.Path)
			if identityErr != nil {
				tool.HealthStatus = "identity-unverified"
				tool.IdentityError = identityErr.Error()
			} else {
				tool.ExecutableIdentity = identity
				tool.Architecture = detectArchitecture(tool.Path)
				tool.HealthStatus = "identity-verified"
			}
		}
		result[i] = tool
	}
	return result, nil
}

func loadMetadata(path string) (map[string]Metadata, error) {
	result := map[string]Metadata{}
	body, err := recordio.ReadFileLimit(path, int64(4<<20))
	if errors.Is(err, os.ErrNotExist) {
		return result, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read tool metadata: %w", err)
	}
	var manifest metadataManifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return nil, fmt.Errorf("decode tool metadata: %w", err)
	}
	if manifest.Version <= 0 {
		return nil, errors.New("tool metadata version must be positive")
	}
	for index, meta := range manifest.Tools {
		meta.Tool = strings.ToLower(strings.TrimSpace(meta.Tool))
		if meta.Tool == "" {
			return nil, fmt.Errorf("tool metadata %d has no tool name", index)
		}
		if _, exists := result[meta.Tool]; exists {
			return nil, fmt.Errorf("duplicate tool metadata %q", meta.Tool)
		}
		meta.Version = strings.TrimSpace(meta.Version)
		meta.Provider = strings.TrimSpace(meta.Provider)
		meta.CanonicalSource = strings.TrimSpace(meta.CanonicalSource)
		meta.License = strings.TrimSpace(meta.License)
		meta.InstallScope = strings.TrimSpace(meta.InstallScope)
		meta.TrustStatus = strings.TrimSpace(meta.TrustStatus)
		meta.Capabilities = normalizeCapabilities(meta.Capabilities)
		result[meta.Tool] = meta
	}
	return result, nil
}

func executableIdentity(path string) (ExecutableIdentity, error) {
	info, err := os.Stat(path)
	if err != nil {
		return ExecutableIdentity{}, err
	}
	if info.IsDir() {
		return ExecutableIdentity{}, errors.New("tool path is a directory")
	}
	file, err := os.Open(path)
	if err != nil {
		return ExecutableIdentity{}, err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return ExecutableIdentity{}, err
	}
	return ExecutableIdentity{
		SHA256:      hex.EncodeToString(hash.Sum(nil)),
		Size:        info.Size(),
		ModifiedUTC: info.ModTime().UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
	}, nil
}

func detectArchitecture(path string) string {
	if file, err := pe.Open(path); err == nil {
		defer file.Close()
		switch file.FileHeader.Machine {
		case pe.IMAGE_FILE_MACHINE_I386:
			return "x86"
		case pe.IMAGE_FILE_MACHINE_AMD64:
			return "x86-64"
		case pe.IMAGE_FILE_MACHINE_ARM64:
			return "arm64"
		case pe.IMAGE_FILE_MACHINE_ARM:
			return "arm"
		default:
			return fmt.Sprintf("pe:0x%x", file.FileHeader.Machine)
		}
	}
	if file, err := elf.Open(path); err == nil {
		defer file.Close()
		return strings.ToLower(file.Machine.String())
	}
	if file, err := macho.Open(path); err == nil {
		defer file.Close()
		return strings.ToLower(file.Cpu.String())
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".bat", ".cmd", ".ps1", ".py", ".sh", ".js":
		return "script"
	default:
		return "unknown"
	}
}

func defaultProvider(tool Tool) string {
	switch tool.Source {
	case "project":
		return "project"
	case "configured":
		return "user-configured"
	case "path":
		return "system"
	default:
		return "unknown"
	}
}

func defaultInstallScope(tool Tool) string {
	switch tool.Source {
	case "project":
		return "project"
	case "configured":
		return "configured-root"
	case "path":
		return "system-or-user"
	default:
		return "unknown"
	}
}

func defaultTrustStatus(tool Tool) string {
	switch tool.Source {
	case "project":
		return "project-owned"
	case "configured":
		return "user-configured"
	case "path":
		return "discovered"
	default:
		return "unknown"
	}
}

func normalizeCapabilities(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}

func nonEmpty(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}
