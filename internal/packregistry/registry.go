package packregistry

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const ManifestVersion = 1

type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}
type Dependency struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}
type Entrypoint struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	Path string `json:"path"`
}
type Manifest struct {
	Version      int          `json:"version"`
	ID           string       `json:"id"`
	PackVersion  string       `json:"pack_version"`
	Kind         string       `json:"kind"`
	Publisher    string       `json:"publisher"`
	PublicKeyID  string       `json:"public_key_id"`
	Capabilities []string     `json:"capabilities,omitempty"`
	Dependencies []Dependency `json:"dependencies,omitempty"`
	Entrypoints  []Entrypoint `json:"entrypoints,omitempty"`
	Files        []File       `json:"files"`
	Signature    string       `json:"signature,omitempty"`
}
type LoadPolicy struct {
	DataOnly          bool     `json:"data_only"`
	Activatable       bool     `json:"activatable"`
	RequiresAdapter   bool     `json:"requires_adapter"`
	AllowedEntrypoint []string `json:"allowed_entrypoint_kinds,omitempty"`
	Reason            string   `json:"reason,omitempty"`
}
type TrustStore struct {
	Keys map[string]string `json:"keys"`
}
type Verification struct {
	ID          string `json:"id"`
	PackVersion string `json:"pack_version"`
	Kind        string `json:"kind"`
	Publisher   string `json:"publisher"`
	Files       int    `json:"files"`
	Verified    bool   `json:"verified"`
}

func Build(root string, m Manifest) (Manifest, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return Manifest{}, err
	}
	m.Version = ManifestVersion
	m.ID = strings.TrimSpace(m.ID)
	m.PackVersion = strings.TrimSpace(m.PackVersion)
	m.Kind = strings.ToLower(strings.TrimSpace(m.Kind))
	m.Publisher = strings.TrimSpace(m.Publisher)
	m.PublicKeyID = strings.TrimSpace(m.PublicKeyID)
	m.Capabilities = clean(m.Capabilities)
	m.Dependencies = cleanDependencies(m.Dependencies)
	m.Entrypoints = cleanEntrypoints(m.Entrypoints)
	m.Signature = ""
	if m.ID == "" || m.PackVersion == "" || m.Publisher == "" || m.PublicKeyID == "" {
		return Manifest{}, errors.New("id, pack_version, publisher, and public_key_id are required")
	}
	switch m.Kind {
	case "skill", "domain", "knowledge", "plugin":
	default:
		return Manifest{}, fmt.Errorf("invalid pack kind %q", m.Kind)
	}
	var files []File
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "manifest.json" {
			return nil
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("pack entry must be regular file: %s", rel)
		}
		actualSHA, err := streamPackSHA256(path, info.Size())
		if err != nil {
			return err
		}
		files = append(files, File{Path: rel, SHA256: actualSHA, Size: info.Size()})
		return nil
	})
	if err != nil {
		return Manifest{}, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	m.Files = files
	if len(files) == 0 {
		return Manifest{}, errors.New("pack contains no files")
	}
	if err := validateManifestSchema(m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}
func Sign(m Manifest, private ed25519.PrivateKey) (Manifest, error) {
	m.Signature = ""
	body, err := canonical(m)
	if err != nil {
		return Manifest{}, err
	}
	m.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, body))
	return m, nil
}
func Verify(root string, m Manifest, trust TrustStore) (Verification, error) {
	if m.Version != ManifestVersion {
		return Verification{}, fmt.Errorf("unsupported manifest version %d", m.Version)
	}
	if err := validateManifestSchema(m); err != nil {
		return Verification{}, err
	}
	keyText, ok := trust.Keys[m.PublicKeyID]
	if !ok {
		return Verification{}, fmt.Errorf("untrusted public_key_id %q", m.PublicKeyID)
	}
	keyBytes, err := base64.StdEncoding.DecodeString(keyText)
	if err != nil || len(keyBytes) != ed25519.PublicKeySize {
		return Verification{}, errors.New("invalid trusted Ed25519 key")
	}
	sig, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil {
		return Verification{}, errors.New("invalid manifest signature encoding")
	}
	copy := m
	copy.Signature = ""
	body, err := canonical(copy)
	if err != nil {
		return Verification{}, err
	}
	if !ed25519.Verify(ed25519.PublicKey(keyBytes), body, sig) {
		return Verification{}, errors.New("manifest signature verification failed")
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return Verification{}, err
	}
	for _, f := range m.Files {
		cleanPath := filepath.Clean(filepath.FromSlash(f.Path))
		if cleanPath == "." || filepath.IsAbs(cleanPath) || cleanPath == ".." || strings.HasPrefix(cleanPath, ".."+string(filepath.Separator)) {
			return Verification{}, fmt.Errorf("unsafe pack path %q", f.Path)
		}
		path := filepath.Join(root, cleanPath)
		rel, err := filepath.Rel(root, path)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return Verification{}, fmt.Errorf("pack path escapes root: %q", f.Path)
		}
		info, err := os.Lstat(path)
		if err != nil {
			return Verification{}, err
		}
		if !info.Mode().IsRegular() {
			return Verification{}, fmt.Errorf("pack entry must be regular file: %s", f.Path)
		}
		if info.Size() != f.Size {
			return Verification{}, fmt.Errorf("size mismatch for %s", f.Path)
		}
		actualSHA, err := streamPackSHA256(path, f.Size)
		if err != nil {
			return Verification{}, err
		}
		if actualSHA != strings.ToLower(f.SHA256) {
			return Verification{}, fmt.Errorf("sha256 mismatch for %s", f.Path)
		}
	}
	return Verification{ID: m.ID, PackVersion: m.PackVersion, Kind: m.Kind, Publisher: m.Publisher, Files: len(m.Files), Verified: true}, nil
}

func streamPackSHA256(path string, expectedSize int64) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	opened, err := file.Stat()
	if err != nil {
		return "", errors.Join(err, file.Close())
	}
	if !opened.Mode().IsRegular() || opened.Size() != expectedSize {
		return "", errors.Join(fmt.Errorf("pack file changed before hashing: %s", path), file.Close())
	}
	hash := sha256.New()
	written, copyErr := io.CopyBuffer(hash, file, make([]byte, 1<<20))
	after, statErr := file.Stat()
	closeErr := file.Close()
	if err := errors.Join(copyErr, statErr, closeErr); err != nil {
		return "", err
	}
	if written != expectedSize || after.Size() != expectedSize ||
		!opened.ModTime().Equal(after.ModTime()) {
		return "", fmt.Errorf("pack file changed during hashing: %s", path)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func canonical(m Manifest) ([]byte, error) {
	m.Capabilities = clean(m.Capabilities)
	m.Dependencies = cleanDependencies(m.Dependencies)
	m.Entrypoints = cleanEntrypoints(m.Entrypoints)
	sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Path < m.Files[j].Path })
	return json.Marshal(m)
}
func clean(v []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, x := range v {
		x = strings.TrimSpace(x)
		if x != "" && !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}
func EvaluateLoadPolicy(m Manifest) (LoadPolicy, error) {
	if err := validateManifestSchema(m); err != nil {
		return LoadPolicy{}, err
	}
	allowed := []string{"data", "knowledge", "protocols", "rules", "skill", "symbols", "types"}
	policy := LoadPolicy{DataOnly: true, Activatable: true, AllowedEntrypoint: allowed}
	for _, entry := range m.Entrypoints {
		if entry.Kind == "mcp-adapter" {
			return LoadPolicy{DataOnly: false, Activatable: false, RequiresAdapter: true, Reason: "executable plugin entrypoints require an external adapter and cannot be activated in-process"}, nil
		}
	}
	for _, file := range m.Files {
		if executablePackPath(file.Path) {
			return LoadPolicy{DataOnly: false, Activatable: false, RequiresAdapter: true, Reason: "pack contains executable content and cannot be activated by the data-pack loader"}, nil
		}
	}
	for _, capability := range m.Capabilities {
		lower := strings.ToLower(capability)
		if strings.Contains(lower, "exec") || strings.Contains(lower, "shell") || strings.Contains(lower, "process") || strings.Contains(lower, "write") {
			return LoadPolicy{DataOnly: false, Activatable: false, RequiresAdapter: true, Reason: "pack declares an effectful capability and cannot be activated by the data-pack loader"}, nil
		}
	}
	return policy, nil
}

func validateManifestSchema(m Manifest) error {
	if strings.TrimSpace(m.ID) == "" || strings.TrimSpace(m.PackVersion) == "" || strings.TrimSpace(m.Publisher) == "" || strings.TrimSpace(m.PublicKeyID) == "" {
		return errors.New("id, pack_version, publisher, and public_key_id are required")
	}
	switch strings.ToLower(strings.TrimSpace(m.Kind)) {
	case "skill", "domain", "knowledge", "plugin":
	default:
		return fmt.Errorf("invalid pack kind %q", m.Kind)
	}
	files := map[string]bool{}
	for _, file := range m.Files {
		path := filepath.ToSlash(filepath.Clean(filepath.FromSlash(strings.TrimSpace(file.Path))))
		if path == "." || strings.HasPrefix(path, "../") || path == ".." || filepath.IsAbs(filepath.FromSlash(path)) {
			return fmt.Errorf("unsafe pack path %q", file.Path)
		}
		if files[path] {
			return fmt.Errorf("duplicate pack file %q", path)
		}
		files[path] = true
		if len(strings.TrimSpace(file.SHA256)) != 64 {
			return fmt.Errorf("invalid sha256 for %s", file.Path)
		}
	}
	seenDeps := map[string]bool{}
	for _, dep := range m.Dependencies {
		id := strings.TrimSpace(dep.ID)
		version := strings.TrimSpace(dep.Version)
		if id == "" || version == "" {
			return errors.New("dependency id and version are required")
		}
		if id == m.ID {
			return errors.New("pack cannot depend on itself")
		}
		if seenDeps[id] {
			return fmt.Errorf("duplicate dependency %q", id)
		}
		seenDeps[id] = true
	}
	seenEntries := map[string]bool{}
	for _, entry := range m.Entrypoints {
		name := strings.TrimSpace(entry.Name)
		kind := strings.ToLower(strings.TrimSpace(entry.Kind))
		path := filepath.ToSlash(filepath.Clean(filepath.FromSlash(strings.TrimSpace(entry.Path))))
		if name == "" || kind == "" || path == "" || path == "." {
			return errors.New("entrypoint name, kind, and path are required")
		}
		switch kind {
		case "data", "knowledge", "protocols", "rules", "skill", "symbols", "types", "mcp-adapter":
		default:
			return fmt.Errorf("invalid entrypoint kind %q", entry.Kind)
		}
		if seenEntries[name] {
			return fmt.Errorf("duplicate entrypoint name %q", name)
		}
		seenEntries[name] = true
		if !files[path] {
			return fmt.Errorf("entrypoint %q references file not in manifest: %s", name, path)
		}
	}
	return nil
}

func cleanDependencies(values []Dependency) []Dependency {
	out := make([]Dependency, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		value.ID = strings.TrimSpace(value.ID)
		value.Version = strings.TrimSpace(value.Version)
		if value.ID == "" || seen[value.ID] {
			continue
		}
		seen[value.ID] = true
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func cleanEntrypoints(values []Entrypoint) []Entrypoint {
	out := make([]Entrypoint, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		value.Name = strings.TrimSpace(value.Name)
		value.Kind = strings.ToLower(strings.TrimSpace(value.Kind))
		value.Path = filepath.ToSlash(filepath.Clean(filepath.FromSlash(strings.TrimSpace(value.Path))))
		if value.Name == "" || seen[value.Name] {
			continue
		}
		seen[value.Name] = true
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func executablePackPath(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".bat", ".cmd", ".com", ".dll", ".dylib", ".exe", ".jar", ".js", ".msi", ".ps1", ".py", ".scr", ".so", ".vbs":
		return true
	default:
		return false
	}
}
