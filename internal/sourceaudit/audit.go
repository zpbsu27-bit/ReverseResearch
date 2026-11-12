package sourceaudit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	DefaultMaxFiles      = 20000
	DefaultMaxFileBytes  = int64(2 << 20)
	DefaultMaxTotalBytes = int64(256 << 20)
)

type Options struct {
	MaxFiles      int   `json:"max_files,omitempty"`
	MaxFileBytes  int64 `json:"max_file_bytes,omitempty"`
	MaxTotalBytes int64 `json:"max_total_bytes,omitempty"`
}

type Manifest struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	SHA256 string `json:"sha256"`
}

type Dependency struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	Manifest  string `json:"manifest"`
	Scope     string `json:"scope,omitempty"`
}

type SecretCandidate struct {
	Path        string `json:"path"`
	Line        int    `json:"line"`
	Kind        string `json:"kind"`
	Fingerprint string `json:"fingerprint"`
	Redacted    string `json:"redacted"`
	Strength    string `json:"strength"`
}

type Report struct {
	Root             string            `json:"root"`
	SnapshotSHA256   string            `json:"snapshot_sha256"`
	FilesScanned     int               `json:"files_scanned"`
	BytesScanned     int64             `json:"bytes_scanned"`
	LanguageCounts   map[string]int    `json:"language_counts"`
	Manifests        []Manifest        `json:"manifests"`
	Dependencies     []Dependency      `json:"dependencies"`
	SecretCandidates []SecretCandidate `json:"secret_candidates"`
	SkippedDirs      []string          `json:"skipped_dirs,omitempty"`
	CompletedUTC     string            `json:"completed_utc"`
}

var (
	awsAccessKey = regexp.MustCompile(`(AKIA[0-9A-Z]{16})`)
	assignment   = regexp.MustCompile(`(?i)\b(api[_-]?key|access[_-]?token|auth[_-]?token|secret|password|passwd)\b\s*[:=]\s*["']([^"']{8,})["']`)
	privateKey   = regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`)
)

func Scan(root string, options Options) (Report, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return Report{}, errors.New("source audit root is required")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return Report{}, err
	}
	info, err := os.Stat(absolute)
	if err != nil {
		return Report{}, err
	}
	if !info.IsDir() {
		return Report{}, errors.New("source audit root must be a directory")
	}
	options = normalizeOptions(options)
	report := Report{
		Root: absolute, LanguageCounts: map[string]int{}, Manifests: []Manifest{},
		Dependencies: []Dependency{}, SecretCandidates: []SecretCandidate{}, SkippedDirs: []string{},
	}
	seenDependencies := map[string]bool{}
	snapshot := sha256.New()
	err = filepath.WalkDir(absolute, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(absolute, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if entry.IsDir() {
			if rel != "." && shouldSkipDir(entry.Name()) {
				report.SkippedDirs = append(report.SkippedDirs, rel)
				return filepath.SkipDir
			}
			return nil
		}
		if report.FilesScanned >= options.MaxFiles {
			return fmt.Errorf("source audit file limit exceeded: %d", options.MaxFiles)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		report.FilesScanned++
		report.LanguageCounts[languageFor(path)]++
		if info.Size() > options.MaxFileBytes {
			return nil
		}
		if report.BytesScanned+info.Size() > options.MaxTotalBytes {
			return fmt.Errorf("source audit byte limit exceeded: %d", options.MaxTotalBytes)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		report.BytesScanned += int64(len(body))
		fileDigest := sha256.Sum256(body)
		snapshot.Write([]byte(rel))
		snapshot.Write([]byte{0})
		snapshot.Write(fileDigest[:])
		snapshot.Write([]byte{0})
		if kind := manifestKind(entry.Name()); kind != "" {
			digest := sha256.Sum256(body)
			report.Manifests = append(report.Manifests, Manifest{
				Path: rel, Kind: kind, SHA256: hex.EncodeToString(digest[:]),
			})
			for _, dependency := range parseDependencies(kind, rel, body) {
				key := dependency.Ecosystem + "\x00" + dependency.Name + "\x00" + dependency.Version + "\x00" + dependency.Scope
				if !seenDependencies[key] {
					seenDependencies[key] = true
					report.Dependencies = append(report.Dependencies, dependency)
				}
			}
		}
		if isTextCandidate(path, body) {
			report.SecretCandidates = append(report.SecretCandidates, scanSecretCandidates(rel, body)...)
		}
		return nil
	})
	if err != nil {
		return Report{}, err
	}
	sort.Slice(report.Manifests, func(i, j int) bool { return report.Manifests[i].Path < report.Manifests[j].Path })
	sort.Slice(report.Dependencies, func(i, j int) bool {
		if report.Dependencies[i].Ecosystem != report.Dependencies[j].Ecosystem {
			return report.Dependencies[i].Ecosystem < report.Dependencies[j].Ecosystem
		}
		if report.Dependencies[i].Name != report.Dependencies[j].Name {
			return report.Dependencies[i].Name < report.Dependencies[j].Name
		}
		return report.Dependencies[i].Version < report.Dependencies[j].Version
	})
	sort.Slice(report.SecretCandidates, func(i, j int) bool {
		if report.SecretCandidates[i].Path != report.SecretCandidates[j].Path {
			return report.SecretCandidates[i].Path < report.SecretCandidates[j].Path
		}
		return report.SecretCandidates[i].Line < report.SecretCandidates[j].Line
	})
	sort.Strings(report.SkippedDirs)
	report.SnapshotSHA256 = hex.EncodeToString(snapshot.Sum(nil))
	report.CompletedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	return report, nil
}

func normalizeOptions(options Options) Options {
	if options.MaxFiles <= 0 {
		options.MaxFiles = DefaultMaxFiles
	}
	if options.MaxFiles > 100000 {
		options.MaxFiles = 100000
	}
	if options.MaxFileBytes <= 0 {
		options.MaxFileBytes = DefaultMaxFileBytes
	}
	if options.MaxFileBytes > 16<<20 {
		options.MaxFileBytes = 16 << 20
	}
	if options.MaxTotalBytes <= 0 {
		options.MaxTotalBytes = DefaultMaxTotalBytes
	}
	if options.MaxTotalBytes > 2<<30 {
		options.MaxTotalBytes = 2 << 30
	}
	return options
}

func shouldSkipDir(name string) bool {
	switch strings.ToLower(name) {
	case ".git", ".hg", ".svn", "node_modules", "vendor", ".tmp", "dist", "build", "bin", "obj":
		return true
	default:
		return false
	}
}

func manifestKind(name string) string {
	switch strings.ToLower(name) {
	case "go.mod":
		return "go-mod"
	case "package.json":
		return "npm"
	case "requirements.txt":
		return "python-requirements"
	case "cargo.toml":
		return "cargo"
	case "pom.xml":
		return "maven"
	case "cyclonedx.json", "bom.json":
		return "cyclonedx"
	case "spdx.json":
		return "spdx"
	default:
		return ""
	}
}

func parseDependencies(kind, manifest string, body []byte) []Dependency {
	switch kind {
	case "go-mod":
		return parseGoMod(manifest, string(body))
	case "npm":
		return parsePackageJSON(manifest, body)
	case "python-requirements":
		return parseRequirements(manifest, string(body))
	default:
		return nil
	}
}

func parseGoMod(manifest, body string) []Dependency {
	result := []Dependency{}
	scanner := bufio.NewScanner(strings.NewReader(body))
	inRequire := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if line == "require (" {
			inRequire = true
			continue
		}
		if inRequire && line == ")" {
			inRequire = false
			continue
		}
		if strings.HasPrefix(line, "require ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "require "))
		} else if !inRequire {
			continue
		}
		line = strings.Split(line, "//")[0]
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			result = append(result, Dependency{Ecosystem: "go", Name: fields[0], Version: fields[1], Manifest: manifest})
		}
	}
	return result
}

func parsePackageJSON(manifest string, body []byte) []Dependency {
	var object struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if json.Unmarshal(body, &object) != nil {
		return nil
	}
	result := []Dependency{}
	for name, version := range object.Dependencies {
		result = append(result, Dependency{Ecosystem: "npm", Name: name, Version: version, Manifest: manifest, Scope: "runtime"})
	}
	for name, version := range object.DevDependencies {
		result = append(result, Dependency{Ecosystem: "npm", Name: name, Version: version, Manifest: manifest, Scope: "development"})
	}
	return result
}

func parseRequirements(manifest, body string) []Dependency {
	result := []Dependency{}
	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		name, version := line, ""
		for _, separator := range []string{"==", ">=", "<=", "~=", ">", "<"} {
			if index := strings.Index(line, separator); index > 0 {
				name = strings.TrimSpace(line[:index])
				version = strings.TrimSpace(line[index:])
				break
			}
		}
		if name != "" {
			result = append(result, Dependency{Ecosystem: "python", Name: name, Version: version, Manifest: manifest})
		}
	}
	return result
}

func scanSecretCandidates(path string, body []byte) []SecretCandidate {
	result := []SecretCandidate{}
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		for _, match := range awsAccessKey.FindAllStringSubmatch(line, -1) {
			result = append(result, newSecretCandidate(path, lineNumber, "aws-access-key", match[1]))
		}
		if privateKey.MatchString(line) {
			result = append(result, newSecretCandidate(path, lineNumber, "private-key-header", "private-key-material"))
		}
		for _, match := range assignment.FindAllStringSubmatch(line, -1) {
			result = append(result, newSecretCandidate(path, lineNumber, strings.ToLower(match[1]), match[2]))
		}
	}
	return result
}

func newSecretCandidate(path string, line int, kind, value string) SecretCandidate {
	digest := sha256.Sum256([]byte(value))
	return SecretCandidate{
		Path: path, Line: line, Kind: kind, Fingerprint: "sha256:" + hex.EncodeToString(digest[:]),
		Redacted: redact(value), Strength: "candidate",
	}
}

func redact(value string) string {
	runes := []rune(value)
	if len(runes) <= 4 {
		return "****"
	}
	return string(runes[:2]) + strings.Repeat("*", minInt(len(runes)-4, 12)) + string(runes[len(runes)-2:])
}

func isTextCandidate(path string, body []byte) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".go", ".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".kt", ".rs", ".c", ".cc", ".cpp", ".h", ".hpp",
		".cs", ".rb", ".php", ".sh", ".ps1", ".yaml", ".yml", ".json", ".toml", ".ini", ".env", ".txt", ".md", ".xml":
		return true
	}
	for _, value := range body {
		if value == 0 {
			return false
		}
	}
	return len(body) < 256*1024
}

func languageFor(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".go":
		return "go"
	case ".py":
		return "python"
	case ".js", ".jsx":
		return "javascript"
	case ".ts", ".tsx":
		return "typescript"
	case ".java":
		return "java"
	case ".kt", ".kts":
		return "kotlin"
	case ".rs":
		return "rust"
	case ".c":
		return "c"
	case ".cc", ".cpp", ".cxx":
		return "cpp"
	case ".h", ".hpp":
		return "header"
	case ".cs":
		return "csharp"
	case ".sh":
		return "shell"
	case ".ps1":
		return "powershell"
	default:
		return "other"
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
