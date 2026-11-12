package domainpack

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type AuditSeverity string

const (
	AuditInfo AuditSeverity = "info"
	AuditWarn AuditSeverity = "warning"
	AuditHigh AuditSeverity = "high"
)

type AuditFinding struct {
	Severity AuditSeverity `json:"severity"`
	Code     string        `json:"code"`
	Path     string        `json:"path,omitempty"`
	Message  string        `json:"message"`
}

type AuditFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type Audit struct {
	PackID          string         `json:"pack_id"`
	Source          string         `json:"source"`
	License         string         `json:"license"`
	TrustStatus     string         `json:"trust_status"`
	SkillRoot       string         `json:"skill_root"`
	AggregateSHA256 string         `json:"aggregate_sha256"`
	Files           []AuditFile    `json:"files"`
	Findings        []AuditFinding `json:"findings"`
	HighRisk        int            `json:"high_risk"`
	Warnings        int            `json:"warnings"`
	Clean           bool           `json:"clean"`
}

var executableExtensions = map[string]bool{
	".ps1": true, ".sh": true, ".py": true, ".js": true, ".ts": true,
	".bat": true, ".cmd": true, ".exe": true, ".dll": true, ".so": true,
}

type contentPattern struct {
	needle   string
	code     string
	severity AuditSeverity
	message  string
}

var riskyPatterns = []contentPattern{
	{"curl |", "pipe_download_exec", AuditHigh, "download-to-shell pattern requires manual source review"},
	{"curl -s |", "pipe_download_exec", AuditHigh, "download-to-shell pattern requires manual source review"},
	{"wget -q", "download_command", AuditWarn, "network download command is present"},
	{"invoke-expression", "powershell_dynamic_exec", AuditHigh, "PowerShell dynamic execution is present"},
	{"iex(", "powershell_dynamic_exec", AuditHigh, "PowerShell dynamic execution is present"},
	{"~/.ssh", "sensitive_path", AuditHigh, "skill references SSH private material"},
	{"\\.ssh", "sensitive_path", AuditHigh, "skill references SSH private material"},
	{"chrome/user data", "browser_profile_path", AuditHigh, "skill references browser profile storage"},
	{"cookies.sqlite", "browser_cookie_store", AuditHigh, "skill references browser cookie storage"},
	{"codex_home", "agent_bootstrap_env", AuditWarn, "skill references an agent bootstrap environment variable"},
	{"mcpservers", "mcp_registration", AuditWarn, "skill contains MCP registration/configuration content"},
	{"authorization: bearer", "remote_auth_material", AuditWarn, "skill contains bearer authorization configuration"},
}

func AuditPack(root string, pack Pack) (Audit, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return Audit{}, err
	}
	skillPath := filepath.Join(root, filepath.FromSlash(pack.Skill.Path))
	info, err := os.Lstat(skillPath)
	if err != nil {
		return Audit{}, fmt.Errorf("stat skill path: %w", err)
	}
	if !info.Mode().IsRegular() {
		return Audit{}, errors.New("skill entry must be a regular file")
	}
	skillRoot := filepath.Dir(skillPath)
	relRoot, err := filepath.Rel(root, skillRoot)
	if err != nil {
		return Audit{}, err
	}
	if relRoot == ".." || strings.HasPrefix(relRoot, ".."+string(filepath.Separator)) {
		return Audit{}, errors.New("skill root escapes project root")
	}
	result := Audit{
		PackID: pack.ID, Source: pack.Source, License: pack.License, TrustStatus: pack.TrustStatus,
		SkillRoot: filepath.ToSlash(relRoot), Files: []AuditFile{}, Findings: []AuditFinding{},
	}
	err = filepath.WalkDir(skillRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			addAuditFinding(&result, AuditHigh, "symlink_file", rel, "symlink files are not accepted in a trusted domain pack")
			return nil
		}
		if !info.Mode().IsRegular() {
			addAuditFinding(&result, AuditHigh, "non_regular_file", rel, "non-regular file is not accepted in a trusted domain pack")
			return nil
		}
		if info.Size() > 4*1024*1024 {
			addAuditFinding(&result, AuditWarn, "large_file", rel, "file exceeds 4 MiB and was not content-scanned")
			hash, err := hashFile(path)
			if err != nil {
				return err
			}
			result.Files = append(result.Files, AuditFile{Path: rel, SHA256: hash, Size: info.Size()})
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(body)
		result.Files = append(result.Files, AuditFile{Path: rel, SHA256: hex.EncodeToString(digest[:]), Size: info.Size()})
		ext := strings.ToLower(filepath.Ext(path))
		if executableExtensions[ext] {
			addAuditFinding(&result, AuditWarn, "executable_surface", rel, "domain pack contains executable/script surface and requires explicit review")
		}
		lower := strings.ToLower(string(body))
		for _, pattern := range riskyPatterns {
			if strings.Contains(lower, pattern.needle) {
				addAuditFinding(&result, pattern.severity, pattern.code, rel, pattern.message)
			}
		}
		return nil
	})
	if err != nil {
		return Audit{}, err
	}
	sort.Slice(result.Files, func(i, j int) bool { return result.Files[i].Path < result.Files[j].Path })
	aggregate := sha256.New()
	for _, file := range result.Files {
		aggregate.Write([]byte(file.Path))
		aggregate.Write([]byte{0})
		aggregate.Write([]byte(file.SHA256))
		aggregate.Write([]byte{0})
	}
	result.AggregateSHA256 = hex.EncodeToString(aggregate.Sum(nil))
	result.Clean = result.HighRisk == 0
	return result, nil
}

func addAuditFinding(result *Audit, severity AuditSeverity, code, path, message string) {
	result.Findings = append(result.Findings, AuditFinding{Severity: severity, Code: code, Path: path, Message: message})
	switch severity {
	case AuditHigh:
		result.HighRisk++
	case AuditWarn:
		result.Warnings++
	}
}

func hashFile(path string) (string, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:]), nil
}
