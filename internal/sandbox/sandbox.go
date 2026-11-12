package sandbox

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"

	"reverseresearch/internal/recordio"
	"reverseresearch/internal/toolindex"
)

type Kind string

const (
	KindFilesystem Kind = "filesystem"
	KindWSL        Kind = "wsl"
	KindDocker     Kind = "docker"
)

var safeID = regexp.MustCompile(`^sandbox_[a-f0-9]{16}$`)

var ErrPlanConflict = errors.New("sandbox id is already bound to a different plan")

type PlanRequest struct {
	Name  string `json:"name"`
	Route string `json:"route,omitempty"`
	Kind  Kind   `json:"kind"`
}

type Plan struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Route         string   `json:"route,omitempty"`
	Kind          Kind     `json:"kind"`
	Root          string   `json:"root"`
	InputDir      string   `json:"input_dir"`
	WorkDir       string   `json:"work_dir"`
	OutputDir     string   `json:"output_dir"`
	RequiredTools []string `json:"required_tools,omitempty"`
	MissingTools  []string `json:"missing_tools,omitempty"`
	Ready         bool     `json:"ready"`
	CreatedUTC    string   `json:"created_utc"`
}

type Manager struct {
	root  string
	tools toolindex.Index
}

func New(root string, tools toolindex.Index) (*Manager, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("sandbox root is required")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve sandbox root: %w", err)
	}
	return &Manager{root: filepath.Clean(absolute), tools: tools}, nil
}

func (m *Manager) Plan(request PlanRequest) (Plan, error) {
	name := strings.TrimSpace(request.Name)
	if name == "" {
		return Plan{}, errors.New("sandbox name is required")
	}
	required, err := requiredTools(request.Kind)
	if err != nil {
		return Plan{}, err
	}
	id, err := newID()
	if err != nil {
		return Plan{}, err
	}
	root := filepath.Join(m.root, "sandboxes", id)
	missing := make([]string, 0, len(required))
	for _, toolName := range required {
		tool, ok := m.tools.ByName(toolName)
		if !ok || !tool.Available {
			missing = append(missing, toolName)
		}
	}
	return Plan{
		ID:            id,
		Name:          name,
		Route:         strings.TrimSpace(request.Route),
		Kind:          request.Kind,
		Root:          root,
		InputDir:      filepath.Join(root, "input"),
		WorkDir:       filepath.Join(root, "work"),
		OutputDir:     filepath.Join(root, "output"),
		RequiredTools: append([]string(nil), required...),
		MissingTools:  missing,
		Ready:         len(missing) == 0,
		CreatedUTC:    time.Now().UTC().Format(time.RFC3339Nano),
	}, nil
}

func (m *Manager) Create(plan Plan) (result Plan, err error) {
	if !safeID.MatchString(plan.ID) {
		return Plan{}, errors.New("invalid sandbox id")
	}
	required, err := requiredTools(plan.Kind)
	if err != nil {
		return Plan{}, err
	}
	expectedRoot := filepath.Join(m.root, "sandboxes", plan.ID)
	if !samePath(plan.Root, expectedRoot) {
		return Plan{}, errors.New("sandbox root does not match manager-owned location")
	}
	expectedDirs := []string{
		filepath.Join(expectedRoot, "input"),
		filepath.Join(expectedRoot, "work"),
		filepath.Join(expectedRoot, "output"),
	}
	if !samePath(plan.InputDir, expectedDirs[0]) || !samePath(plan.WorkDir, expectedDirs[1]) || !samePath(plan.OutputDir, expectedDirs[2]) {
		return Plan{}, errors.New("sandbox directory layout is not canonical")
	}
	if strings.TrimSpace(plan.Name) == "" {
		return Plan{}, errors.New("sandbox name is required")
	}
	if _, err := time.Parse(time.RFC3339Nano, plan.CreatedUTC); err != nil {
		return Plan{}, errors.New("sandbox plan requires its original created_utc")
	}
	if !slices.Equal(plan.RequiredTools, required) {
		return Plan{}, errors.New("sandbox plan required tools differ from the canonical kind")
	}
	body, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return Plan{}, err
	}
	body = append(body, '\n')
	if len(body) > 32<<10 {
		return Plan{}, errors.New("sandbox plan exceeds 32 KiB")
	}
	parent := filepath.Dir(expectedRoot)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return Plan{}, err
	}
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return Plan{}, errors.New("sandbox parent must be a regular manager-owned directory")
	}
	unlock, err := recordio.Acquire(filepath.Join(parent, "."+plan.ID+".lock"), 5*time.Second)
	if err != nil {
		return Plan{}, err
	}
	defer func() { err = errors.Join(err, unlock()) }()
	if info, inspectErr := os.Lstat(expectedRoot); inspectErr == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return Plan{}, errors.New("existing sandbox is not a regular directory")
		}
		storedPath := filepath.Join(expectedRoot, "sandbox.json")
		info, err := os.Lstat(storedPath)
		if err != nil || !info.Mode().IsRegular() {
			return Plan{}, errors.New("existing sandbox has no committed regular metadata; inspect it before recovery")
		}
		storedBody, err := recordio.ReadFileLimit(storedPath, 32<<10)
		if err != nil {
			return Plan{}, err
		}
		var stored Plan
		if err := recordio.DecodeJSON(storedBody, &stored); err != nil {
			return Plan{}, err
		}
		decoder := json.NewDecoder(bytes.NewReader(storedBody))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&stored); err != nil {
			return Plan{}, err
		}
		storedCanonical, err := json.MarshalIndent(stored, "", "  ")
		if err != nil || !bytes.Equal(append(storedCanonical, '\n'), body) {
			return Plan{}, ErrPlanConflict
		}
		for _, dir := range expectedDirs {
			info, err := os.Lstat(dir)
			if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return Plan{}, errors.New("committed sandbox directory layout is incomplete or changed")
			}
		}
		return stored, nil
	} else if !errors.Is(inspectErr, os.ErrNotExist) {
		return Plan{}, fmt.Errorf("inspect sandbox root: %w", inspectErr)
	}
	missing := make([]string, 0, len(required))
	for _, toolName := range required {
		tool, ok := m.tools.ByName(toolName)
		if !ok || !tool.Available {
			missing = append(missing, toolName)
		}
	}
	if !plan.Ready || len(plan.MissingTools) != 0 || len(missing) != 0 {
		if len(missing) == 0 {
			missing = append(missing, plan.MissingTools...)
		}
		return Plan{}, fmt.Errorf("sandbox backend is not ready; missing tools: %s", strings.Join(missing, ", "))
	}
	// Publish one complete directory. Cleanup owns only this private staging
	// directory, never an existing root created by another cooperating process.
	stage, err := os.MkdirTemp(parent, ".rr-sandbox-"+plan.ID+"-")
	if err != nil {
		return Plan{}, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(stage)) }()
	for _, name := range []string{"input", "work", "output"} {
		if err := os.Mkdir(filepath.Join(stage, name), 0o700); err != nil {
			return Plan{}, fmt.Errorf("create sandbox directory %s: %w", name, err)
		}
	}
	if err := recordio.WriteFile(filepath.Join(stage, "sandbox.json"), body, 0o600); err != nil {
		return Plan{}, fmt.Errorf("write sandbox metadata: %w", err)
	}
	if err := os.Rename(stage, expectedRoot); err != nil {
		return Plan{}, fmt.Errorf("publish sandbox: %w", err)
	}
	return plan, nil
}

func requiredTools(kind Kind) ([]string, error) {
	switch kind {
	case KindFilesystem:
		return nil, nil
	case KindWSL:
		return []string{"wsl"}, nil
	case KindDocker:
		return []string{"docker"}, nil
	default:
		return nil, fmt.Errorf("unsupported sandbox kind %q", kind)
	}
}

func newID() (string, error) {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate sandbox id: %w", err)
	}
	return "sandbox_" + hex.EncodeToString(raw[:]), nil
}

func samePath(left, right string) bool {
	leftAbs, _ := filepath.Abs(left)
	rightAbs, _ := filepath.Abs(right)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(filepath.Clean(leftAbs), filepath.Clean(rightAbs))
	}
	return filepath.Clean(leftAbs) == filepath.Clean(rightAbs)
}
