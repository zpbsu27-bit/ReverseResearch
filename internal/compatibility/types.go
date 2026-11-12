package compatibility

import (
	"errors"
	"fmt"
	"strings"

	"reverseresearch/internal/targetidentity"
)

type Outcome string

const (
	OutcomeUnknown      Outcome = "unknown"
	OutcomeCandidate    Outcome = "candidate"
	OutcomeCompatible   Outcome = "compatible"
	OutcomeIncompatible Outcome = "incompatible"
)

// MaxImportManifestBytes bounds an operator-supplied manifest before it is read
// and decoded. Without it, a large or malicious path could allocate its whole
// contents in memory and exhaust the process.
const MaxImportManifestBytes = int64(16 << 20)

type Validation string

const (
	ValidationRecordOnly Validation = "record-only"
	ValidationStatic     Validation = "static-verified"
	ValidationRuntime    Validation = "runtime-verified"
)

var (
	ErrInvalidRecordID     = errors.New("invalid compatibility record id")
	ErrEvidenceRequired    = errors.New("verified compatibility record requires case evidence")
	ErrRuntimeRequired     = errors.New("compatible outcome requires runtime-verified evidence")
	ErrRuntimeEvidenceKind = errors.New("runtime-verified compatibility requires referenced evidence kind runtime or runtime-verification")
	ErrHookMismatch        = errors.New("hook record does not match compatibility module identity")
)

type AddRequest struct {
	Game        string     `json:"game"`
	Build       string     `json:"build"`
	ModulePath  string     `json:"module_path"`
	ModuleRole  string     `json:"module_role,omitempty"`
	HookID      string     `json:"hook_id,omitempty"`
	HookName    string     `json:"hook_name,omitempty"`
	Outcome     Outcome    `json:"outcome"`
	Validation  Validation `json:"validation"`
	CaseID      string     `json:"case_id,omitempty"`
	EvidenceIDs []string   `json:"evidence_ids,omitempty"`
	Notes       string     `json:"notes,omitempty"`
}

type ImportManifest struct {
	Records []AddRequest `json:"records"`
}

type ImportBinding struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type HookBinding struct {
	ID             string `json:"id"`
	SourceRVA      uint64 `json:"source_rva"`
	DestinationRVA uint64 `json:"destination_rva"`
	OriginalHex    string `json:"original_hex"`
	PatchHex       string `json:"patch_hex"`
	BaselineSHA256 string `json:"baseline_sha256"`
}

type Record struct {
	ID           string                  `json:"id"`
	CreatedUTC   string                  `json:"created_utc"`
	Game         string                  `json:"game"`
	Build        string                  `json:"build"`
	ModuleRole   string                  `json:"module_role,omitempty"`
	Module       targetidentity.Identity `json:"module"`
	HookName     string                  `json:"hook_name,omitempty"`
	Hook         *HookBinding            `json:"hook,omitempty"`
	Outcome      Outcome                 `json:"outcome"`
	Validation   Validation              `json:"validation"`
	CaseID       string                  `json:"case_id,omitempty"`
	EvidenceIDs  []string                `json:"evidence_ids,omitempty"`
	Notes        string                  `json:"notes,omitempty"`
	ImportedFrom *ImportBinding          `json:"imported_from,omitempty"`
}

type Filter struct {
	Game       string     `json:"game,omitempty"`
	Build      string     `json:"build,omitempty"`
	ModuleSHA  string     `json:"module_sha256,omitempty"`
	HookID     string     `json:"hook_id,omitempty"`
	Outcome    Outcome    `json:"outcome,omitempty"`
	Validation Validation `json:"validation,omitempty"`
	Limit      int        `json:"limit,omitempty"`
}

type ImportResult struct {
	Manifest ImportBinding `json:"manifest"`
	Records  []Record      `json:"records"`
}

type Issue struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Verification struct {
	RecordID                 string  `json:"record_id"`
	CheckedUTC               string  `json:"checked_utc"`
	RecordValid              bool    `json:"record_valid"`
	SourceCurrent            bool    `json:"source_current"`
	HookBindingCurrent       bool    `json:"hook_binding_current"`
	CaseValid                bool    `json:"case_valid"`
	EvidenceLinksCurrent     bool    `json:"evidence_links_current"`
	CompatibilityRevalidated bool    `json:"compatibility_revalidated"`
	Issues                   []Issue `json:"issues"`
}

func validOutcome(value Outcome) bool {
	switch value {
	case OutcomeUnknown, OutcomeCandidate, OutcomeCompatible, OutcomeIncompatible:
		return true
	default:
		return false
	}
}

func validValidation(value Validation) bool {
	switch value {
	case ValidationRecordOnly, ValidationStatic, ValidationRuntime:
		return true
	default:
		return false
	}
}

func normalizeRequest(request AddRequest) (AddRequest, error) {
	request.Game = strings.TrimSpace(request.Game)
	request.Build = strings.TrimSpace(request.Build)
	request.ModulePath = strings.TrimSpace(request.ModulePath)
	request.ModuleRole = strings.TrimSpace(request.ModuleRole)
	request.HookID = strings.TrimSpace(request.HookID)
	request.HookName = strings.TrimSpace(request.HookName)
	request.CaseID = strings.TrimSpace(request.CaseID)
	request.Notes = strings.TrimSpace(request.Notes)
	if request.Game == "" || request.Build == "" || request.ModulePath == "" {
		return request, errors.New("game, build, and module_path are required")
	}
	if request.Outcome == "" {
		request.Outcome = OutcomeUnknown
	}
	if request.Validation == "" {
		request.Validation = ValidationRecordOnly
	}
	if !validOutcome(request.Outcome) {
		return request, fmt.Errorf("invalid compatibility outcome %q", request.Outcome)
	}
	if !validValidation(request.Validation) {
		return request, fmt.Errorf("invalid compatibility validation %q", request.Validation)
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(request.EvidenceIDs))
	for _, id := range request.EvidenceIDs {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	request.EvidenceIDs = out
	if request.CaseID == "" && len(request.EvidenceIDs) != 0 {
		return request, errors.New("evidence_ids require case_id")
	}
	if request.Outcome == OutcomeCompatible && request.Validation != ValidationRuntime {
		return request, ErrRuntimeRequired
	}
	if request.Validation != ValidationRecordOnly && (request.CaseID == "" || len(request.EvidenceIDs) == 0) {
		return request, ErrEvidenceRequired
	}
	return request, nil
}
