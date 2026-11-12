package hookplan

import (
	"errors"
	"fmt"
	"strings"

	"reverseresearch/internal/targetidentity"
)

const (
	StatePlanned     = "planned"
	StateApplying    = "applying"
	StateApplied     = "applied"
	StateRollingBack = "rolling_back"
	StateRolledBack  = "rolled_back"
	StateCancelled   = "cancelled"

	MaxHookOverwriteBytes = 64
	MaxBoundaryProofBytes = 64 << 10
)

var (
	ErrConflict           = errors.New("hook interval conflict")
	ErrVersionConflict    = errors.New("hook version conflict")
	ErrInvalidHookID      = errors.New("invalid hook id")
	ErrWrongOriginalBytes = errors.New("hook source bytes do not match the frozen original")
	ErrWrongAppliedBytes  = errors.New("hook source bytes do not match the applied detour")
	ErrStructureChanged   = errors.New("hook target PE structure changed")
)

type PlanRequest struct {
	Path           string `json:"path"`
	SourceRVA      uint64 `json:"source_rva"`
	DestinationRVA uint64 `json:"destination_rva"`
	ExpectedHex    string `json:"expected_hex,omitempty"`
	Description    string `json:"description,omitempty"`
}

type ApplyRequest struct {
	HookID          string `json:"hook_id"`
	ExpectedVersion int    `json:"expected_version"`
	OperationID     string `json:"operation_id"`
	ConfirmInPlace  bool   `json:"confirm_in_place"`
}

type RollbackRequest struct {
	HookID          string `json:"hook_id"`
	ExpectedVersion int    `json:"expected_version"`
	OperationID     string `json:"operation_id"`
}

type CancelRequest struct {
	HookID          string `json:"hook_id"`
	ExpectedVersion int    `json:"expected_version"`
}

type Instruction struct {
	Address  uint64 `json:"address"`
	RVA      uint64 `json:"rva"`
	Size     int    `json:"size"`
	BytesHex string `json:"bytes_hex"`
	Opcode   string `json:"opcode"`
	Type     string `json:"type,omitempty"`
}

type Hook struct {
	ID                  string                  `json:"id"`
	Version             int                     `json:"version"`
	State               string                  `json:"state"`
	CreatedUTC          string                  `json:"created_utc"`
	UpdatedUTC          string                  `json:"updated_utc"`
	Path                string                  `json:"path"`
	Baseline            targetidentity.Identity `json:"baseline"`
	SourceRVA           uint64                  `json:"source_rva"`
	DestinationRVA      uint64                  `json:"destination_rva"`
	SourceFileOffset    int64                   `json:"source_file_offset"`
	OverwriteSize       int                     `json:"overwrite_size"`
	OriginalHex         string                  `json:"original_hex"`
	PatchHex            string                  `json:"patch_hex"`
	Relocation          string                  `json:"relocation"`
	Instructions        []Instruction           `json:"instructions"`
	PatchPlanID         string                  `json:"patch_plan_id"`
	Description         string                  `json:"description,omitempty"`
	ApplyOperationID    string                  `json:"apply_operation_id,omitempty"`
	RollbackOperationID string                  `json:"rollback_operation_id,omitempty"`
	AppliedUTC          string                  `json:"applied_utc,omitempty"`
	RolledBackUTC       string                  `json:"rolled_back_utc,omitempty"`
	CancelledUTC        string                  `json:"cancelled_utc,omitempty"`
}

type VerifyResult struct {
	HookID               string `json:"hook_id"`
	State                string `json:"state"`
	Version              int    `json:"version"`
	Path                 string `json:"path"`
	StructureMatch       bool   `json:"structure_match"`
	CurrentState         string `json:"current_state"`
	CurrentHex           string `json:"current_hex"`
	OriginalHex          string `json:"original_hex"`
	PatchHex             string `json:"patch_hex"`
	MatchesExpectedState bool   `json:"matches_expected_state"`
}

func activeState(state string) bool {
	switch state {
	case StatePlanned, StateApplying, StateApplied, StateRollingBack:
		return true
	default:
		return false
	}
}

func validateOperationID(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 140 {
		return "", errors.New("operation_id must be between 1 and 140 characters")
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '-' || char == '_' || char == '.' || char == ':' {
			continue
		}
		return "", fmt.Errorf("operation_id contains unsupported character %q", char)
	}
	return value, nil
}
