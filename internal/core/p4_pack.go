package core

import (
	"errors"
	"strings"

	"reverseresearch/internal/packregistry"
	"reverseresearch/internal/rbac"
)

type PackLifecycleRequest struct {
	AuthorityRole    string `json:"authority_role"`
	ExpectedRevision string `json:"expected_revision"`
	ReceiptID        string `json:"receipt_id,omitempty"`
	PackID           string `json:"pack_id,omitempty"`
	TargetReceiptID  string `json:"target_receipt_id,omitempty"`
	Reason           string `json:"reason,omitempty"`
}

type PackActiveRequest struct {
	AuthorityRole string `json:"authority_role"`
	PackID        string `json:"pack_id"`
}

type PackEntrypointReadRequest struct {
	AuthorityRole string `json:"authority_role"`
	PackID        string `json:"pack_id"`
	Entrypoint    string `json:"entrypoint"`
	MaxBytes      int    `json:"max_bytes,omitempty"`
}

func (s *Service) ActivateVerifiedPack(request PackLifecycleRequest) (packregistry.RegistryState, packregistry.PackRecord, error) {
	if err := requirePackRole(request.AuthorityRole, rbac.ActionRegistryManage); err != nil {
		return packregistry.RegistryState{}, packregistry.PackRecord{}, err
	}
	store, err := s.packRegistryStore()
	if err != nil {
		return packregistry.RegistryState{}, packregistry.PackRecord{}, err
	}
	return store.Activate(strings.TrimSpace(request.ExpectedRevision), strings.TrimSpace(request.ReceiptID))
}

func (s *Service) QuarantineVerifiedPack(request PackLifecycleRequest) (packregistry.RegistryState, packregistry.PackRecord, error) {
	if err := requirePackRole(request.AuthorityRole, rbac.ActionRegistryManage); err != nil {
		return packregistry.RegistryState{}, packregistry.PackRecord{}, err
	}
	store, err := s.packRegistryStore()
	if err != nil {
		return packregistry.RegistryState{}, packregistry.PackRecord{}, err
	}
	return store.Quarantine(strings.TrimSpace(request.ExpectedRevision), strings.TrimSpace(request.ReceiptID), strings.TrimSpace(request.Reason))
}

func (s *Service) RollbackVerifiedPack(request PackLifecycleRequest) (packregistry.RegistryState, packregistry.PackRecord, error) {
	if err := requirePackRole(request.AuthorityRole, rbac.ActionRegistryManage); err != nil {
		return packregistry.RegistryState{}, packregistry.PackRecord{}, err
	}
	store, err := s.packRegistryStore()
	if err != nil {
		return packregistry.RegistryState{}, packregistry.PackRecord{}, err
	}
	return store.Rollback(strings.TrimSpace(request.ExpectedRevision), strings.TrimSpace(request.PackID), strings.TrimSpace(request.TargetReceiptID))
}

func (s *Service) GetActivePack(request PackActiveRequest) (packregistry.RegistryState, packregistry.PackRecord, error) {
	if err := requirePackRole(request.AuthorityRole, rbac.ActionRegistryRead); err != nil {
		return packregistry.RegistryState{}, packregistry.PackRecord{}, err
	}
	store, err := s.packRegistryStore()
	if err != nil {
		return packregistry.RegistryState{}, packregistry.PackRecord{}, err
	}
	return store.ResolveActive(strings.TrimSpace(request.PackID))
}

func (s *Service) ReadActivePackEntrypoint(request PackEntrypointReadRequest) (packregistry.ActiveEntrypoint, error) {
	if err := requirePackRole(request.AuthorityRole, rbac.ActionRegistryRead); err != nil {
		return packregistry.ActiveEntrypoint{}, err
	}
	if strings.TrimSpace(request.PackID) == "" || strings.TrimSpace(request.Entrypoint) == "" {
		return packregistry.ActiveEntrypoint{}, errors.New("pack_id and entrypoint are required")
	}
	store, err := s.packRegistryStore()
	if err != nil {
		return packregistry.ActiveEntrypoint{}, err
	}
	return store.ReadActiveEntrypoint(strings.TrimSpace(request.PackID), strings.TrimSpace(request.Entrypoint), request.MaxBytes)
}

func requirePackRole(value string, action rbac.Action) error {
	role, err := rbac.NormalizeRole(value)
	if err != nil {
		return err
	}
	return rbac.Require(role, action)
}
