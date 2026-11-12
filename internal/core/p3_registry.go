package core

import (
	"errors"
	"path/filepath"
	"strings"

	"reverseresearch/internal/packregistry"
	"reverseresearch/internal/rbac"
	"reverseresearch/internal/targetidentity"
)

type PackRegistryTrustRequest struct {
	AuthorityRole    string `json:"authority_role"`
	ExpectedRevision string `json:"expected_revision,omitempty"`
	KeyID            string `json:"key_id"`
	PublicKey        string `json:"public_key"`
	Publisher        string `json:"publisher"`
}
type PackRegistryRemoveRequest struct {
	AuthorityRole    string `json:"authority_role"`
	ExpectedRevision string `json:"expected_revision"`
	KeyID            string `json:"key_id"`
}
type PackRegistryGetRequest struct {
	AuthorityRole   string `json:"authority_role"`
	IncludeArchived bool   `json:"include_archived,omitempty"`
}
type PackRegistryVerifyRequest struct {
	AuthorityRole    string `json:"authority_role"`
	ExpectedRevision string `json:"expected_revision"`
	Root             string `json:"root"`
	ManifestPath     string `json:"manifest_path"`
}
type PackRegistryVerifyResult struct {
	ManifestSource targetidentity.Identity    `json:"manifest_source"`
	State          packregistry.RegistryState `json:"state"`
	Receipt        packregistry.Receipt       `json:"receipt"`
}

func (s *Service) packRegistryStore() (*packregistry.Registry, error) {
	return packregistry.NewRegistry(filepath.Join(s.root, "state", "pack-registry"))
}
func (s *Service) GetPackRegistry(request PackRegistryGetRequest) (packregistry.RegistryState, error) {
	role, err := rbac.NormalizeRole(request.AuthorityRole)
	if err != nil {
		return packregistry.RegistryState{}, err
	}
	if err := rbac.Require(role, rbac.ActionRegistryRead); err != nil {
		return packregistry.RegistryState{}, err
	}
	store, err := s.packRegistryStore()
	if err != nil {
		return packregistry.RegistryState{}, err
	}
	if request.IncludeArchived {
		return store.Get()
	}
	return store.GetHot()
}
func (s *Service) TrustPackPublisher(request PackRegistryTrustRequest) (packregistry.RegistryState, error) {
	role, err := rbac.NormalizeRole(request.AuthorityRole)
	if err != nil {
		return packregistry.RegistryState{}, err
	}
	if err := rbac.Require(role, rbac.ActionRegistryManage); err != nil {
		return packregistry.RegistryState{}, err
	}
	if strings.TrimSpace(request.KeyID) == "" || strings.TrimSpace(request.PublicKey) == "" || strings.TrimSpace(request.Publisher) == "" {
		return packregistry.RegistryState{}, errors.New("key_id, public_key, and publisher are required")
	}
	store, err := s.packRegistryStore()
	if err != nil {
		return packregistry.RegistryState{}, err
	}
	return store.TrustKey(request.ExpectedRevision, request.KeyID, request.PublicKey, request.Publisher)
}
func (s *Service) RemoveTrustedPackPublisher(request PackRegistryRemoveRequest) (packregistry.RegistryState, error) {
	role, err := rbac.NormalizeRole(request.AuthorityRole)
	if err != nil {
		return packregistry.RegistryState{}, err
	}
	if err := rbac.Require(role, rbac.ActionRegistryManage); err != nil {
		return packregistry.RegistryState{}, err
	}
	store, err := s.packRegistryStore()
	if err != nil {
		return packregistry.RegistryState{}, err
	}
	return store.RemoveKey(request.ExpectedRevision, request.KeyID)
}
func (s *Service) VerifyAndRecordPack(request PackRegistryVerifyRequest) (PackRegistryVerifyResult, error) {
	role, err := rbac.NormalizeRole(request.AuthorityRole)
	if err != nil {
		return PackRegistryVerifyResult{}, err
	}
	if err := rbac.Require(role, rbac.ActionRegistryRead); err != nil {
		return PackRegistryVerifyResult{}, err
	}
	var manifest packregistry.Manifest
	source, err := readStableJSON(request.ManifestPath, 4<<20, &manifest)
	if err != nil {
		return PackRegistryVerifyResult{}, err
	}
	store, err := s.packRegistryStore()
	if err != nil {
		return PackRegistryVerifyResult{}, err
	}
	state, receipt, err := store.VerifyAndRecord(request.Root, manifest, source.SHA256, request.ExpectedRevision)
	if err != nil {
		return PackRegistryVerifyResult{}, err
	}
	return PackRegistryVerifyResult{ManifestSource: source, State: state, Receipt: receipt}, nil
}
