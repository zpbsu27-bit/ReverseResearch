package core

import (
	"path/filepath"

	"reverseresearch/internal/domainpack"
)

func (s *Service) GetDomainPack(id string) (domainpack.Pack, error) {
	registry, err := domainpack.Load(s.root, filepath.Join(s.root, "config", "domain-packs.json"))
	if err != nil {
		return domainpack.Pack{}, err
	}
	return registry.Get(id)
}

func (s *Service) DomainPackForRoute(routeID string) (domainpack.Pack, bool, error) {
	registry, err := domainpack.Load(s.root, filepath.Join(s.root, "config", "domain-packs.json"))
	if err != nil {
		return domainpack.Pack{}, false, err
	}
	value, ok := registry.ForRoute(routeID)
	return value, ok, nil
}

func (s *Service) ListDomainPacks() ([]domainpack.Pack, error) {
	registry, err := domainpack.Load(s.root, filepath.Join(s.root, "config", "domain-packs.json"))
	if err != nil {
		return nil, err
	}
	return registry.List(), nil
}

func (s *Service) AuditDomainPack(id string) (domainpack.Audit, error) {
	registry, err := domainpack.Load(s.root, filepath.Join(s.root, "config", "domain-packs.json"))
	if err != nil {
		return domainpack.Audit{}, err
	}
	pack, err := registry.Get(id)
	if err != nil {
		return domainpack.Audit{}, err
	}
	return domainpack.AuditPack(s.root, pack)
}
