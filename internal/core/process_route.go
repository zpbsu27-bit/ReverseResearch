package core

import (
	"reverseresearch/internal/debugroute"
	"reverseresearch/internal/processcontrol"
)

type ProcessDebugRoute struct {
	PID             uint32 `json:"pid"`
	ProcessKey      string `json:"process_key"`
	Executable      string `json:"executable"`
	Format          string `json:"format"`
	Machine         string `json:"machine"`
	Bits            int    `json:"bits"`
	Architecture    string `json:"architecture"`
	Backend         string `json:"backend"`
	PublicModule    string `json:"public_module"`
	AttachPerformed bool   `json:"attach_performed"`
}

func (s *Service) DebugRouteProcess(pid uint32) (ProcessDebugRoute, error) {
	identity, err := s.InspectProcess(pid)
	if err != nil {
		return ProcessDebugRoute{}, err
	}
	return debugRouteForIdentity(identity)
}

func debugRouteForIdentity(identity processcontrol.Identity) (ProcessDebugRoute, error) {
	route, err := debugroute.ForImage(identity.Image)
	if err != nil {
		return ProcessDebugRoute{}, err
	}
	machine := ""
	if identity.Image.PE != nil {
		machine = identity.Image.PE.Machine
	}
	return ProcessDebugRoute{
		PID:             identity.PID,
		ProcessKey:      identity.Key,
		Executable:      identity.Image.Path,
		Format:          identity.Image.Format,
		Machine:         machine,
		Bits:            route.Bits,
		Architecture:    route.Architecture,
		Backend:         route.Backend,
		PublicModule:    route.PublicModule,
		AttachPerformed: false,
	}, nil
}
