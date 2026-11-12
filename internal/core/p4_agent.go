package core

import (
	"context"
	"errors"
	"strings"
	"time"

	"reverseresearch/internal/rbac"
	"reverseresearch/internal/remoteagent"
)

const (
	defaultAgentStatusTimeoutSeconds = 10
	maxAgentStatusTimeoutSeconds     = 30
	defaultAgentStaleAfterSeconds    = 120
	defaultAgentOfflineAfterSeconds  = 600
	maxAgentFleetThresholdSeconds    = 86400
)

type RemoteAgentStatusRefreshRequest struct {
	AgentID          string `json:"agent_id"`
	Endpoint         string `json:"endpoint"`
	ClientCertPath   string `json:"client_cert_path"`
	ClientKeyPath    string `json:"client_key_path"`
	ServerCAPath     string `json:"server_ca_path"`
	ExpectedRevision string `json:"expected_revision,omitempty"`
	AuthorityRole    string `json:"authority_role"`
	TimeoutSeconds   int    `json:"timeout_seconds,omitempty"`
}

type RemoteAgentFleetRequest struct {
	StaleAfterSeconds   int `json:"stale_after_seconds,omitempty"`
	OfflineAfterSeconds int `json:"offline_after_seconds,omitempty"`
}

func (s *Service) RefreshRemoteAgentStatus(request RemoteAgentStatusRefreshRequest) (remoteagent.StatusRecord, error) {
	return s.RefreshRemoteAgentStatusContext(context.Background(), request)
}

func (s *Service) RefreshRemoteAgentStatusContext(ctx context.Context, request RemoteAgentStatusRefreshRequest) (remoteagent.StatusRecord, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	role, err := rbac.NormalizeRole(request.AuthorityRole)
	if err != nil {
		return remoteagent.StatusRecord{}, err
	}
	if err := rbac.Require(role, rbac.ActionAgentManage); err != nil {
		return remoteagent.StatusRecord{}, err
	}
	request.AgentID = strings.TrimSpace(request.AgentID)
	request.Endpoint = strings.TrimSpace(request.Endpoint)
	request.ClientCertPath = strings.TrimSpace(request.ClientCertPath)
	request.ClientKeyPath = strings.TrimSpace(request.ClientKeyPath)
	request.ServerCAPath = strings.TrimSpace(request.ServerCAPath)
	request.ExpectedRevision = strings.TrimSpace(request.ExpectedRevision)
	if request.AgentID == "" || request.Endpoint == "" || request.ClientCertPath == "" || request.ClientKeyPath == "" || request.ServerCAPath == "" {
		return remoteagent.StatusRecord{}, errors.New("agent_id, endpoint, client_cert_path, client_key_path, and server_ca_path are required")
	}
	if request.TimeoutSeconds == 0 {
		request.TimeoutSeconds = defaultAgentStatusTimeoutSeconds
	}
	if request.TimeoutSeconds < 1 || request.TimeoutSeconds > maxAgentStatusTimeoutSeconds {
		return remoteagent.StatusRecord{}, errors.New("timeout_seconds must be between 1 and 30")
	}
	store, err := s.remoteAgentStore()
	if err != nil {
		return remoteagent.StatusRecord{}, err
	}
	registration, err := store.Get(request.AgentID)
	if err != nil {
		return remoteagent.StatusRecord{}, err
	}
	tlsConfig, clientSHA, err := remoteagent.LoadClientTLSConfig(request.ClientCertPath, request.ClientKeyPath, request.ServerCAPath)
	if err != nil {
		return remoteagent.StatusRecord{}, err
	}
	requestCtx, cancel := context.WithTimeout(ctx, time.Duration(request.TimeoutSeconds)*time.Second)
	defer cancel()
	status, observation, err := remoteagent.FetchStatus(requestCtx, request.Endpoint, tlsConfig, clientSHA)
	if err != nil {
		return remoteagent.StatusRecord{}, err
	}
	if status.AgentID != registration.Manifest.AgentID {
		return remoteagent.StatusRecord{}, errors.New("status endpoint returned a different agent identity")
	}
	return store.RecordStatus(status, observation, request.ExpectedRevision)
}

func (s *Service) GetRemoteAgentStatus(agentID string) (remoteagent.StatusRecord, error) {
	store, err := s.remoteAgentStore()
	if err != nil {
		return remoteagent.StatusRecord{}, err
	}
	return store.GetStatus(agentID)
}

func (s *Service) ListRemoteAgentFleet(request RemoteAgentFleetRequest) ([]remoteagent.FleetEntry, error) {
	staleAfter, offlineAfter, err := normalizeFleetThresholds(request)
	if err != nil {
		return nil, err
	}
	store, err := s.remoteAgentStore()
	if err != nil {
		return nil, err
	}
	return store.ListFleet(time.Now().UTC(), staleAfter, offlineAfter)
}

func normalizeFleetThresholds(request RemoteAgentFleetRequest) (time.Duration, time.Duration, error) {
	staleSeconds := request.StaleAfterSeconds
	offlineSeconds := request.OfflineAfterSeconds
	if staleSeconds == 0 {
		staleSeconds = defaultAgentStaleAfterSeconds
	}
	if offlineSeconds == 0 {
		offlineSeconds = defaultAgentOfflineAfterSeconds
	}
	if staleSeconds < 1 || offlineSeconds <= staleSeconds || offlineSeconds > maxAgentFleetThresholdSeconds {
		return 0, 0, errors.New("fleet thresholds require 0 < stale_after_seconds < offline_after_seconds <= 86400")
	}
	return time.Duration(staleSeconds) * time.Second, time.Duration(offlineSeconds) * time.Second, nil
}
