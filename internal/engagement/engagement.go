package engagement

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"reverseresearch/internal/recordio"
)

var safeID = regexp.MustCompile(`^[a-z0-9_-]+$`)

const maxEngagementRecordBytes = int64(1 << 20)

type Status string

const (
	StatusActive Status = "active"
	StatusClosed Status = "closed"
)

type Authorization struct {
	Status       string   `json:"status"`
	Basis        string   `json:"basis,omitempty"`
	EvidenceRefs []string `json:"evidence_refs,omitempty"`
}

type NetworkProfile struct {
	Mode  string `json:"mode"`
	Notes string `json:"notes,omitempty"`
}

type Scope struct {
	Targets         []string          `json:"targets"`
	ExcludedTargets []string          `json:"excluded_targets,omitempty"`
	Surfaces        []string          `json:"surfaces,omitempty"`
	AllowedActions  []string          `json:"allowed_actions"`
	ExcludedActions []string          `json:"excluded_actions,omitempty"`
	Authorization   Authorization     `json:"authorization"`
	NetworkProfile  NetworkProfile    `json:"network_profile"`
	RateLimits      map[string]string `json:"rate_limits,omitempty"`
	CredentialRefs  []string          `json:"credential_refs,omitempty"`
	DataSensitivity string            `json:"data_sensitivity,omitempty"`
	DataHandling    []string          `json:"data_handling,omitempty"`
	Stealth         string            `json:"stealth,omitempty"`
	Deliverables    []string          `json:"deliverables,omitempty"`
	Cleanup         []string          `json:"cleanup_requirements,omitempty"`
	ReportClass     string            `json:"report_classification,omitempty"`
	StartsUTC       string            `json:"starts_utc,omitempty"`
	EndsUTC         string            `json:"ends_utc,omitempty"`
}

type Engagement struct {
	ID           string `json:"id"`
	Organization string `json:"organization"`
	Operator     string `json:"operator"`
	Status       Status `json:"status"`
	Scope        Scope  `json:"scope"`
	CreatedUTC   string `json:"created_utc"`
	UpdatedUTC   string `json:"updated_utc"`
}

type CreateRequest struct {
	Organization string `json:"organization"`
	Operator     string `json:"operator"`
	Scope        Scope  `json:"scope"`
}

type Decision struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

type Store struct{ root string }

func New(root string) (*Store, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("engagement store root is required")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve engagement root: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(absolute, "engagements"), 0o700); err != nil {
		return nil, fmt.Errorf("create engagement store: %w", err)
	}
	return &Store{root: absolute}, nil
}

func (s *Store) Create(request CreateRequest) (Engagement, error) {
	request.Organization = strings.TrimSpace(request.Organization)
	request.Operator = strings.TrimSpace(request.Operator)
	if request.Organization == "" || request.Operator == "" {
		return Engagement{}, errors.New("organization and operator are required")
	}
	request.Scope = normalizeScope(request.Scope)
	if err := validateScope(request.Scope); err != nil {
		return Engagement{}, err
	}
	id, err := newID("eng")
	if err != nil {
		return Engagement{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	value := Engagement{
		ID: id, Organization: request.Organization, Operator: request.Operator,
		Status: StatusActive, Scope: request.Scope, CreatedUTC: now, UpdatedUTC: now,
	}
	if err := s.save(value); err != nil {
		return Engagement{}, err
	}
	return value, nil
}

func (s *Store) Get(id string) (Engagement, error) {
	if err := validateID(id); err != nil {
		return Engagement{}, err
	}
	body, err := recordio.ReadFileLimit(s.path(id), maxEngagementRecordBytes)
	if err != nil {
		return Engagement{}, err
	}
	var value Engagement
	if err := json.Unmarshal(body, &value); err != nil {
		return Engagement{}, err
	}
	if value.ID != id {
		return Engagement{}, errors.New("engagement identity mismatch")
	}
	return value, nil
}

func (s *Store) Authorize(id, target, action string, at time.Time) (Decision, error) {
	return s.AuthorizeEffect(id, target, action, "observation", at)
}

func (s *Store) AuthorizeEffect(id, target, action, effectClass string, at time.Time) (Decision, error) {
	value, err := s.Get(id)
	if err != nil {
		return Decision{}, err
	}
	if value.Status != StatusActive {
		return Decision{Reason: "engagement is not active"}, nil
	}
	if value.Scope.Authorization.Status != "granted" {
		return Decision{Reason: "engagement authorization is not granted"}, nil
	}
	target = strings.TrimSpace(target)
	action = strings.TrimSpace(action)
	effectClass = strings.ToLower(strings.TrimSpace(effectClass))
	if target == "" || action == "" {
		return Decision{Reason: "target and action are required"}, nil
	}
	if !withinWindow(value.Scope, at.UTC()) {
		return Decision{Reason: "outside engagement time window"}, nil
	}
	if contains(value.Scope.ExcludedTargets, target) {
		return Decision{Reason: "target is explicitly excluded"}, nil
	}
	if !contains(value.Scope.Targets, target) {
		return Decision{Reason: "target is outside scope"}, nil
	}
	if contains(value.Scope.ExcludedActions, action) {
		return Decision{Reason: "action is explicitly excluded"}, nil
	}
	if !contains(value.Scope.AllowedActions, action) {
		return Decision{Reason: "action is not allowed"}, nil
	}
	if effectClass == "active network interaction" && value.Scope.NetworkProfile.Mode == "offline" {
		return Decision{Reason: "offline network profile forbids active network interaction"}, nil
	}
	return Decision{Allowed: true, Reason: "scope allows target, action, effect, and current authorization"}, nil
}

func validateScope(scope Scope) error {
	if len(scope.Targets) == 0 {
		return errors.New("scope targets must not be empty")
	}
	if len(scope.AllowedActions) == 0 {
		return errors.New("scope allowed_actions must not be empty")
	}
	switch scope.Authorization.Status {
	case "granted", "pending", "denied":
	default:
		return errors.New("authorization.status must be granted, pending, or denied")
	}
	switch scope.NetworkProfile.Mode {
	case "offline", "lab_only", "authorized_target_only", "unrestricted_lab":
	default:
		return errors.New("network_profile.mode must be offline, lab_only, authorized_target_only, or unrestricted_lab")
	}
	switch scope.Stealth {
	case "", "low", "medium", "high":
	default:
		return errors.New("stealth must be low, medium, or high")
	}
	if scope.StartsUTC != "" {
		if _, err := time.Parse(time.RFC3339, scope.StartsUTC); err != nil {
			return fmt.Errorf("invalid starts_utc: %w", err)
		}
	}
	if scope.EndsUTC != "" {
		if _, err := time.Parse(time.RFC3339, scope.EndsUTC); err != nil {
			return fmt.Errorf("invalid ends_utc: %w", err)
		}
	}
	if scope.StartsUTC != "" && scope.EndsUTC != "" {
		start, _ := time.Parse(time.RFC3339, scope.StartsUTC)
		end, _ := time.Parse(time.RFC3339, scope.EndsUTC)
		if !end.After(start) {
			return errors.New("scope ends_utc must be after starts_utc")
		}
	}
	for _, excluded := range scope.ExcludedTargets {
		if contains(scope.Targets, excluded) {
			return fmt.Errorf("target %q cannot be both allowed and excluded", excluded)
		}
	}
	for _, excluded := range scope.ExcludedActions {
		if contains(scope.AllowedActions, excluded) {
			return fmt.Errorf("action %q cannot be both allowed and excluded", excluded)
		}
	}
	return nil
}

func normalizeScope(scope Scope) Scope {
	scope.Targets = cleanUnique(scope.Targets)
	scope.ExcludedTargets = cleanUnique(scope.ExcludedTargets)
	scope.Surfaces = cleanUnique(scope.Surfaces)
	scope.AllowedActions = cleanUnique(scope.AllowedActions)
	scope.ExcludedActions = cleanUnique(scope.ExcludedActions)
	scope.Authorization.Status = strings.ToLower(strings.TrimSpace(scope.Authorization.Status))
	scope.Authorization.Basis = strings.TrimSpace(scope.Authorization.Basis)
	scope.Authorization.EvidenceRefs = cleanUnique(scope.Authorization.EvidenceRefs)
	scope.NetworkProfile.Mode = strings.ToLower(strings.TrimSpace(scope.NetworkProfile.Mode))
	scope.NetworkProfile.Notes = strings.TrimSpace(scope.NetworkProfile.Notes)
	scope.CredentialRefs = cleanUnique(scope.CredentialRefs)
	scope.DataSensitivity = strings.TrimSpace(scope.DataSensitivity)
	scope.DataHandling = cleanUnique(scope.DataHandling)
	scope.Stealth = strings.ToLower(strings.TrimSpace(scope.Stealth))
	scope.Deliverables = cleanUnique(scope.Deliverables)
	scope.Cleanup = cleanUnique(scope.Cleanup)
	scope.ReportClass = strings.TrimSpace(scope.ReportClass)
	scope.StartsUTC = strings.TrimSpace(scope.StartsUTC)
	scope.EndsUTC = strings.TrimSpace(scope.EndsUTC)
	return scope
}

func withinWindow(scope Scope, at time.Time) bool {
	if scope.StartsUTC != "" {
		start, err := time.Parse(time.RFC3339, scope.StartsUTC)
		if err != nil || at.Before(start) {
			return false
		}
	}
	if scope.EndsUTC != "" {
		end, err := time.Parse(time.RFC3339, scope.EndsUTC)
		if err != nil || at.After(end) {
			return false
		}
	}
	return true
}

func contains(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func cleanUnique(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

func (s *Store) path(id string) string { return filepath.Join(s.root, "engagements", id+".json") }

func (s *Store) save(value Engagement) error {
	if err := validateID(value.ID); err != nil {
		return err
	}
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if int64(len(body)) > maxEngagementRecordBytes {
		return fmt.Errorf("engagement record exceeds durable size limit: %d > %d", len(body), maxEngagementRecordBytes)
	}
	return recordio.WriteFile(s.path(value.ID), body, 0o600)
}

func validateID(id string) error {
	if len(id) > 128 || !safeID.MatchString(id) || strings.Contains(id, "..") {
		return fmt.Errorf("invalid engagement id %q", id)
	}
	return nil
}

func newID(prefix string) (string, error) {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return prefix + "_" + hex.EncodeToString(raw[:]), nil
}
