package processcontrol

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"reverseresearch/internal/recordio"
)

type inspectFunc func(uint32) (Identity, error)

const maxProcessLeaseBytes = int64(64 << 10)

type LeaseStore struct {
	root    string
	inspect inspectFunc
}

type AcquireRequest struct {
	Expected Identity `json:"expected"`
	Owner    string   `json:"owner"`
}

type ReleaseRequest struct {
	PID        uint32 `json:"pid"`
	ProcessKey string `json:"process_key"`
	Owner      string `json:"owner"`
	LeaseID    string `json:"lease_id"`
}

type Lease struct {
	LeaseID     string   `json:"lease_id"`
	PID         uint32   `json:"pid"`
	ProcessKey  string   `json:"process_key"`
	Owner       string   `json:"owner"`
	Identity    Identity `json:"identity"`
	AcquiredUTC string   `json:"acquired_utc"`
}

func NewLeaseStore(root string) (*LeaseStore, error) {
	return newLeaseStore(root, Inspect)
}

func newLeaseStore(root string, inspect inspectFunc) (*LeaseStore, error) {
	if inspect == nil {
		return nil, errors.New("process inspector is required")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(absolute, 0o700); err != nil {
		return nil, err
	}
	return &LeaseStore{root: absolute, inspect: inspect}, nil
}

func (s *LeaseStore) Acquire(request AcquireRequest) (result Lease, err error) {
	owner, err := validateOwner(request.Owner)
	if err != nil {
		return Lease{}, err
	}
	if request.Expected.PID == 0 || strings.TrimSpace(request.Expected.Key) == "" {
		return Lease{}, errors.New("expected process identity requires pid and key")
	}
	release, err := recordio.Acquire(s.lockPath(request.Expected.PID), 10*time.Second)
	if err != nil {
		return Lease{}, err
	}
	defer func() { err = errors.Join(err, release()) }()

	current, err := s.inspect(request.Expected.PID)
	if err != nil {
		return Lease{}, fmt.Errorf("%w: %v", ErrProcessChanged, err)
	}
	if !SameInstance(request.Expected, current) {
		return Lease{}, fmt.Errorf("%w: expected %s current %s", ErrProcessChanged, request.Expected.Key, current.Key)
	}

	existing, loadErr := s.load(request.Expected.PID)
	switch {
	case loadErr == nil && existing.ProcessKey == current.Key:
		if existing.Owner != owner {
			return Lease{}, fmt.Errorf("%w: owner %q holds lease %s", ErrControlled, existing.Owner, existing.LeaseID)
		}
		return existing, nil
	case loadErr == nil:
		// Same PID now identifies a different process instance. The persisted
		// lease is stale and must not block the freshly inspected instance.
	case errors.Is(loadErr, os.ErrNotExist), errors.Is(loadErr, ErrLeaseNotFound):
	default:
		return Lease{}, loadErr
	}

	leaseID, err := newLeaseID()
	if err != nil {
		return Lease{}, err
	}
	value := Lease{
		LeaseID:     leaseID,
		PID:         current.PID,
		ProcessKey:  current.Key,
		Owner:       owner,
		Identity:    current,
		AcquiredUTC: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := s.save(value); err != nil {
		return Lease{}, err
	}
	return value, nil
}

func (s *LeaseStore) Get(pid uint32) (result Lease, err error) {
	if pid == 0 {
		return Lease{}, errors.New("pid is required")
	}
	release, err := recordio.Acquire(s.lockPath(pid), 10*time.Second)
	if err != nil {
		return Lease{}, err
	}
	defer func() { err = errors.Join(err, release()) }()

	lease, err := s.load(pid)
	if err != nil {
		return Lease{}, err
	}
	current, inspectErr := s.inspect(pid)
	if inspectErr != nil {
		return Lease{}, fmt.Errorf("%w: %v", ErrProcessChanged, inspectErr)
	}
	if !SameInstance(lease.Identity, current) || lease.ProcessKey != current.Key {
		return Lease{}, fmt.Errorf("%w: lease %s belongs to %s, current is %s", ErrProcessChanged, lease.LeaseID, lease.ProcessKey, current.Key)
	}
	return lease, nil
}

func (s *LeaseStore) Release(request ReleaseRequest) (err error) {
	owner, err := validateOwner(request.Owner)
	if err != nil {
		return err
	}
	if request.PID == 0 || strings.TrimSpace(request.ProcessKey) == "" || strings.TrimSpace(request.LeaseID) == "" {
		return errors.New("pid, process_key, and lease_id are required")
	}
	release, err := recordio.Acquire(s.lockPath(request.PID), 10*time.Second)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, release()) }()

	lease, err := s.load(request.PID)
	if err != nil {
		return err
	}
	if lease.ProcessKey != request.ProcessKey {
		return fmt.Errorf("%w: lease belongs to process %s, request used %s", ErrProcessChanged, lease.ProcessKey, request.ProcessKey)
	}
	if lease.LeaseID != strings.TrimSpace(request.LeaseID) {
		return fmt.Errorf("%w: current lease is %s", ErrLeaseChanged, lease.LeaseID)
	}
	if lease.Owner != owner {
		return fmt.Errorf("%w: owner %q holds lease %s", ErrControlled, lease.Owner, lease.LeaseID)
	}
	if err := os.Remove(s.leasePath(request.PID)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrLeaseNotFound
		}
		return err
	}
	return nil
}

func (s *LeaseStore) leasePath(pid uint32) string {
	return filepath.Join(s.root, fmt.Sprintf("pid-%d.json", pid))
}

func (s *LeaseStore) lockPath(pid uint32) string {
	return filepath.Join(s.root, fmt.Sprintf(".pid-%d.lock", pid))
}

func (s *LeaseStore) load(pid uint32) (Lease, error) {
	path := s.leasePath(pid)
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Lease{}, ErrLeaseNotFound
		}
		return Lease{}, err
	}
	if !info.Mode().IsRegular() {
		return Lease{}, errors.New("process lease record must be a regular file")
	}
	body, err := recordio.ReadFileLimit(path, maxProcessLeaseBytes)
	if err != nil {
		return Lease{}, err
	}
	var lease Lease
	if err := json.Unmarshal(body, &lease); err != nil {
		return Lease{}, fmt.Errorf("decode process lease: %w", err)
	}
	if lease.PID != pid || lease.LeaseID == "" || lease.ProcessKey == "" || lease.Owner == "" {
		return Lease{}, errors.New("invalid process lease record")
	}
	if lease.Identity.PID != pid || lease.Identity.Key != lease.ProcessKey {
		return Lease{}, errors.New("process lease identity mismatch")
	}
	return lease, nil
}

func (s *LeaseStore) save(lease Lease) error {
	body, err := json.MarshalIndent(lease, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if int64(len(body)) > maxProcessLeaseBytes {
		return fmt.Errorf("process lease exceeds durable size limit: %d > %d", len(body), maxProcessLeaseBytes)
	}
	return recordio.WriteFile(s.leasePath(lease.PID), body, 0o600)
}

func validateOwner(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("control owner is required")
	}
	if len(value) > 160 || !utf8.ValidString(value) || strings.ContainsRune(value, 0) {
		return "", errors.New("control owner must be valid UTF-8 without NUL and at most 160 bytes")
	}
	return value, nil
}

func newLeaseID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "lease_" + hex.EncodeToString(raw[:]), nil
}
