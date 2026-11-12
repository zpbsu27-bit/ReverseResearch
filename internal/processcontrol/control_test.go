package processcontrol

import (
	"errors"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"testing"

	"reverseresearch/internal/targetidentity"
)

type fakeInspector struct {
	mu      sync.Mutex
	current map[uint32]Identity
	err     map[uint32]error
}

func (f *fakeInspector) inspect(pid uint32) (Identity, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.err[pid]; err != nil {
		return Identity{}, err
	}
	value, ok := f.current[pid]
	if !ok {
		return Identity{}, errors.New("process unavailable")
	}
	return value, nil
}

func (f *fakeInspector) set(value Identity) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.current[value.PID] = value
}

func fixtureIdentity(pid uint32, key, sha string) Identity {
	return Identity{
		PID:            pid,
		CreationUTC:    "2026-10-02T00:00:00Z",
		MainModuleBase: 0x400000,
		Key:            key,
		Image: targetidentity.Identity{
			ID:     "sha256:" + sha,
			Path:   "C:\\fixture\\game.exe",
			SHA256: sha,
			Size:   123,
			Format: "pe",
			PE:     &targetidentity.PEIdentity{Bits: 32, Machine: "i386"},
		},
	}
}

func TestLeaseOwnershipIsExclusiveAndIdempotentAcrossStores(t *testing.T) {
	root := t.TempDir()
	current := fixtureIdentity(42, "proc-key-a", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	fake := &fakeInspector{current: map[uint32]Identity{42: current}, err: map[uint32]error{}}
	firstStore, err := newLeaseStore(root, fake.inspect)
	if err != nil {
		t.Fatal(err)
	}
	secondStore, err := newLeaseStore(root, fake.inspect)
	if err != nil {
		t.Fatal(err)
	}

	first, err := firstStore.Acquire(AcquireRequest{Expected: current, Owner: "analysis-a"})
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := secondStore.Acquire(AcquireRequest{Expected: current, Owner: "analysis-a"})
	if err != nil {
		t.Fatal(err)
	}
	if first.LeaseID == "" || replayed.LeaseID != first.LeaseID {
		t.Fatalf("same owner did not get idempotent lease: first=%+v replay=%+v", first, replayed)
	}
	if _, err := secondStore.Acquire(AcquireRequest{Expected: current, Owner: "analysis-b"}); !errors.Is(err, ErrControlled) {
		t.Fatalf("second owner acquired controlled process: %v", err)
	}
	got, err := secondStore.Get(current.PID)
	if err != nil || got.LeaseID != first.LeaseID || got.Owner != "analysis-a" {
		t.Fatalf("get lease=%+v err=%v", got, err)
	}
	if err := secondStore.Release(ReleaseRequest{
		PID: current.PID, ProcessKey: current.Key, Owner: "analysis-b", LeaseID: first.LeaseID,
	}); !errors.Is(err, ErrControlled) {
		t.Fatalf("wrong owner released lease: %v", err)
	}
	if err := firstStore.Release(ReleaseRequest{
		PID: current.PID, ProcessKey: current.Key, Owner: "analysis-a", LeaseID: first.LeaseID,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := secondStore.Get(current.PID); !errors.Is(err, ErrLeaseNotFound) {
		t.Fatalf("released lease still visible: %v", err)
	}
}

func TestAcquireRejectsExpectedIdentityDrift(t *testing.T) {
	root := t.TempDir()
	oldIdentity := fixtureIdentity(77, "old-key", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	newIdentity := fixtureIdentity(77, "new-key", "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	fake := &fakeInspector{current: map[uint32]Identity{77: newIdentity}, err: map[uint32]error{}}
	store, err := newLeaseStore(root, fake.inspect)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Acquire(AcquireRequest{Expected: oldIdentity, Owner: "analysis"}); !errors.Is(err, ErrProcessChanged) {
		t.Fatalf("stale expected identity accepted: %v", err)
	}
}

func TestPIDReuseReplacesOnlyStaleLeaseAndOldOwnerCannotDeleteNewLease(t *testing.T) {
	root := t.TempDir()
	oldIdentity := fixtureIdentity(99, "old-process-instance", "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
	newIdentity := fixtureIdentity(99, "new-process-instance", "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
	fake := &fakeInspector{current: map[uint32]Identity{99: oldIdentity}, err: map[uint32]error{}}
	store, err := newLeaseStore(root, fake.inspect)
	if err != nil {
		t.Fatal(err)
	}
	oldLease, err := store.Acquire(AcquireRequest{Expected: oldIdentity, Owner: "old-owner"})
	if err != nil {
		t.Fatal(err)
	}

	fake.set(newIdentity)
	newLease, err := store.Acquire(AcquireRequest{Expected: newIdentity, Owner: "new-owner"})
	if err != nil {
		t.Fatalf("new process instance blocked by stale lease: %v", err)
	}
	if newLease.ProcessKey != newIdentity.Key || newLease.LeaseID == oldLease.LeaseID {
		t.Fatalf("stale lease was not replaced: old=%+v new=%+v", oldLease, newLease)
	}
	if err := store.Release(ReleaseRequest{
		PID: 99, ProcessKey: oldIdentity.Key, Owner: "old-owner", LeaseID: oldLease.LeaseID,
	}); !errors.Is(err, ErrProcessChanged) {
		t.Fatalf("old owner affected new process lease: %v", err)
	}
	got, err := store.Get(99)
	if err != nil || got.LeaseID != newLease.LeaseID || got.Owner != "new-owner" {
		t.Fatalf("new lease lost: %+v err=%v", got, err)
	}
}

func TestLeaseStoreCoordinatesIndependentProcesses(t *testing.T) {
	if mode := os.Getenv("RR_PROCESS_CONTROL_WORKER"); mode != "" {
		root := os.Getenv("RR_PROCESS_CONTROL_ROOT")
		pid64, err := strconv.ParseUint(os.Getenv("RR_PROCESS_CONTROL_PID"), 10, 32)
		if err != nil {
			t.Fatal(err)
		}
		current, err := Inspect(uint32(pid64))
		if err != nil {
			t.Fatal(err)
		}
		store, err := NewLeaseStore(root)
		if err != nil {
			t.Fatal(err)
		}
		_, err = store.Acquire(AcquireRequest{Expected: current, Owner: os.Getenv("RR_PROCESS_CONTROL_OWNER")})
		switch mode {
		case "same-owner":
			if err != nil {
				t.Fatal(err)
			}
		case "other-owner":
			if !errors.Is(err, ErrControlled) {
				t.Fatalf("other owner should be rejected across process boundary: %v", err)
			}
		default:
			t.Fatalf("unknown worker mode %q", mode)
		}
		return
	}

	root := t.TempDir()
	current, err := Inspect(uint32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	runWorker := func(mode, owner string) {
		t.Helper()
		cmd := exec.Command(exe, "-test.run=^TestLeaseStoreCoordinatesIndependentProcesses$")
		cmd.Env = append(os.Environ(),
			"RR_PROCESS_CONTROL_WORKER="+mode,
			"RR_PROCESS_CONTROL_ROOT="+root,
			"RR_PROCESS_CONTROL_PID="+strconv.FormatUint(uint64(current.PID), 10),
			"RR_PROCESS_CONTROL_OWNER="+owner,
		)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s/%s worker: %v\n%s", mode, owner, err, output)
		}
	}

	const workers = 6
	var wg sync.WaitGroup
	errs := make(chan string, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cmd := exec.Command(exe, "-test.run=^TestLeaseStoreCoordinatesIndependentProcesses$")
			cmd.Env = append(os.Environ(),
				"RR_PROCESS_CONTROL_WORKER=same-owner",
				"RR_PROCESS_CONTROL_ROOT="+root,
				"RR_PROCESS_CONTROL_PID="+strconv.FormatUint(uint64(current.PID), 10),
				"RR_PROCESS_CONTROL_OWNER=shared-owner",
			)
			if output, err := cmd.CombinedOutput(); err != nil {
				errs <- string(output)
				return
			}
			errs <- ""
		}()
	}
	wg.Wait()
	close(errs)
	for output := range errs {
		if output != "" {
			t.Fatalf("same-owner worker failed:\n%s", output)
		}
	}

	store, err := NewLeaseStore(root)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := store.Get(current.PID)
	if err != nil {
		t.Fatal(err)
	}
	if lease.Owner != "shared-owner" || lease.ProcessKey != current.Key {
		t.Fatalf("cross-process lease=%+v", lease)
	}
	runWorker("other-owner", "blocked-owner")
}

func TestStaleReleaseCannotDeleteReacquiredLeaseForSameProcess(t *testing.T) {
	root := t.TempDir()
	identity := fixtureIdentity(321, "same-process", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	fake := &fakeInspector{current: map[uint32]Identity{321: identity}, err: map[uint32]error{}}
	store, err := newLeaseStore(root, fake.inspect)
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.Acquire(AcquireRequest{Expected: identity, Owner: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Release(ReleaseRequest{PID: 321, ProcessKey: identity.Key, Owner: "owner", LeaseID: first.LeaseID}); err != nil {
		t.Fatal(err)
	}
	second, err := store.Acquire(AcquireRequest{Expected: identity, Owner: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	if second.LeaseID == first.LeaseID {
		t.Fatalf("reacquire reused released lease id: %s", second.LeaseID)
	}
	if err := store.Release(ReleaseRequest{PID: 321, ProcessKey: identity.Key, Owner: "owner", LeaseID: first.LeaseID}); !errors.Is(err, ErrLeaseChanged) {
		t.Fatalf("stale release did not fail closed: %v", err)
	}
	got, err := store.Get(321)
	if err != nil || got.LeaseID != second.LeaseID {
		t.Fatalf("stale release affected new lease: got=%+v err=%v", got, err)
	}
}

func TestGetRejectsLeaseAfterCurrentProcessIdentityChanges(t *testing.T) {
	root := t.TempDir()
	identity := fixtureIdentity(123, "stable-before", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	fake := &fakeInspector{current: map[uint32]Identity{123: identity}, err: map[uint32]error{}}
	store, err := newLeaseStore(root, fake.inspect)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Acquire(AcquireRequest{Expected: identity, Owner: "owner"}); err != nil {
		t.Fatal(err)
	}
	changed := identity
	changed.Key = "stable-after"
	fake.set(changed)
	if _, err := store.Get(123); !errors.Is(err, ErrProcessChanged) {
		t.Fatalf("drifted lease reported current: %v", err)
	}
}
