package job

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"reverseresearch/internal/engagement"
	"reverseresearch/internal/recordio"
)

func newScopedStore(t *testing.T) (*Store, engagement.Engagement) {
	t.Helper()
	root := t.TempDir()
	engagements, err := engagement.New(root)
	if err != nil {
		t.Fatal(err)
	}
	eng, err := engagements.Create(engagement.CreateRequest{
		Organization: "Lab",
		Operator:     "alice",
		Scope: engagement.Scope{
			Targets:        []string{"host-a"},
			AllowedActions: []string{"observe", "patch", "scan"},
			Authorization:  engagement.Authorization{Status: "granted", Basis: "lab_only"},
			NetworkProfile: engagement.NetworkProfile{Mode: "authorized_target_only"},
			StartsUTC:      time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
			EndsUTC:        time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	jobs, err := New(root, engagements)
	if err != nil {
		t.Fatal(err)
	}
	return jobs, eng
}

func TestJobLifecycleAndIdempotentPlan(t *testing.T) {
	store, eng := newScopedStore(t)
	request := PlanRequest{
		OperationID:   "job-op-1",
		EngagementID:  eng.ID,
		Target:        "host-a",
		Action:        "patch",
		EffectClass:   "local mutation",
		InputRevision: "sha256:abc",
	}
	planned, err := store.Plan(request)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := store.Plan(request)
	if err != nil {
		t.Fatal(err)
	}
	if replay.ID != planned.ID || replay.State != StatePlanned {
		t.Fatalf("replay=%+v planned=%+v", replay, planned)
	}
	prepared, err := store.Prepare(planned.ID, planned.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.State != StatePrepared || prepared.PreparedUTC == "" {
		t.Fatalf("prepared=%+v", prepared)
	}
	running, err := store.Transition(TransitionRequest{JobID: planned.ID, OperationID: planned.OperationID, To: StateRunning})
	if err != nil {
		t.Fatal(err)
	}
	applied, err := store.Transition(TransitionRequest{
		JobID: planned.ID, OperationID: planned.OperationID, To: StateApplied,
		ResultIdentity: "sha256:def", CleanupState: "verified",
	})
	if err != nil {
		t.Fatal(err)
	}
	if running.State != StateRunning || applied.State != StateApplied || applied.ResultIdentity != "sha256:def" {
		t.Fatalf("running=%+v applied=%+v", running, applied)
	}
	rolled, err := store.Transition(TransitionRequest{JobID: planned.ID, OperationID: planned.OperationID, To: StateRolledBack})
	if err != nil {
		t.Fatal(err)
	}
	if rolled.State != StateRolledBack {
		t.Fatalf("rolled=%+v", rolled)
	}
}

func TestJobOperationIDConflictAndScopeDenial(t *testing.T) {
	store, eng := newScopedStore(t)
	first, err := store.Plan(PlanRequest{
		OperationID: "job-op-shared", EngagementID: eng.ID, Target: "host-a", Action: "observe", EffectClass: "observation",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Plan(PlanRequest{
		OperationID: "job-op-shared", EngagementID: eng.ID, Target: "host-a", Action: "patch", EffectClass: "local mutation",
	})
	if err == nil || !strings.Contains(err.Error(), "different job request") {
		t.Fatalf("conflict err=%v", err)
	}
	outside, err := store.Plan(PlanRequest{
		OperationID: "job-op-outside", EngagementID: eng.ID, Target: "host-b", Action: "observe", EffectClass: "observation",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Prepare(outside.ID, outside.OperationID); err == nil || !strings.Contains(err.Error(), "scope denied") {
		t.Fatalf("scope err=%v", err)
	}
	if got, err := store.Get(first.ID); err != nil || got.State != StatePlanned {
		t.Fatalf("got=%+v err=%v", got, err)
	}
}

func TestUncertainJobCannotBeReplayedForward(t *testing.T) {
	store, eng := newScopedStore(t)
	planned, err := store.Plan(PlanRequest{
		OperationID: "job-op-uncertain", EngagementID: eng.ID, Target: "host-a", Action: "patch", EffectClass: "local mutation",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Prepare(planned.ID, planned.OperationID); err != nil {
		t.Fatal(err)
	}
	uncertain, err := store.Transition(TransitionRequest{
		JobID: planned.ID, OperationID: planned.OperationID, To: StateUncertain, Failure: "transport lost after effect start",
	})
	if err != nil {
		t.Fatal(err)
	}
	if uncertain.State != StateUncertain {
		t.Fatalf("uncertain=%+v", uncertain)
	}
	if _, err := store.Transition(TransitionRequest{JobID: planned.ID, OperationID: planned.OperationID, To: StateRunning}); err == nil || !strings.Contains(err.Error(), "cannot be automatically replayed") {
		t.Fatalf("err=%v", err)
	}
}

func TestOfflineNetworkProfileBlocksActiveInteraction(t *testing.T) {
	root := t.TempDir()
	engagements, err := engagement.New(root)
	if err != nil {
		t.Fatal(err)
	}
	eng, err := engagements.Create(engagement.CreateRequest{
		Organization: "Lab", Operator: "alice",
		Scope: engagement.Scope{
			Targets: []string{"host-a"}, AllowedActions: []string{"scan"},
			Authorization:  engagement.Authorization{Status: "granted", Basis: "lab_only"},
			NetworkProfile: engagement.NetworkProfile{Mode: "offline"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	jobs, err := New(root, engagements)
	if err != nil {
		t.Fatal(err)
	}
	planned, err := jobs.Plan(PlanRequest{
		OperationID: "job-op-offline", EngagementID: eng.ID, Target: "host-a",
		Action: "scan", EffectClass: "active network interaction",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jobs.Prepare(planned.ID, planned.OperationID); err == nil || !strings.Contains(err.Error(), "offline network profile") {
		t.Fatalf("err=%v", err)
	}
}

func TestPlanRejectsWhenOperationReceiptShardQuotaIsFull(t *testing.T) {
	store, eng := newScopedStore(t)
	const operationID = "job-op-operation-quota"
	shardDir := filepath.Dir(store.operationPath(operationID))
	if err := os.MkdirAll(shardDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < MaxJobShardFiles; i++ {
		path := filepath.Join(shardDir, fmt.Sprintf("fill-%03d.json", i))
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	request := PlanRequest{
		OperationID:  operationID,
		EngagementID: eng.ID,
		Target:       "host-a",
		Action:       "observe",
		EffectClass:  "observation",
	}
	_, err := store.Plan(request)
	if !errors.Is(err, recordio.ErrShardQuota) {
		t.Fatalf("plan err=%v want ErrShardQuota", err)
	}
	digest, err := requestDigest(normalizePlan(request))
	if err != nil {
		t.Fatal(err)
	}
	if _, statErr := os.Stat(store.jobPath("job_" + digest[:16])); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("quota rejection left orphan job state: %v", statErr)
	}
}

func TestPlanContextHonorsCancellationBeforeDurableWrite(t *testing.T) {
	store, eng := newScopedStore(t)
	request := PlanRequest{
		OperationID: "job-op-cancelled", EngagementID: eng.ID, Target: "host-a",
		Action: "observe", EffectClass: "observation",
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.PlanContext(ctx, request); !errors.Is(err, context.Canceled) {
		t.Fatalf("plan err=%v want context.Canceled", err)
	}
	digest, err := requestDigest(normalizePlan(request))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(store.jobPath("job_" + digest[:16])); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancelled plan left durable job: %v", err)
	}
}
