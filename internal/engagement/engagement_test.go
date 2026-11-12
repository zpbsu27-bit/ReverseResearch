package engagement

import (
	"testing"
	"time"
)

func TestAuthorizeRequiresTargetActionAndWindow(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	eng, err := store.Create(CreateRequest{Organization: "Lab", Operator: "alice", Scope: Scope{Targets: []string{"host-a"}, ExcludedTargets: []string{"host-b"}, AllowedActions: []string{"observe", "debug"}, Authorization: Authorization{Status: "granted", Basis: "lab_only"}, NetworkProfile: NetworkProfile{Mode: "authorized_target_only"}, StartsUTC: "2026-10-01T00:00:00Z", EndsUTC: "2026-10-03T00:00:00Z"}})
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	allowed, err := store.Authorize(eng.ID, "host-a", "debug", at)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed.Allowed {
		t.Fatalf("expected allowed: %+v", allowed)
	}
	denied, _ := store.Authorize(eng.ID, "host-c", "debug", at)
	if denied.Allowed || denied.Reason != "target is outside scope" {
		t.Fatalf("unexpected decision: %+v", denied)
	}
	denied, _ = store.Authorize(eng.ID, "host-a", "patch", at)
	if denied.Allowed || denied.Reason != "action is not allowed" {
		t.Fatalf("unexpected decision: %+v", denied)
	}
	denied, _ = store.Authorize(eng.ID, "host-a", "debug", at.Add(48*time.Hour))
	if denied.Allowed || denied.Reason != "outside engagement time window" {
		t.Fatalf("unexpected decision: %+v", denied)
	}
}

func TestCreateRejectsContradictoryScope(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Create(CreateRequest{Organization: "Lab", Operator: "alice", Scope: Scope{Targets: []string{"host-a"}, ExcludedTargets: []string{"host-a"}, AllowedActions: []string{"observe"}}})
	if err == nil {
		t.Fatal("expected contradictory scope to fail")
	}
}

func TestAuthorizationAndNetworkProfileAreHardGates(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pending, err := store.Create(CreateRequest{
		Organization: "Lab", Operator: "alice",
		Scope: Scope{
			Targets: []string{"host-a"}, AllowedActions: []string{"scan"},
			Authorization:  Authorization{Status: "pending", Basis: "written_contract"},
			NetworkProfile: NetworkProfile{Mode: "authorized_target_only"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := store.AuthorizeEffect(pending.ID, "host-a", "scan", "active network interaction", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allowed || decision.Reason != "engagement authorization is not granted" {
		t.Fatalf("decision=%+v", decision)
	}
	offline, err := store.Create(CreateRequest{
		Organization: "Lab", Operator: "alice",
		Scope: Scope{
			Targets: []string{"host-a"}, AllowedActions: []string{"scan"},
			Authorization:  Authorization{Status: "granted", Basis: "lab_only"},
			NetworkProfile: NetworkProfile{Mode: "offline"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	decision, err = store.AuthorizeEffect(offline.ID, "host-a", "scan", "active network interaction", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allowed || decision.Reason != "offline network profile forbids active network interaction" {
		t.Fatalf("decision=%+v", decision)
	}
}
