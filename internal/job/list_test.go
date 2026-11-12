package job

import "testing"

func TestOperationIDWithColonUsesPortableReceiptKeyAndList(t *testing.T) {
	store, eng := newScopedStore(t)
	first, err := store.Plan(PlanRequest{
		OperationID: "tenant:job:1", EngagementID: eng.ID, Target: "host-a",
		Action: "observe", EffectClass: "observation",
	})
	if err != nil {
		t.Fatal(err)
	}
	replay, err := store.Plan(PlanRequest{
		OperationID: "tenant:job:1", EngagementID: eng.ID, Target: "host-a",
		Action: "observe", EffectClass: "observation",
	})
	if err != nil {
		t.Fatal(err)
	}
	if replay.ID != first.ID {
		t.Fatalf("replay=%+v first=%+v", replay, first)
	}
	listed, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].OperationID != "tenant:job:1" {
		t.Fatalf("listed=%+v", listed)
	}
}
