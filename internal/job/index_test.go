package job

import (
	"os"
	"testing"
	"time"
)

func TestJobRecentIndexListRecentAndFullList(t *testing.T) {
	store, eng := newScopedStore(t)
	var planned []Job
	for i, op := range []string{"job-index-1", "job-index-2", "job-index-3"} {
		value, err := store.Plan(PlanRequest{
			OperationID: op, EngagementID: eng.ID, Target: "host-a",
			Action: "observe", EffectClass: "observation",
		})
		if err != nil {
			t.Fatal(err)
		}
		planned = append(planned, value)
		if i < 2 {
			time.Sleep(2 * time.Millisecond)
		}
	}

	recent, err := store.ListRecent(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(recent) != 2 || recent[0].ID != planned[1].ID || recent[1].ID != planned[2].ID {
		t.Fatalf("recent=%+v planned=%+v", recent, planned)
	}

	all, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Fatalf("full list len=%d want 3", len(all))
	}

	if err := os.WriteFile(store.jobIndexPath(), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	recent, err = store.ListRecent(3)
	if err != nil {
		t.Fatal(err)
	}
	if len(recent) != 3 {
		t.Fatalf("rebuilt recent len=%d want 3", len(recent))
	}
}

func TestJobRecentListSurvivesRemovedAndDamagedRecords(t *testing.T) {
	store, eng := newScopedStore(t)
	ids := make([]string, 0, 3)
	for _, op := range []string{"job-res-1", "job-res-2", "job-res-3"} {
		value, err := store.Plan(PlanRequest{
			OperationID: op, EngagementID: eng.ID, Target: "host-a",
			Action: "observe", EffectClass: "observation",
		})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, value.ID)
		time.Sleep(2 * time.Millisecond)
	}
	if err := os.Remove(store.jobPath(ids[0])); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.jobPath(ids[1]), []byte(`{"job_id":"foreign","planned_at":"not-a-time"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	recent, err := store.ListRecent(3)
	if err != nil {
		t.Fatalf("one damaged record must not fail the recent view: %v", err)
	}
	if len(recent) != 1 || recent[0].ID != ids[2] {
		t.Fatalf("recent=%+v want only %s", recent, ids[2])
	}
	again, err := store.ListRecent(3)
	if err != nil || len(again) != 1 {
		t.Fatalf("rebuilt recent=%+v err=%v", again, err)
	}
}

func TestJobRecentDirtyMarkerRecoversCommittedJob(t *testing.T) {
	store, eng := newScopedStore(t)
	value, err := store.Plan(PlanRequest{
		OperationID: "job-index-dirty", EngagementID: eng.ID, Target: "host-a",
		Action: "observe", EffectClass: "observation",
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := store.markJobIndexDirtyUnlocked(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.jobIndexPath(), []byte("{stale"), 0o600); err != nil {
		t.Fatal(err)
	}

	listed, err := store.ListRecent(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].ID != value.ID {
		t.Fatalf("listed=%+v", listed)
	}
	if _, err := os.Stat(store.jobIndexDirtyPath()); !os.IsNotExist(err) {
		t.Fatalf("dirty marker was not cleared: %v", err)
	}
}

func TestJobRecentIndexIsBounded(t *testing.T) {
	index := jobIndex{Version: jobIndexVersion}
	base := time.Now().UTC().Add(-time.Hour)
	for i := 0; i < jobRecentLimit+20; i++ {
		index.Entries = append(index.Entries, jobIndexEntry{
			ID:         "job_" + time.Unix(0, int64(i+1)).UTC().Format("150405.000000000"),
			PlannedUTC: base.Add(time.Duration(i) * time.Millisecond).Format(time.RFC3339Nano),
		})
	}
	sortJobIndex(index.Entries)
	if len(index.Entries) <= jobRecentLimit {
		t.Fatal("fixture did not exceed recent index limit")
	}
	index.Entries = index.Entries[len(index.Entries)-jobRecentLimit:]
	if len(index.Entries) != jobRecentLimit {
		t.Fatalf("bounded recent entries=%d want=%d", len(index.Entries), jobRecentLimit)
	}
}
