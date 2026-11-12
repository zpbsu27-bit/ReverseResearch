package casebook

import "testing"

func TestSnapshotBindsCaseAndRevision(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c, err := store.Create(CreateRequest{Title: "snapshot"})
	if err != nil {
		t.Fatal(err)
	}
	got, rev, err := store.Snapshot(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != c.ID || len(rev) != 64 {
		t.Fatalf("case=%+v rev=%q", got, rev)
	}
	v, err := store.Verify(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if v.CaseSHA256 != rev {
		t.Fatalf("verify=%s snapshot=%s", v.CaseSHA256, rev)
	}
}
