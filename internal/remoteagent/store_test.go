package remoteagent

import (
	"crypto/ed25519"
	"encoding/base64"
	"path/filepath"
	"testing"
	"time"
)

func TestAgentStoreRequiresSignedCurrentReplacement(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	m, err := SignManifest(Manifest{AgentID: "agent-1", Platform: "linux", Architecture: "x86-64", Capabilities: []string{"artifact.inspect"}, MutualTLSRequired: true, NoRemoteShell: true, PublicKey: base64.StdEncoding.EncodeToString(pub), ExpiresUTC: time.Now().UTC().Add(time.Hour).Format(time.RFC3339)}, priv)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(filepath.Join(t.TempDir(), "agents"))
	if err != nil {
		t.Fatal(err)
	}
	reg, err := store.Register(m, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Register(m, ""); err == nil {
		t.Fatal("replacement without current revision accepted")
	}
	next, err := store.Register(m, reg.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if next.Revision == reg.Revision {
		t.Fatal("replacement did not advance revision")
	}
	list, err := store.List()
	if err != nil || len(list) != 1 {
		t.Fatalf("list=%+v err=%v", list, err)
	}
}
