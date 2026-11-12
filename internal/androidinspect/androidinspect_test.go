package androidinspect

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fakeADB(t *testing.T, responses map[string]runResult, calls *[]string) runner {
	t.Helper()
	return func(_ context.Context, _ string, args []string) runResult {
		key := strings.Join(args, " ")
		*calls = append(*calls, key)
		if value, ok := responses[key]; ok {
			return value
		}
		return runResult{Err: errors.New("unexpected call: " + key)}
	}
}

func TestDevicesAndProbeRequireExplicitAuthorization(t *testing.T) {
	var calls []string
	responses := map[string]runResult{
		"devices -l": {Stdout: []byte("List of devices attached\nabc device product:x model:Pixel transport_id:1\ndef unauthorized transport_id:2\n")},
		"-s abc shell getprop ro.product.manufacturer":  {Stdout: []byte("Google\n")},
		"-s abc shell getprop ro.product.model":         {Stdout: []byte("Pixel\n")},
		"-s abc shell getprop ro.build.version.release": {Stdout: []byte("15\n")},
		"-s abc shell getprop ro.build.version.sdk":     {Stdout: []byte("35\n")},
		"-s abc shell getprop ro.product.cpu.abi":       {Stdout: []byte("arm64-v8a\n")},
		"-s abc shell id": {Stdout: []byte("uid=2000(shell) gid=2000(shell)\n")},
	}
	m := newManager(t.TempDir(), "adb", fakeADB(t, responses, &calls), time.Now)
	devices, err := m.Devices(context.Background())
	if err != nil || len(devices) != 2 || !devices[0].Authorized || devices[1].Authorized {
		t.Fatalf("devices=%#v err=%v", devices, err)
	}
	if _, err := m.Probe(context.Background(), "def"); err == nil || !strings.Contains(err.Error(), "not authorized") {
		t.Fatalf("unauthorized device was probed: %v", err)
	}
	probe, err := m.Probe(context.Background(), "abc")
	if err != nil {
		t.Fatal(err)
	}
	if probe.SerialSHA256 == "" || probe.Model != "Pixel" || probe.RootShell {
		t.Fatalf("probe=%#v", probe)
	}
}

func TestSnapshotAndTapAreCurrentnessBoundAndReplaySafe(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	xmlBody := []byte(`<?xml version="1.0" encoding="UTF-8"?><hierarchy rotation="0"><node text="" resource-id="root" bounds="[0,0][100,100]"><node text="Continue" resource-id="btn" content-desc="" bounds="[10,20][50,60]"/></node></hierarchy>`)
	var calls []string
	responses := map[string]runResult{
		"devices -l": {Stdout: []byte("List of devices attached\nabc device transport_id:1\n")},
		"-s abc exec-out uiautomator dump /dev/tty": {Stdout: append([]byte("UI hierchary dumped to: /dev/tty\n"), xmlBody...)},
		"-s abc exec-out screencap -p":              {Stdout: []byte{0x89, 'P', 'N', 'G'}},
		"-s abc shell input tap 30 40":              {},
	}
	m := newManager(root, "adb", fakeADB(t, responses, &calls), func() time.Time {
		value := now
		now = now.Add(time.Second)
		return value
	})
	snapshot, err := m.Snapshot(context.Background(), "abc")
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.UISHA256 == "" || snapshot.ScreenshotSHA256 == "" {
		t.Fatalf("snapshot=%#v", snapshot)
	}
	receipt, err := m.Tap(context.Background(), TapRequest{
		Serial: "abc", SnapshotID: snapshot.ID, ExpectedUISHA256: snapshot.UISHA256,
		Selector: Selector{ResourceID: "btn"}, OperationID: "tap-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.State != "applied" || receipt.X != 30 || receipt.Y != 40 || receipt.SelectorHash == "" {
		t.Fatalf("receipt=%#v", receipt)
	}
	before := len(calls)
	replay, err := m.Tap(context.Background(), TapRequest{
		Serial: "abc", SnapshotID: snapshot.ID, ExpectedUISHA256: snapshot.UISHA256,
		Selector: Selector{ResourceID: "btn"}, OperationID: "tap-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if replay.State != "applied" || len(calls) != before {
		t.Fatalf("replay should return the durable receipt without touching adb, calls=%v before=%d receipt=%#v", calls, before, replay)
	}
	workspace, err := m.PrepareWorkspace("abc")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(workspace.Path, "abc") || !strings.Contains(workspace.Path, filepath.Join("state", "android")) {
		t.Fatalf("workspace leaked raw serial: %#v", workspace)
	}
	if _, err := os.Stat(workspace.CertPath); err != nil {
		t.Fatal(err)
	}
}

func TestResolveSelectorRequiresExactlyOneCriterion(t *testing.T) {
	body := []byte(`<hierarchy><node resource-id="btn" text="Continue" bounds="[0,0][20,20]"/></hierarchy>`)
	if _, _, _, _, err := resolveSelector(body, Selector{ResourceID: "btn", Text: "Continue"}); err == nil {
		t.Fatal("multiple selector criteria were accepted")
	}
}

func TestTapRefusesStaleUIWithoutAction(t *testing.T) {
	var calls []string
	current := []byte(`<hierarchy><node resource-id="btn" bounds="[0,0][20,20]"/></hierarchy>`)
	responses := map[string]runResult{
		"devices -l": {Stdout: []byte("List of devices attached\nabc device\n")},
		"-s abc exec-out uiautomator dump /dev/tty": {Stdout: current},
	}
	m := newManager(t.TempDir(), "adb", fakeADB(t, responses, &calls), time.Now)
	_, err := m.Tap(context.Background(), TapRequest{
		Serial: "abc", SnapshotID: "s", ExpectedUISHA256: strings.Repeat("0", 64),
		Selector: Selector{ResourceID: "btn"}, OperationID: "tap-stale",
	})
	if err == nil || !strings.Contains(err.Error(), "currentness mismatch") {
		t.Fatalf("stale UI accepted: %v", err)
	}
	for _, call := range calls {
		if strings.Contains(call, "input tap") {
			t.Fatalf("stale UI executed tap: %v", calls)
		}
	}
}
