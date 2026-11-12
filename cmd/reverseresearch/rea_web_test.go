package main

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"reverseresearch/internal/webinspect"
)

func TestREAWebCLIUsesOfflineCore(t *testing.T) {
	root, _ := isolatedCLIRoot(t)
	var stdout, stderr bytes.Buffer
	mapPath := filepath.Join(root, "testdata", "rea-web-source.map")
	if err := runMain(context.Background(), root, []string{"web", "sourcemap", mapPath, "--source-index", "1"}, &stdout, &stderr); err != nil {
		t.Fatalf("source-map CLI: %v stderr=%s", err, stderr.String())
	}
	var source webinspect.SourceMapReadReport
	if err := json.Unmarshal(stdout.Bytes(), &source); err != nil {
		t.Fatal(err)
	}
	if !source.ContentAvailable || !source.CoverageComplete || source.TotalBytes != 0 || source.ExecutionPerformed {
		t.Fatalf("empty embedded source lost its meaning: %+v", source)
	}
	stdout.Reset()
	harPath := filepath.Join(root, "testdata", "rea-web-capture.har")
	if err := runMain(context.Background(), root, []string{"web", "har", harPath, "--offset", "1", "--limit", "1"}, &stdout, &stderr); err != nil {
		t.Fatalf("HAR CLI: %v stderr=%s", err, stderr.String())
	}
	var har webinspect.HARReport
	if err := json.Unmarshal(stdout.Bytes(), &har); err != nil {
		t.Fatal(err)
	}
	if har.TotalEntries != 2 || len(har.Entries) != 1 || har.Entries[0].Ordinal != 1 || har.CoverageComplete || har.NetworkInteraction {
		t.Fatalf("HAR CLI changed source ordinals/coverage: %+v", har)
	}
	stdout.Reset()
	if err := runMain(context.Background(), root, []string{"web", "har", harPath, "--expected-sha256", "stale"}, &stdout, &stderr); err == nil || stdout.Len() != 0 {
		t.Fatal("stale HAR pagination did not fail without a result")
	}
	stdout.Reset()
	ssePath := filepath.Join(root, "testdata", "protocol-stream.sse")
	if err := runMain(context.Background(), root, []string{"web", "sse", ssePath, "--offset", "2", "--limit", "2", "--data-preview-bytes", "256"}, &stdout, &stderr); err != nil {
		t.Fatalf("SSE CLI: %v stderr=%s", err, stderr.String())
	}
	var sse webinspect.SSEReport
	if err := json.Unmarshal(stdout.Bytes(), &sse); err != nil {
		t.Fatal(err)
	}
	if sse.TotalEvents != 4 || sse.ReturnedEvents != 2 || sse.Events[0].Ordinal != 2 || !sse.Events[0].DoneMarker || sse.Events[1].Ordinal != 3 || !sse.PendingDataAtEOF || sse.CoverageComplete || sse.ApplicationCompletion != "unverified" {
		t.Fatalf("SSE CLI lost framing/failure semantics: %+v", sse)
	}
	stdout.Reset()
	if err := runMain(context.Background(), root, []string{"web", "sse", ssePath, "--expected-sha256", "stale"}, &stdout, &stderr); err == nil || stdout.Len() != 0 {
		t.Fatal("stale SSE pagination did not fail without a result")
	}
}
