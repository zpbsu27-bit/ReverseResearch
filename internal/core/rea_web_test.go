package core

import (
	"path/filepath"
	"testing"

	"reverseresearch/internal/webinspect"
)

func TestREAWebCoreSharesProjectionAndDigestFences(t *testing.T) {
	root, sourceRoot := isolatedCoreRoot(t)
	service, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	source, err := service.ReadWebSourceMap(filepath.Join(sourceRoot, "testdata", "rea-web-source.map"), webinspect.SourceMapReadOptions{SourceIndex: 2})
	if err != nil || source.ContentAvailable || source.CoverageComplete || source.UnavailableReason == "" {
		t.Fatalf("source=%+v err=%v", source, err)
	}
	har, err := service.InspectWebHAR(filepath.Join(sourceRoot, "testdata", "rea-web-capture.har"), webinspect.HAROptions{})
	if err != nil || !har.CoverageComplete || har.ReturnedEntries != 2 || har.EvidenceAuthority != "historical-producer-record" {
		t.Fatalf("har=%+v err=%v", har, err)
	}
	if har.NetworkInteraction || har.ExecutionPerformed {
		t.Fatal("offline core reported execution/network effects")
	}
	sse, err := service.InspectWebSSE(filepath.Join(sourceRoot, "testdata", "protocol-stream.sse"), webinspect.SSEOptions{Limit: 1})
	if err != nil || sse.TotalEvents != 4 || !sse.PendingDataAtEOF || sse.CoverageComplete || sse.ApplicationCompletion != "unverified" || sse.NetworkInteraction || sse.ExecutionPerformed {
		t.Fatalf("sse=%+v err=%v", sse, err)
	}
	for _, text := range []string{"inspect historical HAR capture", "分析 HAR 抓包", "读取 sourcemap 中的源码", "inspect SSE capture", "分析 SSE 抓包", "event-stream framing"} {
		routed, err := service.Route(text)
		if err != nil || routed.Route.ID != "js-web" {
			t.Fatalf("route for %q = %+v err=%v", text, routed, err)
		}
	}
}
