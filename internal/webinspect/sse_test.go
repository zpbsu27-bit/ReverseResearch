package webinspect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSSEFramingAndEOF(t *testing.T) {
	body := ": heartbeat\nid: first\nevent: snapshot\ndata: ab\ndata: 中🙂\n\nretry: 1000\ndata: delta\n\nid\ndata: [DONE]\n\ndata: still here\n\ndata: pending\n"
	for _, separator := range []string{"\n", "\r", "\r\n"} {
		t.Run(fmtSSESeparator(separator), func(t *testing.T) {
			input := "\ufeff" + strings.ReplaceAll(body, "\n", separator)
			path := writeREAInput(t, "capture.sse", input)
			report, err := InspectSSE(path, SSEOptions{DataPreviewBytes: 4096})
			if err != nil {
				t.Fatal(err)
			}
			if report.TotalEvents != 4 || report.ReturnedEvents != 4 || report.CommentLines != 1 || report.RetryFields != 1 || report.DoneMarkerCount != 1 || !report.PendingDataAtEOF || report.EndedOnBlockBoundary || report.CoverageComplete || !report.Truncated || report.ApplicationCompletion != "unverified" {
				t.Fatalf("framing/EOF metadata lost: %+v", report)
			}
			first, second, reset := report.Events[0], report.Events[1], report.Events[2]
			if first.EventType != "snapshot" || first.DataLines != 2 || *first.DataPreview != "ab\n中🙂" || first.DataSHA256 != sseTextDigest("ab\n中🙂") || second.EventType != "message" || first.LastEventIDSHA256 != second.LastEventIDSHA256 || reset.LastEventIDBytes != 0 || reset.LastEventIDSHA256 != sseTextDigest("") || !reset.DoneMarker {
				t.Fatalf("field/snapshot identity changed: %+v", report.Events)
			}
			if first.StartByte != 3 || first.StartLine != 1 || first.EndLine != 6 || !strings.HasSuffix(input[first.StartByte:first.EndByte], separator+separator) || report.Events[3].Ordinal != 3 || *report.Events[3].DataPreview != "still here" {
				t.Fatalf("original block spans/order lost: %+v", report.Events)
			}
			page, err := InspectSSE(path, SSEOptions{Offset: 1, Limit: 1, ExpectedSHA256: report.SHA256})
			if err != nil || page.Events[0].Ordinal != 1 || page.NextOffset == nil || *page.NextOffset != 2 || page.Events[0].DataPreview != nil || page.NetworkInteraction || page.ExecutionPerformed {
				t.Fatalf("bounded offline page=%+v err=%v", page, err)
			}
		})
	}
}

func fmtSSESeparator(separator string) string {
	switch separator {
	case "\r":
		return "CR"
	case "\r\n":
		return "CRLF"
	default:
		return "LF"
	}
}

func TestSSEEmptyFieldsOpaqueDataAndUTF8Preview(t *testing.T) {
	path := writeREAInput(t, "fields.sse", "id: stable\n\nid: bad\x00id\nData: ignored\ndata\n\ndata:  leading\n\nevent: control\n\ndata: 中🙂z\n\ndata: {\"x\":1,\"x\":2}\n\n")
	report, err := InspectSSE(path, SSEOptions{DataPreviewBytes: 4096})
	if err != nil || report.TotalEvents != 4 || report.IgnoredIDFields != 1 || report.IgnoredFields != 1 || !report.CoverageComplete || report.PendingDataAtEOF {
		t.Fatalf("fields=%+v err=%v", report, err)
	}
	if *report.Events[0].DataPreview != "" || report.Events[0].LastEventIDSHA256 != sseTextDigest("stable") || *report.Events[1].DataPreview != " leading" || report.Events[2].EventType != "message" || *report.Events[3].DataPreview != `{"x":1,"x":2}` {
		t.Fatalf("framing changed opaque application data: %+v", report.Events)
	}
	page, err := InspectSSE(path, SSEOptions{Offset: 2, Limit: 1, DataPreviewBytes: 4})
	if err != nil || *page.Events[0].DataPreview != "中" || !page.Events[0].PreviewTruncated || !utf8.ValidString(*page.Events[0].DataPreview) {
		t.Fatalf("preview split UTF-8: %+v err=%v", page, err)
	}
	for _, body := range []string{"", "\ufeff", ": comment\n", "id: only\n\n"} {
		empty, err := InspectSSE(writeREAInput(t, "empty.sse", body), SSEOptions{})
		if err != nil || empty.TotalEvents != 0 || !empty.CoverageComplete || empty.Events == nil {
			t.Fatalf("empty/control stream=%+v err=%v", empty, err)
		}
	}
	for _, body := range []string{"data: pending", "data: pending\n", "data: pending\r\n"} {
		tail, err := InspectSSE(writeREAInput(t, "tail.sse", body), SSEOptions{})
		if err != nil || tail.TotalEvents != 0 || !tail.PendingDataAtEOF || tail.CoverageComplete || tail.UndispatchedTailBytes != len(body) {
			t.Fatalf("EOF dispatched pending data: %+v err=%v", tail, err)
		}
	}
}

func TestSSERejectsBoundsAndStaleSources(t *testing.T) {
	path := writeREAInput(t, "valid.sse", "data: valid\n\n")
	for _, options := range []SSEOptions{{Offset: -1}, {Offset: 100001}, {Offset: 2}, {Limit: -1}, {Limit: 201}, {DataPreviewBytes: -1}, {DataPreviewBytes: 4097}, {ExpectedSHA256: strings.Repeat("0", 64)}} {
		if _, err := InspectSSE(path, options); err == nil {
			t.Fatalf("accepted invalid options %+v", options)
		}
	}
	for _, tail := range []string{string([]byte{0xff}), "data:" + strings.Repeat("x", maxSSELineBytes) + "\n\n", "event:" + strings.Repeat("x", 1025) + "\n\n", "id:" + strings.Repeat("x", 4097) + "\n\n", strings.Repeat("data:"+strings.Repeat("x", maxSSELineBytes-5)+"\n", 5) + "\n"} {
		if _, err := InspectSSE(writeREAInput(t, "outside-page.sse", "data: valid\n\n"+tail), SSEOptions{Limit: 1}); err == nil {
			t.Fatal("accepted malformed/oversized input outside selected page")
		}
	}
	large, err := os.Create(filepath.Join(t.TempDir(), "large.sse"))
	if err != nil {
		t.Fatal(err)
	}
	if err := large.Truncate(MaxSSEBytes + 1); err != nil {
		t.Fatal(err)
	}
	large.Close()
	if _, err := InspectSSE(large.Name(), SSEOptions{}); err == nil {
		t.Fatal("accepted oversized artifact")
	}
	if _, err := InspectSSE(writeREAInput(t, "too-many.sse", strings.Repeat("data\n\n", maxSSEEvents+1)), SSEOptions{}); err == nil {
		t.Fatal("accepted too many emitted events")
	}
}

func TestSSEPageBudgetPreservesNextOrdinal(t *testing.T) {
	path := writeREAInput(t, "budget.sse", strings.Repeat("data: "+strings.Repeat("x", 1024)+"\n\n", 200))
	report, err := InspectSSE(path, SSEOptions{Limit: 200, DataPreviewBytes: 4096})
	if err != nil || report.ReturnedEvents < 1 || report.ReturnedEvents >= 200 || report.NextOffset == nil || *report.NextOffset != report.ReturnedEvents || report.TotalEvents != 200 || report.OmittedEvents != 200-report.ReturnedEvents {
		t.Fatalf("budget=%+v err=%v", report, err)
	}
	pageBytes := 0
	for _, event := range report.Events {
		encoded, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		pageBytes += len(encoded) + 1
	}
	if pageBytes > report.PageBytesLimit {
		t.Fatalf("page exceeded budget: %d", pageBytes)
	}
	next, err := InspectSSE(path, SSEOptions{Offset: *report.NextOffset, Limit: 1, ExpectedSHA256: report.SHA256})
	if err != nil || next.Events[0].Ordinal != report.ReturnedEvents {
		t.Fatalf("next ordinal skipped data: %+v err=%v", next, err)
	}
}
