package webinspect

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestHARViewsPreserveHistoricalAuthorityAndEmptyBody(t *testing.T) {
	first := `{"log":{"version":"1.2","entries":[{"request":{"method":"GET","url":"https://api.test/search?q=secret"},"response":{"status":200,"content":{"mimeType":"application/json","text":"aGVsbG8=","encoding":"base64"}}},{"request":{"method":"POST","url":"https://api.test/search","postData":{"text":""}},"response":{"status":204,"content":{}}}]}}`
	p := writeREAInput(t, "bodies.har", first)
	api, err := InspectHARAPI(p, HAROptions{Limit: 1})
	if err != nil || api.TotalEntries != 2 || api.TotalEndpoints != 2 || api.CoverageComplete || strings.Contains(api.Endpoints[0].URL, "secret") {
		t.Fatalf("API %+v %v", api, err)
	}
	body, err := ReadHARBody(p, HARBodyOptions{EntryOrdinal: 0, Side: "response", Limit: 2, ExpectedSHA256: api.SHA256})
	if err != nil || !body.Available || body.TotalBytes != 5 || body.CoverageComplete || body.JSONPointer != "/log/entries/0/response/content/text" || body.NetworkInteraction {
		t.Fatalf("body %+v %v", body, err)
	}
	b, _ := base64.StdEncoding.DecodeString(body.DataBase64)
	if string(b) != "he" {
		t.Fatalf("decoded %q", b)
	}
	empty, err := ReadHARBody(p, HARBodyOptions{EntryOrdinal: 1, Side: "request"})
	if err != nil || !empty.Available || empty.TotalBytes != 0 || !empty.CoverageComplete {
		t.Fatalf("empty %+v %v", empty, err)
	}
	missing, err := ReadHARBody(p, HARBodyOptions{EntryOrdinal: 1, Side: "response"})
	if err != nil || missing.Available || missing.UnavailableReason == "" {
		t.Fatalf("missing %+v %v", missing, err)
	}
	other := writeREAInput(t, "after.har", strings.Replace(first, `"status":200`, `"status":500`, 1))
	diff, err := CompareHAR(p, other, HARCompareOptions{})
	if err != nil || diff.TotalItems != 2 || diff.Items[0].SameSummary || diff.NetworkInteraction {
		t.Fatalf("diff %+v %v", diff, err)
	}
	if _, err := CompareHAR(p, other, HARCompareOptions{HAROptions: HAROptions{ExpectedSHA256: strings.Repeat("0", 64)}}); err == nil {
		t.Fatal("comparison accepted stale identity")
	}
	bad := writeREAInput(t, "bad-body.har", strings.Replace(first, "aGVsbG8=", "bad*", 1))
	if _, err := ReadHARBody(bad, HARBodyOptions{Side: "response"}); err == nil {
		t.Fatal("accepted bad base64")
	}
}
