package webinspect

import (
	"math"
	"testing"
)

func TestSourceMapVLQAndEmbeddedSectionBoundaries(t *testing.T) {
	for _, v := range []struct {
		s string
		n int
	}{{"iB", 17}, {"V", -10}, {"B", math.MinInt32}} {
		i := 0
		n, err := decodeVLQ(v.s, &i)
		if err != nil || n != v.n || i != len(v.s) {
			t.Fatalf("VLQ %s=%d %v", v.s, n, err)
		}
	}
	body := `{"version":3,"sections":[{"offset":{"line":1,"column":3},"map":{"version":3,"sources":["a.js"],"names":["fn"],"mappings":"AAAAA,K","sourcesContent":["fixture"]}},{"offset":{"line":2,"column":5},"map":{"version":3,"sources":[],"mappings":""}}]}`
	p := writeREAInput(t, "indexed.map", body)
	r, err := LocateSourceMap(p, SourceMapLocateOptions{Line: 1, Column: 4})
	if err != nil || !r.Mapped || r.Source != "a.js" || r.Name != "fn" || r.MappingColumn != 3 || r.OriginalLine != 0 || r.ExecutionPerformed || r.NetworkInteraction {
		t.Fatalf("location %+v %v", r, err)
	}
	for _, pos := range [][2]int{{0, 0}, {1, 2}, {1, 8}, {2, 5}} {
		r, err := LocateSourceMap(p, SourceMapLocateOptions{Line: pos[0], Column: pos[1]})
		if err != nil || r.Mapped {
			t.Fatalf("unmapped %+v %v", r, err)
		}
	}
	for _, body := range []string{`{"version":3,"sources":["a"],"mappings":"BAAA"}`, `{"version":3,"sources":["a"],"mappings":"AAAA,AAAA"}`, `{"version":3,"sources":["a"],"mappings":"g"}`, `{"version":3,"sections":[{"offset":{"line":0,"column":0},"url":"http://example.test/map"}]}`} {
		if _, err := parseSourceMap([]byte(body)); err == nil {
			t.Fatalf("accepted malformed/unsupported map %s", body)
		}
	}
}
