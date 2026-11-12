package js

import (
	"strings"
	"testing"

	"github.com/tdewolff/parse/v2"
)

func TestFactorySourceRanges(t *testing.T) {
	factories := []string{
		"function(a,b,c){/*中*/return /[}]/.test(`x${a}`)}",
		"async /* c */ function* (a){yield await a}",
		"(a,b,c) => {\r\n return c(1);\r\n}",
		"x => x + /a/.source",
		"async /* c */ x => await x",
		"async (a,b) => ({a,b})",
		"async => async + 1",
		"function(){return (a => ({a}))}",
		"function(){return async /*c*/ function(){}}",
	}
	for _, factory := range factories {
		t.Run(factory, func(t *testing.T) {
			source := "#!node\n/*前导*/ const x = (" + factory + ") /*尾*/;"
			tree, ranges, err := ParseWithFactoryRanges(parse.NewInputString(source), Options{})
			if err != nil {
				t.Fatal(err)
			}
			plain, err := Parse(parse.NewInputString(source), Options{})
			if err != nil || tree.JSString() != plain.JSString() {
				t.Fatalf("Parse parity: %v", err)
			}
			found := false
			for _, r := range ranges {
				if r.Start < 0 || r.End > len(source) || r.End <= r.Start {
					t.Fatalf("invalid range: %+v", r)
				}
				if source[r.Start:r.End] == factory {
					found = true
				}
			}
			if !found {
				t.Fatalf("missing original factory %q; ranges=%v", factory, ranges)
			}
		})
	}
	for _, method := range []string{"m(a){return a}", "async /*c*/ m(a){return await a}", "*m(){yield 1}", "[key](a){return a}", "get m(){return 1}"} {
		source := "const o = { /*前*/ " + method + " /*后*/ };"
		_, ranges, err := ParseWithFactoryRanges(parse.NewInputString(source), Options{})
		if err != nil {
			t.Fatal(err)
		}
		if len(ranges) != 1 {
			t.Fatalf("method ranges: %v", ranges)
		}
		for _, r := range ranges {
			if source[r.Start:r.End] != method {
				t.Fatalf("method %q: got %q", method, source[r.Start:r.End])
			}
		}
	}
	if _, ranges, err := ParseWithFactoryRanges(parse.NewInputString("function(){"), Options{}); err == nil || ranges != nil {
		t.Fatal("malformed input returned evidence")
	}
	// Occurrences have separate pointer identity even when their source is equal.
	_, ranges, err := ParseWithFactoryRanges(parse.NewInputString("const a=()=>1,b=()=>1;"), Options{})
	if err != nil || len(ranges) != 2 {
		t.Fatalf("equal factories lost: %v %v", ranges, err)
	}
	for _, r := range ranges {
		if !strings.HasPrefix("const a=()=>1,b=()=>1;"[r.Start:r.End], "()") {
			t.Fatalf("arrow prefix: %+v", r)
		}
	}
}
