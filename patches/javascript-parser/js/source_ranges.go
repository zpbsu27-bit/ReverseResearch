package js

import "github.com/tdewolff/parse/v2"

// SourceRange uses zero-based UTF-8 byte offsets in the original parser input.
// End is exclusive. Whitespace/comments inside the factory are retained; leading
// and trailing trivia and grouping parentheses are not part of a factory node.
type SourceRange struct {
	Start int
	End   int
}

// FactoryRanges contains only function, arrow and object-method nodes. It is an
// optional side table; the AST and the normal Parse API remain unchanged.
type FactoryRanges map[INode]SourceRange

// ParseWithFactoryRanges uses the same parser and grammar as Parse. No evidence
// is returned for malformed input. Class methods are outside this API's scope.
func ParseWithFactoryRanges(r *parse.Input, o Options) (*AST, FactoryRanges, error) {
	ranges := FactoryRanges{}
	tree, err := parseWithFactoryRanges(r, o, ranges)
	if err != nil {
		return nil, nil, err
	}
	return tree, ranges, nil
}

func (p *Parser) recordFactory(node INode, start int) {
	if p.factoryRanges == nil || node == nil || p.err != nil || p.previousEnd < start {
		return
	}
	switch node.(type) {
	case *FuncDecl, *ArrowFunc, *MethodDecl:
		p.factoryRanges[node] = SourceRange{Start: start, End: p.previousEnd}
	}
}
