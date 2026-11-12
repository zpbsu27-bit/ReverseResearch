# Pinned ECMAScript parser source ranges

This is the root, buffer and js package subset of github.com/tdewolff/parse/v2
v2.8.16, licensed under the included MIT LICENSE.md. upstream-files.json records
the original bytes and module checksum. No module-cache source was edited.

RR's go.mod replaces that same dependency with this directory. There is one
compiled JavaScript parser. The optional ParseWithFactoryRanges API records
function, arrow and object-method node offsets in the original UTF-8 byte input.
End offsets are exclusive; trivia inside a factory is preserved. Class methods
are outside the range API's scope. Parse and Options retain their original API
and grammar. Only js/parse.go is modified upstream source; source_ranges.go and
source_ranges_test.go are local additions. Original package tests are retained.

Ranges and original-byte SHA are evidence about the selected source snapshot.
RR separately labels normalized AST rendering hashes tdewolff-js-render-v1;
these are neither Babel fingerprints nor proof of semantic equivalence.
