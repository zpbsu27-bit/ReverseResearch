# Third-Party Notices

This repository contains or adapts third-party components. Each component
remains under its own license; the project-level MIT license does not replace
those terms. The authoritative license text shipped with each component is
listed below.

| Component | Location | License |
| --- | --- | --- |
| OpenAI Secure MCP Tunnel client | `patches/tunnel-client` | Apache-2.0 (`LICENSE`, `NOTICE`) |
| tdewolff/parse v2 patches | `patches/javascript-parser` | MIT (`LICENSE.md`) |
| JADX-derived patches | `patches/jadx` | MIT (`LICENSE`) |
| re-mcp / Ghidra integration patches | `patches/ghidra` | MIT OR Apache-2.0 (SPDX headers) |
| DDrawCompat reference source | `reference-sources/DDrawCompat` | ISC (`LICENSE.txt`) |
| miniz | `tools/vendor-snapshots/miniz-3.1.2` | MIT (`LICENSE`) |
| zlib 1.2.8 CRC32 snapshot | `tools/vendor-snapshots/zlib-1.2.8-crc32` | zlib (`LICENSE`) |
| EVMole WASM | `internal/evmengine` | MIT (`LICENSE.evmole`, `NOTICE.md`) |

Go module dependencies are resolved from `go.mod` / `go.sum` and retain their
upstream licenses; they are not vendored in this repository.

Runtime tools such as radare2, Ghidra, the JDK, JADX, x64dbg and WABT are
installed or supplied separately and are not relicensed by this project. See
`docs/upstream-snapshots.md` for pinned versions and provenance.

If you redistribute a binary build, include the upstream `NOTICE` files for
Apache-2.0 components and preserve the license files referenced above.
