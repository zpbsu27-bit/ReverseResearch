# Web / JS / Protocol Playbook

Use for js-web, web-security, and traffic-protocol routes.

## Isolation first

Use a dedicated browser/profile for reverse work. Do not attach CDP, inject extensions, change proxy/cert settings, or clear storage in the user's daily browser profile.

Record:
- URL/origin and client build/version when observable;
- profile/session identity;
- proxy/capture state;
- baseline request/response and relevant JS/WASM artifact hashes.

## Choose the layer

1. Source map or readable source available -> verify it belongs to the loaded build before trusting it; maps can be absent, stale, partial, or cross-build.
2. Bundled/minified JS -> map module graph, lazy route-specific chunks, entry points, signing/encryption call sites and runtime values.
3. WASM -> keep static format analysis separate from execution/instrumentation evidence. Existing web_wasm_inspect optionally admits WABT 1.0.42 for full static validation and SHA-fenced paged WAT/details; its default remains partial structure. Trusted tools must already be supplied through ToolIndex. WAT is decoded representation and never runtime/source/byte round-trip proof.
4. Electron -> treat browser and native/desktop boundaries separately.
5. Network protocol -> classify HTTP/REST vs protobuf/gRPC/WebSocket/QUIC/custom framing before replay.
6. Server-owned result -> do not claim a client patch controls server/account resources without evidence.

## Offline artifacts before runtime

Use the existing Core tools before opening a browser or installing a parser:

- `web_source_analyze` / `web source <bundle>` validates classic or embedded indexed SourceMap v3, external/inline, with at most 64 names / 16 KiB. `web_source_map_locate` / `web locate <map> --line <n> --column <n>` uses zero-based lines/UTF-16 columns. Indexed indexes flatten in section order; section URLs are refused. Coordinates are artifact declarations, not proof of current loaded source identity.
- `web_source_map_read` / `web sourcemap <map> --source-index <n>` reads only that local map's embedded `sourcesContent`, in UTF-8 byte pages. An absent/null entry is unavailable; an empty string is available empty text. Source names and `sourceRoot` are labels and are never opened or fetched. Supply `expected_sha256` / `--expected-sha256` from the first page for every later page.
- `web_har_inspect` / `web har <capture.har>` returns an offline HAR 1.2 summary with original ordinals and `/log/entries/<ordinal>` locations. Every record's projected fields and the whole JSON structure are validated before a page is selected. The result is capped by entry count and a 48 KiB encoded-entry budget. Follow `next_offset` under the same capture SHA; an omitted or truncated result is not full coverage.
- `web_har_api` groups exact visible method/URL declarations; `web_har_body_read` explicitly reads one retained text/base64 body, preserving missing/empty and its JSON pointer. `web_har_compare` compares redacted summaries with both capture digests plus comparison digest. These are historical projections, never live/wire/request equivalence proofs.
- `app_javascript_application` / `app analyze <asar-or-directory>` parses all selected JS modules and projects relative import/Electron/endpoint candidates. ASAR entry/integrity and standalone AST checks share appinspect. Aliases, package resolution, runtime binding and transpilation stay unresolved. Use `case view` to query existing recorded evidence/links/progress; it does not accept completion.
- `web_sse_inspect` / `web sse <capture.sse>` frames a retained UTF-8 event-stream body using CR, LF or CRLF, blank-line dispatch and multi-line data. Original event ordinals, byte/line spans, joined-data SHA and ID SHA are retained. Follow `next_offset` with the same artifact SHA. Raw IDs and payloads are omitted by default; optional `data_preview_bytes` / `--data-preview-bytes` exposes at most 4096 UTF-8 bytes per event under a 48 KiB page budget. Prefix truncation is separate from event coverage.

HAR headers, cookies, bodies, query values, URL credentials and fragments are excluded. Visible host/path/query names can still be sensitive. This is a summary profile, not complete HAR-schema validation or a recovery of wire bytes. A stored request is a historical producer statement, not proof of a current browser/server transaction; inspection never replays it.

## Investigate one feature at a time

State the input, expected output and precise question. Locate the entry point, the computation or state change, and the output boundary using the smallest useful source/function observations. Preserve missing links instead of connecting similarly named strings or functions by assumption.

For Electron, follow renderer -> exposed preload API -> IPC channel -> main handler -> optional native boundary. Treat static links as inferred unless actual runtime evidence establishes the transition. Keep packaged resources/configuration in the same build identity when they affect behavior.

Record this path with the existing Case Evidence -> Finding -> Path owner. Rebuilding a feature requires independent input/output fixtures and explicit environment/server dependencies. Reading decompiled or embedded source does not establish equivalence with the original application.

## Request replay

Freeze the exact request inputs that matter: method, endpoint, headers/cookies/tokens, body, clock/nonce inputs, device/session identifiers, and client-generated signatures. Redact secrets in reusable journal material.

A replay mismatch is evidence about the model only if the baseline is controlled. Time, account, device fingerprint, server state, and anti-replay fields can invalidate comparisons.

## Recover a streaming protocol

1. Preserve the captured raw bytes and identify the transport separately from the application envelope: HTTP status/headers and body framing, SSE blocks or WebSocket messages, then application payload. Network chunks and individual `data:` lines are not event boundaries. Do not apply string unescaping or trim application data beyond the framing rule.
2. Determine whether each message contains a cumulative snapshot, an append delta, a replacement, or a control record. Compare independent samples before merging content; treating snapshots as deltas duplicates text, while treating deltas as snapshots loses content.
3. Preserve exchange/session/conversation/parent/item/call identities where available. Keep multiple choices, tool calls and concurrent sessions distinct. Associate a tool request with its actual execution receipt by the recorded call identity; arguments or a proxy-rendered summary do not establish that a tool ran.
4. Separate connection EOF, a fully delimited event, a provider completion record, a failure/incomplete record and `[DONE]`. The SSE inspector always reports application completion as unverified. Pending EOF data is undispatched and makes coverage incomplete. A later captured event after `[DONE]` remains visible. Malformed or unknown application JSON remains a protocol gap; generic SSE framing does not validate provider semantics.
5. Reconstruct one feature against independent fixtures: successful response, error response, partial/truncated stream, interleaved calls and resumed session. Record unsupported variants and mutation/server dependencies in the existing Case/WorkItems. After a possibly dispatched request, use the original operation/exchange identity to recover its outcome before considering another request; a dropped stream is not proof of no execution.

The offline SSE profile requires valid UTF-8 and has 32 MiB input, 1 MiB line, 4 MiB joined-data and 100000 emitted-event limits. It counts comments/control fields without simulating retries or reconnects. Original byte spans include block metadata and the blank-line delimiter; data digests cover the joined field values. A decoded/decompressed body capture does not recover transport chunk timing or compressed wire bytes.

## Reconstruct the observed contract

Use source property reads, recorded request fields and independently observed responses to recover the input/output contract. UI, private/legacy endpoints and published APIs may use different serializers while sharing one domain model; preserve each boundary's observed field names, optional/null/missing meanings, per-item errors and state transitions.

Define acceptance for the reconstructed feature before implementation: input -> serialization -> computation/dependency -> response projection -> visible/state effect. Match relevant behavior against independent success and failure fixtures. A locally deterministic dependency fixture proves that local boundary only; external payment/worker/account/server behavior stays unverified until observed in its own authority. Keep implementation notes in research documentation so they do not change the reconstructed product's flow.

## Browser-side mutation

Prefer runtime observation before source rewriting. Confirm the correct frame/worker/service-worker before treating a trace as relevant. Timing/anti-debug behavior can make stepping change the program, so prefer bounded logging/hooks when that risk exists. When mutation is needed, keep it reversible and scoped to the isolated profile/session. Capture both the client-side effect and the corresponding network/server behavior.

## Stop signals

Load failure-catalog.md when:
- identical JS produces different requests/responses across uncontrolled sessions;
- a request only works in the daily browser but not the isolated profile;
- source-map assumptions survive two failed lookups;
- replay keeps failing after two token/header permutations without a controlled baseline.
