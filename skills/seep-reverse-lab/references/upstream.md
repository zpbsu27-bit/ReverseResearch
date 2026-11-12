# Upstream Inspirations

This skill is an original integration for ReverseResearch / Seep-Reverse-Lab. It adopts workflow patterns rather than vendoring upstream source trees or third-party binaries.

## reverse-skill

- Repository: https://github.com/zhaoxuya520/reverse-skill
- Reviewed HEAD: cab634bd855fc287f6e420c1f36fd1a6b9245960
- License at review time: MIT for the main repository; nested/third-party components may have different licenses.
- Adopted ideas: one routing source of truth, route regression tests, tool-index-first behavior, progressive skill routing, case/evidence discipline, client-neutral Core vs adapter separation, supply-chain skepticism.
- Not copied: broad red-team/CTF skill inventory, client-specific bootstraps, duplicate routing tables, or unrelated toolchains.
- Rechecked on 2026-10-09: current remote HEAD is still the reviewed revision. Second-pass sources: `skills/case-review/SKILL.md`, `skills/case-review/scripts/review_case.py`, and `skills/field-journal/2026-08-01_nextjs-cdk-contract-faithful-local-reconstruction.md`. Adopted independent reconstruction fixtures, boundary serializers, partial-result/state semantics and read-only evidence review methods in the existing Web/Evidence references. RR already owns file drift/link/strength checks in casebook; no parallel Python reviewer was added.

## apk-reverse

- Repository: https://github.com/newliver666/apk-reverse
- Reviewed HEAD: 7b6c6932a95f03d778e81e5e1a2cbf6f62dc97fd
- License at review time: MIT.
- Adopted ideas: short decision-oriented skill entrypoint, progressive references, environment doctor, explicit gates with pass criteria, symptom-driven stop signals, two-strike rule, strict definition of done, and several generalized APK failure lessons.
- Second-pass adoption against the same pinned HEAD: explicit `observed|inferred|unverified` claim strength, precedent/dead-route readback before repeating work, off-PATH configured tool roots, deliverable-form constraints, signature-derived request-key checks, feature-scoped TLS triage, consistent split-set signing, and the strict applicability boundary for known-plaintext Dex-VMP differential analysis.
- Not copied: target-specific data, exploit payloads, third-party binaries, or a second Android tool owner.

## REA (Reverse Engineer Anything)

- Repository: https://github.com/morluto/rea
- Reviewed revision on 2026-10-09: cf415619cadcfcb18cda59a54b26c9d164f750a4
- Main repository license: MIT, copyright 2026 morluto. Reviewed LICENSE SHA-256: c1e889027b0d1d14f6b2c7fd3d2d7fecc22854a1c3e22c8772ec4a6d73121864. This does not assign that license to commercial tools or nested third-party components.
- Reviewed sources: `docs/web-network-captures.md`, `src/application/WebNetworkCaptureService.ts`, `src/browser/history/HarCaptureAdapter.ts`, `src/domain/sourceMapContents.ts`, `src/domain/sourceMapEnvelope.ts`, `src/javascript/sourceMaps/SourceMapFormat.ts`, `docs/javascript-application-graph.md`, `src/domain/functionDossierEvidence.ts`, `src/domain/evidenceCompletionLedger.ts`, `skill-src/reverse-engineer-anything/SKILL.md`, `docs/mcp-prompts.md`, and `docs/managed-code-analysis.md`.
- Adopted with original Go implementations: inline classic source-map inventory, strict embedded-source correspondence, bounded UTF-8 source reading, whole-artifact duplicate-key checks, offline historical HAR summary, producer ordinals/locations, pagination/digest fences, output coverage and explicit unavailable content.
- Adopted as workflow methods: feature-scoped tracing, entry/computation/result boundaries, source/resource identity, independent reconstruction fixtures, observation authority separate from claim strength, and per-claim completion with gaps retained in existing Case review/WorkItems.
- Kept local owners: webinspect -> Core -> CLI/MCP; Router/Playbook; Case/Evidence/Finding/Path; process leases and lazy backends. No REA code, Node dependency tree, agent bootstrap, commercial provider or target execution is bundled.
- Expansion reviewed on 2026-10-12 at `fa87dd2aac3eaeb49875c54e93ec18c98cc92e4d` (MIT; LICENSE SHA-256 `798f9e4d18e49b30bf2f12696c8ced73dc4e1413da375a333d01281543a1ea8b`). Sources include current ToolContracts, managed/application/JavaScript/artifact/Go/EVM/Web/provider guides. First-pass exclusions describe that historical scope and are not permanent refusals.
- Current original Go additions: embedded indexed/VLQ source-map lookup; ASAR inventory/entry/SHA integrity; pinned ECMAScript AST and ephemeral module candidates; PE/CLI metadata and selected CIL; static declaration comparisons; historical HAR API/body/summary comparisons; Go buildinfo; EVM linear selector candidates; ZIP inventory/CRC entry reads; canonical Case snapshot dossiers/progress. Container layout remains the existing targetidentity owner.
- Continuing portable profiles: TAR/gzip TAR inventory/member bytes; XML/bplist00 typed object tables and explicit data reads; original NSKeyedArchiver object/UID/class declarations; compiled NIBArchive v1 tables; Linux ELF64 amd64 LE recorded core notes/registers with exact source ranges; ESM import/export and CommonJS export shape candidates in the same AST visitor. Historical PID/serialized class names never authorize runtime control or instantiate classes.
- Bounds remain explicit: not full ECMA-426/HAR/REA conformance, bundler/runtime reconstruction, semantic cross-build CIL fingerprints, C#/NativeAOT/IL2CPP recovery, ABI/mutability inference, native mitmproxy or platform-exclusive engine acceptance. Apple/Harmony package projections, raw Go metadata and optional WABT 1.0.42 static validation/WAT use existing snapshot/query owners. No second persistent graph, completion state, provider setup or target process owner is introduced. See REA04–REA18 in the existing implementation ledger for remaining gaps.

## Historical ChatGPT reverse-engineering clients

- PawanOsman/ChatGPT: the repository URL now redirects to PawanOsman/OpenCursor. Reviewed the retained old proxy object `46043c685100e9d6d22501b39a196d3b6762878a`, specifically `src/app.ts`, `README.md` and `LICENSE`; its license is AGPL-3.0. The current redirected repository has a separate HEAD, `b4528f95ca5ab4cddf22bef3e19431fad00feb01`, and is not treated as that historical proxy implementation.
- acheong08/ChatGPT: archived repository; reviewed revision `9167b325addc7d3520987face684e8230bd62b46`, `src/revChatGPT/V1.py`, `src/revChatGPT/V3.py` and `LICENSE` (GPL-2.0).
- Adopted as research methods: preserve session/conversation/parent identities, distinguish cumulative snapshots from deltas, separate HTTP/framing/application outcomes, preserve error/partial behavior and retain exact capture locations. These historical implementations do not prove current endpoint, model or authentication availability.
- No upstream code, authentication flow, proxy process, credential store, account pool or private endpoint implementation is incorporated. SSE framing is an original Go implementation derived from the public WHATWG parsing contract within RR's existing webinspect owner.

## codex-proxy research candidates

The user supplied an uncertain `coddexproxy` name and asked to select material useful for reverse research. These are explicitly selected candidates, not an assertion that the name uniquely identifies either repository.

- lininn/codex-proxy: reviewed revision `4e30ee7f0f7932a113934d38f718ac5d4189fb64`, `src/stream.ts`, `src/translator.ts` and `LICENSE` (MIT, copyright 2026 Emerson Towne). Adopted the framing/translation boundary and per-call identity as methods. Line-only parsing and synthesizing completion at EOF in this sample are not sufficient evidence of generic SSE or application completion; RR reports those limits explicitly.
- xblanc33/CodexProxy: reviewed revision `368bd7f49497395fd910858d37ab2e4e9c7f18fc`, `server.js`, `README.md` and `package.json`. The package declares ISC but this revision has no standalone LICENSE file; no implementation is copied. Adopted exact exchange/call correlation and raw-record versus summary separation as methods. Best-effort text/tool summaries are derived observations.
- Original implementation: `web_sse_inspect` / `web sse` inspect offline UTF-8 SSE artifacts, with joined multi-line data, inherited/reset ID digests, event boundaries, EOF gaps, bounded previews and SHA-fenced paging. Reference: https://html.spec.whatwg.org/multipage/server-sent-events.html#parsing-an-event-stream . No protocol translator, model routing or proxy deployment is added to RR.

## Local precedence

When upstream guidance conflicts with ReverseResearch's tested safety/currentness owners, the local owner wins. Examples include process leases, x32 mutation receipts, PE Hook/patch currentness, Ghidra Unicode alias handling, and compatibility evidence rules.
