# Windows / Native Playbook

Use for memory-search, dynamic-debug, binary-diff, patch, pe-static, native-static, .NET, game-resource, and native obfuscation routes.

## First choices

- Freeze the file or process identity before analysis.
- Prefer Core owners already present in ReverseResearch: target identity, DiE, Ghidra, radare2, memory scan, pointer map, process lease, guarded patch, guarded PE Hook, compatibility records.
- Keep x32/x64 debugger routing architecture-bound. Never attach because a PID merely looks familiar.
- Keep Ghidra/radare2 lazy; inspect reverse_status before assuming a daemon is yours.
- Use a copy for destructive file work unless the explicit in-place guard is the deliverable.

## Dynamic work

1. Identify the live process and capture its process key.
2. Acquire the cooperating process lease before typed mutation.
3. Route to x32dbg/x64dbg from the current PE identity.
4. Prefer read-only memory scan/pointer mapping before debugger attachment.
5. For mutation, use the existing guarded operation ID and replay rules; uncertain effects are not replayed.

## Patch / Hook work

- Patch and Hook plans freeze source bytes and current identity.
- Whole-instruction Hook boundaries and executable-section checks must pass before apply.
- Always verify the postcondition and exercise rollback on an isolated fixture before calling a mechanism reusable.
- A compatibility record does not prove runtime compatibility. Compatible requires runtime evidence linked through the case store.

## Cross-version work

Use static diff to propose mappings, then independently confirm important behavior. Semantic sync is preview-only until a separate write owner exists. Preserve target-side user names/comments by default.

## Currentness and ownership stops

- Paths and PIDs are labels, not identities. Re-check file SHA/size/PE structure or the live process key at the final-effect boundary.
- Never infer x86/x64 from filenames or install directories; route from the current PE/process identity.
- Do not inherit a debugger attach or lease from another ReverseResearch runtime.
- Ghidra may preserve an external Unicode source path while requiring a content-addressed ASCII internal item name; do not reinterpret that as source-path corruption.
- If current bytes are neither the frozen original nor the exact recorded patch, stop rather than adapting the patch in place.

## Stop signals

Load failure-catalog.md when:
- the same attach/launch fails twice;
- bytes or structure drift after the plan was created;
- a daemon/port is already occupied;
- an old build's RVA/function name is being treated as proof for a new build.

## Bounded native evidence workflow

- Start from the original requirement and its context. A derived feature name, translated label or route keyword is a hypothesis; record unsupported scope before selecting a producer.
- Classify patch registrations before counting functions or consumers: instruction entry, operand/immediate, data pointer and callback are different evidence. Keep raw control IDs, key codes and producer-specific modifier masks distinct.
- Prefer function/CFG views when their metadata exists. Distinguish typed identity or a provider body header from CALL XREF comments naming callers; the first symbol token is not an enclosing-function identity. A semantic tool failure or missing function is not absence proof; use a bounded raw window and an independently checked instruction boundary for the concrete missing question. Avoid repeated global analysis without new evidence.
- Inspect producer limits as well as pagination. A last page, zero CLI exit or hash of a cropped span does not prove a complete function. Verify original bytes, whole instructions, table values, returned/omitted budgets and the claimed dataflow. Unknown case labels/defaults remain unknown.
- Bind historical source to immutable artifacts or declared commit manifests. A rolling currentness file is current owner state, not an immutable source snapshot. Preserve old observation identities without substituting today bytes.
- Retain original native algorithms, callbacks, counters, final presentation and cleanup when the implementation scope only adapts input, values or pacing. Recover an opaque callee further when a concrete replacement requires its CFG/type/lifetime contract.
- Record observed, inferred and unverified separately through existing Case/Evidence/Finding/Path owners. Structural verification, professional case readiness, source-reference sufficiency and actual runtime acceptance are distinct claims.
- Compare efficiency only under a matched task/engine/input/query baseline. Subprocess elapsed time and serialized result bytes are neither end-to-end research cost nor model-token usage.
