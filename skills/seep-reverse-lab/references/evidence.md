# Evidence Discipline

ReverseResearch already stores Evidence -> Finding -> Path in the casebook. Use that owner instead of parallel notes when possible.

## Evidence

Evidence is an immutable observation. Prefer:
- source path + SHA-256/size for files;
- process key for live Windows processes;
- package/build/signature identity for Android;
- URL/session/build plus request/response identity for Web;
- exact command/tool/operation identity when reproducibility matters.

If a statement is inferred rather than directly observed, say so in the evidence notes.

## Findings

A Finding is a conclusion supported by one or more evidence IDs. Grade evidence strength independently from subjective confidence:

- `observed` - the claimed fact was directly produced by a recorded command/capture and its evidence exists;
- `inferred` - the conclusion follows from observations but the transition itself was reasoned, not directly measured;
- `unverified` - an assumption, historical report, or hypothesis that has not been reproduced here.

New Case Findings default to `unverified` until explicitly graded. Legacy findings without a strength remain readable and are counted as ungraded by verification; do not silently rewrite them. Keep confidence calibrated separately. Do not promote a candidate to validated because several observations came from the same measurement source.

## Paths

A Path links the important sequence:
- Windows/native: call/data/control-flow or patch/Hook chain;
- Android: package -> code/load layer -> mutation/instrumentation -> runtime effect;
- Web: page/module -> client computation -> request/protocol -> server result.

## Reusable journal

Only reusable, target-independent lessons should graduate to the knowledge journal. Keep target secrets, credentials, private payloads and proprietary data in the user's case artifacts, not in generic skill references.

A reusable precedent must include the route that converged **and** the dead end/retracted claim that measurement disproved. Search these precedents before rerunning the same class of work. A success-only story loses the most transferable information.

## Completion review

For a broad investigation, break the conclusion into concrete claims before collecting evidence. Associate each claim with its existing Case evidence IDs and record pass, fail, unsupported, unknown or truncated in the review notes/WorkItems; do not create a second completion store. A collection of successful commands does not close the claims that they never measured.

Retain the observation authority with the source location: artifact bytes, historical producer record, static inference, or current runtime observation. A source-map declaration and an old capture remain tied to their exact artifact digest. They do not identify the current browser process or authenticate the original server outcome.

Keep original item indices/JSON pointers when selecting a subset. Preserve total/returned/omitted counts, byte budgets, unavailable reasons and pagination fences. Combining pages requires the same artifact digest throughout; a final page alone is not complete coverage. Unsupported, unknown and truncated claims remain open unless a different measurement addresses the missing proof.

For protocol captures, keep the raw artifact digest plus the exact retained byte/line span. A proxy's parsed summary and an application payload digest are derived observations; neither replaces the original bytes, transport metadata or server/executor receipt. An emitted tool call is a request for execution. Link the corresponding outcome by call/operation identity before grading the execution claim. Connection EOF, stream markers and HTTP 200 alone do not settle completion.

For reconstruction, record the acceptance boundary and independent input/output fixtures beside the claim. Preserve partial success, null/missing fields, error and interrupted-stream behavior. An implementation fixture that was generated from the same inferred model is not independent evidence of equivalence.

Before closing a case, verify:
- referenced evidence still exists/currently hashes;
- every important Finding has evidence;
- the Path does not skip an unproved transition;
- cleanup state is recorded.
