# Failure Catalog

A matching symptom is a stop signal. Record the failed hypothesis before trying another layer.

| Symptom | Likely wrong assumption | Next measurement |
| --- | --- | --- |
| APK rebuild/sign succeeds but startup fails in an unrelated library | Packaging cleanup was assumed harmless | Compare archive entries, especially service/provider metadata, against the control build |
| DEX checksums/signature look correct but runtime rejects the dex | Byte validity was confused with structural validity | Check string/table ordering, instruction boundaries and loader diagnostics |
| Whole-tree smali round-trip looks equivalent statically but crashes only at runtime | Rebuild was assumed semantics-preserving | Return to a minimal method/byte edit and compare runtime behavior |
| Re-signed APK launches normally but every signed/API request fails | Functional patch was blamed while the signing certificate may feed request key derivation | Compare original vs rebuilt runtime certificate-derived input and the same computed request-signing field before further patching |
| Only login/registration/payment or one API-backed screen fails while the rest works | A feature-scoped TLS/certificate path was mistaken for a patch regression | Capture full exception chain, runtime host/trust stack, device clock, and an unmodified-original control on the same device/network |
| Split APK set fails only after re-sign/install-multiple | Base APK was treated as the whole signing unit | Inventory the complete split set and prove every member uses one signing identity; treat merge as a separate transformation |
| Native patch changes a crash into a silent hang | A non-returning terminate path was replaced with another non-returning path | Inspect caller expectations and prove return/control-flow behavior |
| Forged login/session passes a local gate but data remains empty | Resource was assumed client-scoped | Compare authorized account/server responses before more client patching |
| Same attach/start action fails twice | Parameters are assumed wrong | Stop; inspect existing process/port/session ownership and change the hypothesis |
| Ghidra import fails only for a Unicode basename | External path support was conflated with internal project item naming | Preserve original path identity and use the existing content-addressed ASCII alias path |
| Old version RVA/name works in notes but not in the new binary | Historical mapping was treated as current proof | Re-identify the target and perform version-bound diff/currentness checks |
| Browser replay differs despite identical visible form inputs | Hidden session/time/device state was ignored | Capture a full controlled baseline including tokens/nonces/cookies and server state |
| Web result varies by account while client code is unchanged | Client code was assumed authoritative | Treat it as a server/resource-scope question until disproved |
| Suspected Dex-VMP opcode mapping changes shape per method or code length moves | A known-plaintext opcode substitution model was assumed without its preconditions | Prove body-present + same-length + stable per-opcode substitution first; otherwise mark the differential route not applicable |
| A previously rejected explanation keeps reappearing after context changes | Retraction/dead-route evidence was not consulted | Search Journal/Case precedent and carry the disproving measurement forward before a new experiment |

## Two-strike enforcement

After two failures with the same observable shape:
1. append the dead end to the case;
2. state which assumption is now unsupported;
3. select a different measurement or layer;
4. do not run a third cosmetic variant of the same hypothesis.
