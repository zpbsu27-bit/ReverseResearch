# Android / APK Playbook

This playbook distills repeatable lessons from real APK work without importing another project's binaries or target-specific data.

## Offline APK / DEX research

An explicitly offline task uses the canonical `android-static` route and its four static gates. The built-in readers require no device or external decompiler. Use `app_package_inspect` / `app package --family android` for components, manifest declarations and ARSC configurations; use `app_dex_inspect` / `app dex` for classes, method definitions/references and string items. Keep the original APK SHA256 on subsequent pages and attach selected member hashes and byte ranges to the existing Case evidence.

Binary and plain XML attributes are declarations. Resource IDs, typed raw values and bag mappings remain tied to one configuration hash and source member; winning device configuration, overlays, inherited/dynamic symbol pools and reference resolution remain unverified. DEX native flags identify declarations, not loaded native bindings. instructions/cfg/edges select one exact build-local method_index, validate the whole admitted body before paging and retain original byte hashes/code-unit offsets; signed literals are exact decimal JSON strings. Structural CFG includes unreachable instructions and conservative possible catch edges, not typed ART/runtime proof. DEX 041 containers and CompactDex are rejected explicitly.

Code recovery uses the observation-only android-code route and app_android_recover with the pinned JADX 0.7.1 interpreted profile. ToolIndex alone discovers Jar/bridge/java/compiler identities; file presence is not an actual worker/analysis proof. Exact class/method selection, explicit ambiguous overload ordinal, native code absence, initializer smali fallback and unresolved static reference locations remain visible. Result bytes are SHA-fenced canonical JSON base64 pages; subsequent pages require both artifact and result digests. The original backend owner closes each private worker before workspace removal, and uncertain cleanup fails while retaining evidence. Do not treat derived Java/smali or display signatures as original-byte reconstruction, JNI binding or device execution.

Complete static G1–G4 with the existing Case → evidence → finding → path → strict Review → report → Journal owners, verify input currentness and record `target_execution_performed=false`. Preserve split-package and signer/installation limitations. When the requested conclusion requires device behavior, continue through the runtime gates below and leave that conclusion open until the exact device/runtime is available.

## G1 - Classify the artifact

Record:
- APK vs split APK/App Bundle set;
- package/version/signature identity;
- ABI(s) and whether behavior lives in DEX, native .so, Flutter/Dart AOT, a loader/packer, or a server;
- rooted/non-rooted/emulator/physical-device constraints;
- requested deliverable: explanation, patch, repack, runtime instrumentation, module-side change, or service/API understanding;
- delivery constraints: unrooted/rooted, standalone artifact vs live helper, ABI/device class, network dependency, persistence, and distribution/self-containment.

Do not assume a missing feature is client code. Distinguish a client-side gate from an account/server-scoped resource before patching authentication state.

## G2 - Establish environment truth

Run tool-index/doctor first. Check for existing adb/proxy/frida/device sessions and do not reuse them implicitly. Record whether jadx/apktool/adb/frida and required Java tooling are actually available.

For split packages, preserve the set identity and signing relationship. Treat one member extracted from a split install as incomplete until proved otherwise. If a split set must be re-signed for `install-multiple`, every member must use the same signing identity; do not sign only the base. A standalone merge is a separate transformation: inventory code/native/resources/manifest ownership first and refuse to flatten members whose resource semantics are not understood.

## G3 - Control build

Before functional edits, prove that the unmodified decode/rebuild/sign/install path works for this sample, or explicitly record why repack is not the chosen delivery layer.

A successful build/signature check is not a runtime proof. Do not broadly delete META-INF or neighboring metadata just because it looks signature-related; service/provider registrations and runtime metadata may be colocated.

### Before the first re-sign: check signature-derived key material

A rebuilt APK can install and launch perfectly while every signed request fails because the client feeds its own signing certificate into a request-signing/encryption routine. Before blaming the functional patch, search for certificate/signature reads (`PackageInfo.signatures`, `SigningInfo`, `Signature.toCharsString()`/byte-array use) and trace whether the value reaches HMAC/AES/DES/native request helpers or computed request fields such as `sign`/`sig`/`nonce`.

If certificate bytes are part of key derivation, treat the original app's runtime value as authoritative. Offline certificate/container extraction is only a cross-check because the value exposed by Android can differ from the whole JAR/PKCS#7 container. Compare the same request/signing parameter on original and rebuilt controls before changing business logic.

## G4 - Smallest viable change

Prefer surgical, structure-aware edits over full-tree reconstruction.

When working on DEX:
- avoid whole-tree Smali round-trips when a surgical method/byte change can answer the question; optimized/R8 output can drift even when the rebuilt tree looks equivalent;
- preserve table ordering and structural invariants;
- recompute header integrity in the correct order;
- verify decoded instructions and branch targets, not only raw byte length.

When working on native code:
- preserve calling/return behavior unless the control-flow change is the explicit hypothesis;
- a non-returning replacement for a terminate path can convert a crash into a hang rather than neutralize the condition.

When a packer/custom loader is present, first determine whether a decrypted DEX actually exists during process lifetime. Java-to-native transformed code may have no recoverable DEX equivalent.

For a suspected private-opcode/Dex-VMP transformation, do not jump straight to an opcode-table claim. A known-plaintext differential is only meaningful when all three are proved: the hardened method body is still present, instruction-stream length is preserved, and the transform behaves like a stable per-opcode substitution rather than per-method rewriting. If a body is stripped/extracted or resized, the differential route is not applicable. Treat any external hardening-platform submission/retrieval step as an explicit manual boundary rather than pretending the entire chain is automatable.

## Network / server boundary

Classify REST vs protobuf/gRPC/QUIC/custom traffic before choosing tooling. If the same client state still produces account-dependent empty data, investigate server/resource scope rather than repeatedly forging client state.

If only one feature fails (login, registration, payment, one API-backed screen) while the rest of the app works, rule out a feature-scoped TLS/certificate path before touching the patch again. Capture the full exception chain, exact runtime host, trust-stack owner, device clock, and an unmodified-original control on the same device/network. Different HTTP stacks inside one app can use different trust chains, so unrelated requests succeeding does not clear TLS.

## Prior-build / precedent stop conditions

Do not use an unknown third-party "modded" APK as the patching workbench when an original build is available. Re-protected/injected builds can add more layers than the vendor artifact and destroy attribution. Diff them as evidence; patch from a controlled original.

Before repeating a route already attempted in this workspace, search the Journal/Case record and read both the successful chain and the dead ends/retracted explanations. Preserve the retraction alongside the replacement conclusion so the plausible-but-wrong story cannot silently return later.

## Repack stop conditions

Stop iterating on repack parameters when independent checks repeatedly reject the same delivery form. Move to an authorized alternative layer (runtime instrumentation, module-side delivery, local service, or an evidence-only report) instead of treating every block as a build problem.

## Required evidence

For any claimed APK modification, capture at minimum:
- original and delivered artifact identity;
- exact changed method/native location;
- install/launch result;
- runtime behavior proving the intended effect;
- cleanup/restore state.
