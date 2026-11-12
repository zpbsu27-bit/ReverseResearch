---
name: seep-reverse-lab
description: Local-first orchestration for multidisciplinary reverse engineering and security research in the Seep-Reverse-Lab / ReverseResearch workspace. Use when an agent must classify a reverse task, select the existing ReverseResearch route and MCP tools, check the local toolchain and session state before acting, preserve Evidence -> Finding -> Path traceability, apply platform-specific failure lessons, or decide whether a task is complete. Prefer existing Core/MCP owners over ad-hoc commands and load only the platform reference needed for the current task.
---

# Seep Reverse Lab

Use this skill as the control plane. Keep detailed platform knowledge in references/ and load only the file selected by the canonical router.

## Control rules

1. Treat config/routes.json as the task-routing source of truth and config/playbooks.json as the route-to-workflow source of truth. Prefer MCP task_prepare or CLI ReverseResearch prepare <task>; use task_route only when classification alone is needed.
2. Refresh the machine-local tool inventory with MCP tool_index_scan or CLI ReverseResearch tools scan. Do not guess executable paths and do not auto-install replacements.
3. Preserve existing user sessions. Never kill, restart, attach to, or reuse an existing debugger, Ghidra, browser, Android, proxy, or device session merely to make automation easier.
4. Separate observation from mutation. Read-only discovery may run automatically; installs, target mutation, runtime writes, active network actions, signing, deployment, or device changes require the platform's existing guard/lease/currentness boundary.
5. Store conclusions as Evidence -> Finding -> Path. Grade each new Finding as `observed`, `inferred`, or `unverified`; keep subjective confidence separate from evidence strength. A remembered fact or a clean log is not proof.
6. When the same failure shape happens twice, stop changing parameters. Load references/failure-catalog.md, revise the hypothesis, and choose a different measurement.
7. Do not claim "done" until the completion gate below passes.

## Workflow gates

### G1 - Classify

Run task_prepare / prepare and record the selected route, playbook ID, specialist Domain Pack/Skill when present, reviewed Knowledge/Standards Packs, target identity, Engagement/Scope, and requested deliverable. If no playbook exists, do not force-fit the task into Windows/Android/Web.

For Android/Web deliverables, make the constraint testable before acting: artifact vs live instrumentation/module/proxy, root/privilege requirement, ABI/device class, network dependency, persistence, and whether the result must be self-contained/distributable. A privileged runtime workaround is a fallback, not proof of an unrooted standalone artifact.

Pass only when the target and deliverable are concrete enough to measure.

### G2 - Establish environment truth

Refresh the tool index. On Windows, run scripts/doctor.ps1 when session contamination could change results. If tools are installed outside PATH, use the explicit `REVERSERESEARCH_TOOLS` directory list rather than guessing paths.

Before the first mutation, inspect the reviewed Knowledge/Standards Packs returned by `prepare`, then query the existing Journal/Case knowledge for a matching route, symptom, or toolchain. Read prior dead ends and retractions before repeating the experiment; a precedent is useful before you are stuck, not only after.

Pass only when:
- required tools are known present or explicitly missing;
- existing sessions are identified;
- the plan will not consume another task's port/profile/project/device;
- optional backends remain lazy until needed;
- relevant prior precedent/dead-route records were checked, or explicitly none exist.

### G3 - Freeze a control baseline

Before the first mutation, capture the cheapest reproducible baseline:
- file/package hash and architecture/build identity;
- original runtime behavior or request/response;
- current module/session state;
- expected cleanup condition.

Pass only when the control can distinguish a real effect from an environment change.

### G4 - Act at the narrowest layer

Load exactly the reference/Skill returned by the canonical playbook and Domain Pack. Master references still cover Windows/native, Android/APK and Web/JS/protocol; specialist Domain Packs currently cover Malware, Blue Detection and Purple Validation. Never classify a task inside a specialist Skill.

Before an effectful specialist action, require current Engagement/Scope authorization and a prepared Generic Job. Prefer the smallest reversible operation that answers the question. Record Evidence and Timeline/WorkItem progress as the operation completes.

## Two-strike rule

Two failures with the same observable shape invalidate the current hypothesis or measurement layer. Do not try a third cosmetic variant. Record the dead end, consult the failure catalog, and move one layer up/down or obtain a different independent measurement.

## Completion gate

A task is complete only when all applicable items hold:

1. target/build identity is frozen;
2. route and actual toolchain are recorded;
3. a control/baseline exists;
4. the claimed effect is reproduced or independently cross-checked;
5. Evidence -> Finding -> Path links support the conclusion, with uncertainty stated;
6. task-owned temporary state is cleaned and unrelated user sessions remain untouched;
7. complex professional Cases pass structural verification and the strict Case review gate before report/handoff.

If any item is missing, report a checkpoint and the exact remaining proof instead of saying done.

## References

- references/windows.md - PE/native/game DLL, Ghidra/radare2/x32/x64dbg, patch/hook/currentness.
- references/android.md - APK/DEX/native/Flutter, repack/runtime choices, Android gates and common false leads.
- references/web.md - JS/Electron/WASM/browser/network/protocol workflow and profile isolation.
- references/failure-catalog.md - paid-for failure patterns and stop signals.
- references/evidence.md - evidence grading and reusable case recording.
- references/upstream.md - upstream inspirations, pinned revisions, and adoption boundaries.
