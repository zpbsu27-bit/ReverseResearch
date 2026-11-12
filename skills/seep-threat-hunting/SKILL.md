---
name: seep-threat-hunting
description: Hypothesis-driven threat-hunting workflow for declared telemetry sources, ATT&CK techniques, read-only query adapters, conflicting evidence, and retest. Use when work is routed to threat-hunting and must distinguish a hunt plan from an executed search while preserving raw evidence and normalized analysis separately.
---

# Seep Threat Hunting

Use the canonical Router result; this skill never owns task classification (`owns_routing=false`).

## Workflow

1. Write a falsifiable hypothesis and identify the affected population/time window.
2. Declare required telemetry and current availability before selecting adapters.
3. Use read-only query/search adapters by default; a hunt plan is not an executed search.
4. Preserve raw telemetry identity and source revision separately from normalized events.
5. Record supporting and conflicting evidence; reject or retract disproven hypotheses instead of deleting them.
6. Map confirmed behavior to ATT&CK and Detection coverage only after evidence supports the relationship.
7. Link any rule/remediation change to retest evidence.

Read `references/workflow.md` for the canonical sequence.
