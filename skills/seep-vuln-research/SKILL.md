---
name: seep-vuln-research
description: Vulnerability/fuzzing specialist for ReverseResearch. Use after the canonical Router selects vuln-research for harness planning, fuzzing, crash triage/deduplication, root-cause analysis, mitigation and regression. Never own routing and never treat a crash alone as proven exploitability.
---

# Seep Vulnerability Research

1. Freeze target, harness, corpus and tool identities before execution.
2. Keep fuzz execution explicit, scoped and isolated; planning alone never starts an engine.
3. Fingerprint crashes using module + exception + faulting instruction + normalized stack, not exception code alone.
4. Hash minimized/reproducer inputs and preserve the original crash group relationship.
5. Separate crash observation, root-cause hypothesis and exploitability conclusion.
6. Use sanitizers/debuggers as evidence sources and record their exact revisions.
7. Link mitigation/patch findings to regression fixtures.
8. Finish only after positive reproducer and negative regression evidence are current.

Load references/workflow.md for gates and evidence requirements.
