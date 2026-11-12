---
name: seep-dfir
description: DFIR specialist for ReverseResearch. Use after the canonical Router selects dfir-forensics to ingest memory/disk/event/registry/network artifacts, normalize provenance-linked timelines, correlate process/user/network activity and create evidence-backed incident findings. Never own routing and never replace raw evidence with normalized events.
---

# Seep DFIR

1. Freeze every raw artifact identity before parsing.
2. Select parsers/adapters from artifact truth and ToolIndex; do not guess formats.
3. Preserve raw EVTX, memory, disk, registry, MFT/USN, Prefetch/Amcache/SRUM and PCAP evidence unchanged.
4. Normalized events must retain source artifact SHA and source record/line reference.
5. Count rejected/unparsed records explicitly.
6. Correlate timeline, process, user/session, persistence and network relations without erasing uncertainty.
7. Findings must link back to raw evidence, not only tool output.
8. Record cleanup of temporary extraction/cache data.

Load references/workflow.md for ingest and timeline rules.
