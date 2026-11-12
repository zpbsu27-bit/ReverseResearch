---
name: seep-cti
description: Cyber-threat-intelligence specialist for ReverseResearch. Use after the canonical Router selects cti-analysis to work with STIX/TAXII-style IOC, malware, campaign, intrusion-set, infrastructure, vulnerability, observed-data, attack-pattern, and relationship objects while preserving source revision and confidence. Never own routing and never automatically upload private Case data to MISP, OpenCTI, TAXII, or other services.
---

# Seep CTI

1. Freeze intelligence source identity, revision, and collection time.
2. Normalize supported objects and typed relationships without erasing raw source provenance.
3. Keep unsupported/rejected objects explicit.
4. Distinguish source claims, analyst inference, and Case observation.
5. Qualify attribution and confidence; do not infer motive from weak relationships.
6. Treat external sharing/export as a separate explicit action.

Load references/workflow.md for CTI normalization and relationship handling.
