---
name: seep-protocol
description: Protocol reverse specialist for ReverseResearch. Use after the canonical Router selects traffic-protocol to analyze PCAP/raw messages, infer candidate framing/fields/endian/length/checksum/state relationships, generate parser/schema candidates and validate them by fixtures and round-trip. Never own routing and never promote a statistical candidate to validated without proof.
---

# Seep Protocol

1. Freeze the raw PCAP/message corpus and direction/session context.
2. Compare multiple messages before inferring field boundaries.
3. Mark stable offsets, varying offsets, endian, length and checksum results as candidates.
4. Keep encryption/compression hypotheses separate from observed framing.
5. Generate parsers/Kaitai/dissectors only as projections of the current corpus.
6. Validate candidates against held-out fixtures and round-trip serialization where applicable.
7. Record parser/schema revision and source corpus identity.
8. Do not send active network traffic unless Engagement scope explicitly allows it.

Load references/workflow.md for the inference and validation sequence.
