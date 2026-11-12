---
name: seep-firmware
description: Firmware and IoT reverse/security specialist for ReverseResearch. Use after the canonical Router selects firmware-iot to triage immutable firmware images, detect packaging/filesystems/boot formats, plan extraction, identify architecture, analyze services and configuration, and design isolated QEMU/FirmAE-style emulation. Never own routing; raw firmware remains authoritative and flashing/emulation effects require explicit lab scope.
---

# Seep Firmware

1. Freeze raw firmware SHA before extraction.
2. Classify container/filesystem/boot format with bounded reads.
3. Treat extracted filesystems and decompressed images as derived Artifacts linked to the raw image.
4. Establish CPU/boot assumptions as hypotheses until verified.
5. Use isolated emulation for dynamic evidence; never flash hardware implicitly.
6. Record network mode, snapshot, tool versions, artifacts, cleanup, and retest.

Load references/workflow.md for firmware evidence discipline.
