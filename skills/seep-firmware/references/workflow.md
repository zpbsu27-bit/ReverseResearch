# Firmware / IoT workflow

1. Freeze image SHA-256, size, provenance, and requested deliverable.
2. Identify container/filesystem/boot format read-only before extraction.
3. Extract only into a task-owned copy/workspace and hash recovered artifacts.
4. Analyze binaries/configs with source image lineage preserved.
5. Treat EMBA/QEMU/FirmAE or device execution as isolated Lab work with explicit network mode.
6. Do not flash hardware or modify boot state as part of inspection.
7. Persist Findings, mitigations, and retest evidence against exact image/tool revisions.

See `firmware.md` for format/tool guidance.
