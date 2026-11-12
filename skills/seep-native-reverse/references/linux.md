# Linux / ELF workflow

## Sequence

1. Identify the exact ELF and record SHA-256, class, byte order, machine, type, entry point and build-id.
2. Inventory sections, symbols, dynamic dependencies and relevant mitigations without modifying the target.
3. Use Ghidra/radare2 for static recovery and retain address/revision provenance.
4. For core dumps, keep dump identity and module/load-map context with every conclusion.
5. If live execution is necessary, bind it to current Engagement scope and a Generic Job before GDB/LLDB/rr activity.
6. Record runtime observations separately from static hypotheses.
7. Verify cleanup and Case currentness before handoff.

## Stop conditions

Stop and report the gap when architecture/tool compatibility is unknown, the ELF changes during inspection, or runtime authorization is absent.
