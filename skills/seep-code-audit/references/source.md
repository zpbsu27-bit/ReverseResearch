# Source / supply-chain workflow

repository identity -> bounded inventory -> dependency/SBOM -> SAST/dataflow -> secret candidates -> triage -> Finding -> remediation -> retest

Built-in inventory is intentionally bounded and read-only. External scanners are adapters and their stdout is never a final Finding.

Secret candidates are always redacted in normal output; preserve only a one-way fingerprint plus source location and strength.
