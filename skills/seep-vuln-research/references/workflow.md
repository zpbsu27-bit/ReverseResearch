# Vulnerability research workflow

surface -> harness -> fuzz/repro -> crash -> dedupe -> minimize -> root cause -> primitive classification -> mitigation -> regression

## Evidence rules

- Every crash has an input identity and structural fingerprint.
- A duplicate crash remains traceable to every input that produced it.
- Minimized input never replaces the original evidence.
- Root cause and security impact stay hypotheses/findings until directly supported.
- Mitigation success requires the prior reproducer to stop reproducing plus negative regression evidence.
