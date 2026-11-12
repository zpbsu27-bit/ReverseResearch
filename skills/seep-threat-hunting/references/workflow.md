# Threat hunting workflow

1. Define hypothesis, time window, population, ATT&CK technique candidates, and expected observable behavior.
2. List required telemetry (for example EVTX/Sysmon, EDR, DNS, proxy, Zeek, Suricata, cloud audit, Kubernetes audit, osquery).
3. Verify telemetry availability and field/currentness assumptions.
4. Prepare read-only adapters such as Sigma/EQL/KQL/Splunk/osquery/Zeek queries without treating preparation as execution.
5. Run separately scoped searches, then preserve source identity and raw results as Evidence.
6. Update the hypothesis with supporting/conflicting evidence; use rejected/retracted states when disproven.
7. Convert confirmed gaps into Detection/Mitigation work and retest against fresh telemetry.
