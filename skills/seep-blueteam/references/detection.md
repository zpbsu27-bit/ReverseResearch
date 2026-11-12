# Detection validation matrix

A Detection is not validated until all applicable checks are recorded:

1. source Finding/TTP and evidence IDs;
2. telemetry source and required fields;
3. rule format and revision;
4. syntax/schema validation;
5. positive fixture with expected hit;
6. negative fixture with expected non-hit;
7. false-positive notes;
8. coverage statement;
9. deployment/query adapter assumptions;
10. evidence-backed retest.

Supported first-class artifact families are Sigma, YARA/YARA-X, Suricata, and Zeek. EQL/KQL/Splunk are adapters over the same canonical Detection object.

Do not erase a superseded rule. Retain revision lineage and the evidence that caused replacement.
