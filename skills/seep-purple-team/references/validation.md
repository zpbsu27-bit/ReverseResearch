# Purple validation chain

Canonical chain:

ATT&CK TTP -> scoped emulation Job -> telemetry -> Detection -> gap -> mitigation/countermeasure -> retest Evidence

## Required records

- Engagement and exact target/action scope
- operation/job receipt and effect class
- expected telemetry
- actual telemetry evidence
- Detection revision evaluated
- observed hit/miss
- gap classification
- mitigation or D3FEND-oriented countermeasure reference
- retest evidence and final status

A missing detection hit is not automatically a product defect: distinguish absent telemetry, collection failure, parser/normalization failure, rule logic gap, deployment mismatch, and expected non-coverage.
