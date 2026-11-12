# CTI analysis workflow

1. Freeze STIX/source identity and revision.
2. Import supported objects and relationships locally; preserve attribution and timestamps.
3. Keep unsupported or rejected content explicit rather than guessing semantics.
4. Do not upload private Case data or synchronize to TAXII/MISP/OpenCTI implicitly.
5. Link corroborated CTI to IOC/TTP/Findings without turning external claims into observed local facts.
6. For hunting, hand off to the dedicated `seep-threat-hunting` skill.

See `cti.md` for ingestion details and `hunting.md` for the shared hunt-model background.
