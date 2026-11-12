# Seep-Reverse-Lab skill index

This directory contains the master orchestrator plus specialist skill packs. `seep-reverse-lab/` owns orchestration; specialist skills own domain methods only.

The ownership boundaries are intentionally separate:

- `config/routes.json` — task -> capability route; the only task-classification source.
- `config/playbooks.json` — route -> platform playbook, gates, done criteria and the platform reference inside the master skill.
- `skills/seep-reverse-lab/SKILL.md` — the short master control loop.
- `config/domain-packs.json` — domain pack manifest binding routes to specialist skills/playbooks/capabilities without owning routing; each pack records source/license/trust metadata and can be statically audited.
- `config/knowledge-packs.json` — reviewed standards/knowledge bundles bound to canonical routes; this is enrichment, never a second classifier.
- `config/tool-metadata.json` + `config/tool-recipes.json` — ToolIndex v2 provenance/policy metadata plus Tool Recipe v2 acquisition contracts.
- `skills/seep-malware/`, `skills/seep-blueteam/`, `skills/seep-purple-team/` — first specialist packs; each declares `owns_routing=false` by contract.
- `skills/seep-native-reverse/`, `skills/seep-vuln-research/`, `skills/seep-dfir/`, `skills/seep-protocol/`, `skills/seep-code-audit/` — P1 specialist packs for Linux/ELF, vulnerability/fuzzing, DFIR, protocol RE, and source/supply-chain audit.
- `skills/seep-redteam/`, `skills/seep-identity/`, `skills/seep-cloud/`, `skills/seep-mobile/`, `skills/seep-firmware/`, `skills/seep-cti/`, `skills/seep-threat-hunting/` — P2 specialist packs for scoped network/red-team work, identity/AD graphs, cloud/Kubernetes, iOS, firmware/IoT, CTI, and hypothesis-driven hunting.
- `skills/seep-reverse-lab/references/` — progressively loaded Windows, Android, Web, evidence and failure material.
- `skills/seep-reverse-lab/scripts/doctor.ps1` — read-only Windows environment/session preflight.

Use `ReverseResearch prepare <task>` or MCP `task_prepare` for the joined route + playbook + Domain Pack + Knowledge/Standards Packs + capability/provision/sandbox view. Use `task_route` only for classification, `playbook_get` for one workflow, and `tool_index_scan` for machine-local tool truth.

A playbook is not proof that its runtime adapter exists or ran. Pending Android/Web execution owners remain explicit in the implementation plan.


Use `ReverseResearch domain-pack audit <pack-id>` or MCP `domain_pack_audit` before trusting newly imported specialist content. Builtin packs must have zero high-risk audit findings in the regression suite.
