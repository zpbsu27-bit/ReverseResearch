---
name: seep-identity
description: Evidence-first identity and Active Directory security workflow for imported principals, groups, sessions, trusts, certificate templates, permissions, and attack-path graphs. Use when work is routed to identity-ad and needs currentness, opaque credential references, scoped analysis, or remediation/retest without executing credential-bearing actions implicitly.
---

# Seep Identity

Use the canonical Router result; this skill never owns task classification (`owns_routing=false`).

## Workflow

1. Freeze Engagement scope, domain/tenant identity, target allowlist, time window, and allowed identity actions.
2. Prefer imported identity inventory and graph evidence before live collection.
3. Represent users, computers, groups, domains, trusts, sessions, certificate templates, services, roles, and permissions as typed nodes/edges.
4. Store passwords, tokens, tickets, keys, and reusable credentials only as opaque credential references; never put them in graph properties or Evidence excerpts.
5. Treat BloodHound/SharpHound/Impacket/NetExec/Certipy output as source-attributed observations, not proof that a path was exploited or a credential is valid now.
6. Any credential-bearing or active identity action requires a scoped Generic Job with explicit operation identity and cleanup.
7. Link remediation and retest to the exact graph/source revision.

Read `references/workflow.md` for the canonical sequence.
