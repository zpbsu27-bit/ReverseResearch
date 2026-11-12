# Identity / AD workflow

1. Record domain/tenant, collection source, tool version, and source revision.
2. Normalize identity graph nodes and typed edges such as `member-of`, `admin-of`, `trusts`, `authenticates-to`, `can-assume`, `reachable-from`, and `can-access`.
3. Reject secret-bearing graph properties; use opaque credential-reference nodes when needed.
4. Compute attack paths as candidates only. Corroborate high-impact edges with current evidence before creating Findings.
5. Separate offline graph analysis from active Kerberos, LDAP, SMB, certificate, or credential-bearing operations.
6. Active operations require Engagement + Generic Job and must record rate limits, target scope, receipt, and cleanup.
7. Retest from a new current inventory after remediation.
