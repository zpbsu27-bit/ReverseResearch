# Cloud security workflow

1. Freeze provider/account/subscription/project/cluster scope and inventory revision.
2. Import or collect a bounded inventory through a reviewed adapter.
3. Normalize principals, roles, resources, trust, exposure, workloads, services, and image identities into the canonical graph.
4. Treat reachability/permission edges as observations until currentness is corroborated.
5. Keep secrets out of artifacts; use opaque credential references.
6. Any live provider or Kubernetes mutation requires Engagement + Generic Job.
7. Link remediation and retest to a fresh inventory revision.

Use `cloud.md` for AWS/Azure/GCP details and `kubernetes.md` for container/Kubernetes work.
