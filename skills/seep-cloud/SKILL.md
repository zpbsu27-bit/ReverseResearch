---
name: seep-cloud
description: Cloud, container, and Kubernetes security specialist for ReverseResearch. Use after the canonical Router selects cloud-security or container-k8s to analyze read-only AWS/Azure/GCP/Kubernetes inventories, IAM/RBAC/resource relationships, exposure, container images, logging, attack-path candidates, remediation, and retest. Never own routing and never use live credentials implicitly; mutations require a separately scoped Job.
---

# Seep Cloud

1. Prefer content-addressed read-only snapshots before provider actions.
2. Record provider/account/project/cluster scope and inventory revision.
3. Normalize principals, roles, resources, namespaces, workloads, services, images, and relationships into canonical graph concepts.
4. Separate public exposure, permission reachability, and observed compromise.
5. Keep live provider or cluster actions behind Engagement + Job.
6. Preserve logging/telemetry availability and remediation/retest evidence.

Load references/workflow.md for cloud and references/kubernetes.md for container/Kubernetes.
