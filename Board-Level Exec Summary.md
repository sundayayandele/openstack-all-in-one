Board-level Executive Summary
Date: 2026-02-20

Board-level Executive Version: Private Cloud Web Platform (OpenStack + Kubernetes + GitOps)
**Date:** 2026-02-20

Why we are doing this
We are building a **repeatable, secure, regulator-ready** private-cloud platform to deploy websites as microservices using:
- OpenStack (private cloud)
- Kubernetes (application platform)
- GitOps (controlled, auditable delivery)

This enables fast delivery of environments (dev/test/acceptance) while keeping data and operations under full organizational control.

---

What will be delivered
**Platform**
- Small Kubernetes cluster (3 nodes) on OpenStack VMs
- Ingress for controlled external access (single public IP)
- Persistent storage for databases and uploads
- Observability and policy guardrails

**Applications**
- Three isolated environments: `dev`, `test`, `acc`
- Each environment runs:
  - WordPress service
  - PostgreSQL database service

**Governance**
- Infrastructure as Code (Terraform)
- GitOps deployment (Argo CD): every change is versioned, reviewed, and auditable
- Security baseline aligned to ISO 27001 controls and DORA objectives citeturn0search24turn1search7

---

Key business benefits
1. **Speed**: environments can be recreated in minutes, not days
2. **Risk reduction**: fewer manual errors; controlled change management
3. **Audit readiness**: traceability from code commit → deployment
4. **Sovereignty**: runs fully on private infrastructure
5. **Scalability**: same pattern extends to more apps or teams

---

Risk & mitigation
- **Single public IP**: mitigate with ingress and tight security groups; later upgrade to LBaaS/HA
- **WordPress + PostgreSQL compatibility**: validate plugin set early; switch to MariaDB if needed
- **Availability**: Phase 2 introduces auto-healing and HA expansion options

---

Roadmap
- **Phase 1**: Platform + GitOps + 3 environments (this repo)
- **Phase 2**: Agentic self-healing operations (see blueprint) — automated remediation and compliance evidence

---
