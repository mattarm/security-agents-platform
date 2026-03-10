---
Last Verified: 2026-03-09
Verified By: Cyber Defense Team
Status: Active
---

# DevOps/SRE — Security Customer Profile

## Team Overview

DevOps/SRE owns the cloud infrastructure, CI/CD pipelines, container orchestration, and observability stack that everything else runs on. They operate the AWS multi-account environment, manage Kubernetes clusters, and maintain the deployment tooling used by all other engineering teams.

## Criticality

**Tier 1** — Infrastructure foundation. Every service, every agent, every customer interaction depends on the reliability and security of what this team operates. Compromise here is compromise everywhere.

## Ownership

### Services & Systems
- AWS multi-account environment (production, staging, development, security, shared-services)
- EKS clusters (production and staging Kubernetes)
- CI/CD pipelines (GitHub Actions, ArgoCD for GitOps deployment)
- Container registry (ECR with image scanning)
- Infrastructure as Code (Terraform modules, state management)
- Observability stack (Prometheus, Grafana, Loki, PagerDuty)
- DNS and CDN (Route53, CloudFront)
- Secrets management (AWS Secrets Manager, HashiCorp Vault)
- VPN and network connectivity

### Key Repositories
- `infrastructure-terraform`
- `k8s-manifests`
- `ci-cd-pipelines`
- `observability-config`
- `security-baseline`

## Data Classification

| Data Type | Classification | Notes |
|-----------|---------------|-------|
| Infrastructure secrets | **Restricted** | AWS credentials, API keys, TLS certificates |
| Deployment credentials | **Restricted** | CI/CD tokens, container registry access |
| Terraform state | **Restricted** | Full infrastructure topology and configuration |
| Audit logs | **Confidential** | CloudTrail, VPC flow logs, access logs |
| Monitoring data | **Internal** | Metrics, dashboards, alerting configuration |

## Regulatory Exposure

- **SOC 2 Type II** — Infrastructure controls (access management, change management, availability)
- **AWS Shared Responsibility Model** — "Security of the cloud" vs. "security in the cloud" boundary
- **PCI-DSS** — Network segmentation, access controls for cardholder data environment
- **Data residency requirements** — Region selection for EU customer data (GDPR)

## Key Contacts

| Role | Name | Contact |
|------|------|---------|
| Head of Infrastructure | TBD | |
| SRE Lead | TBD | |
| Platform Security Engineer | TBD | |
| On-Call Rotation | | `#infra-oncall` in Slack |

## What Security Success Means to This Team

- No infrastructure compromise — no unauthorized access to production
- Least-privilege access enforced (no standing admin access)
- Immutable deployments — all changes through GitOps, no manual production changes
- Zero-trust networking — services authenticate to each other, not just to the perimeter
- Infrastructure drift detected and corrected automatically
- Secrets rotation automated and audited
