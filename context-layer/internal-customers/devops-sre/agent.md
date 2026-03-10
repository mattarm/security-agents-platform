---
Last Verified: 2026-03-09
Verified By: Cyber Defense Team
Status: Active
---

# DevOps/SRE — Agent Operating Protocol

## Scope

Security agents operating in DevOps/SRE's domain cover: AWS accounts (all environments), EKS clusters, CI/CD infrastructure, container registries, IaC repositories, secrets management, DNS, CDN, and the observability stack.

## Autonomy Tiers

### Production AWS + Kubernetes

| Action Type | Autonomy Level | Approval Required |
|-------------|---------------|-------------------|
| Alert enrichment and triage | **Autonomous** | None |
| GuardDuty/Security Hub finding triage | **Autonomous** | None |
| Jira ticket creation | **Autonomous** | None |
| Security group modification (block malicious IP) | **Human-approved** | SRE on-call + SOC analyst |
| IAM policy change (revoke compromised credential) | **Human-approved** | SRE Lead + SOC lead |
| EKS pod termination (compromised container) | **Human-approved** | SRE on-call |
| AWS account isolation | **Human-approved** | Head of Infrastructure + CISO |
| Route53 DNS changes | **Prohibited** | SRE only — customer-impacting |
| Terraform state modification | **Prohibited** | Never — GitOps only |

### Staging/Development AWS

| Action Type | Autonomy Level |
|-------------|---------------|
| Security group modifications | **Autonomous** |
| Pod termination | **Autonomous** |
| IAM credential rotation (service accounts) | **Autonomous** |
| Infrastructure scanning | **Autonomous** |

### CI/CD Infrastructure

| Action Type | Autonomy Level |
|-------------|---------------|
| Pipeline security scanning | **Autonomous** |
| Secret detection in repos | **Autonomous** |
| GitHub Actions workflow review | **Autonomous** |
| Pipeline halt for critical findings | **Human-approved** — Beta-4 proposes, SRE Lead decides |
| Container image blocking (vuln threshold) | **Autonomous** for Critical CVEs, **Human-approved** for High |

## Escalation Rules

- **Compromised AWS credentials**: P0 — Immediate escalation. Rotate credential immediately (pre-approved action). Alert `#infra-oncall` + `#security-incidents`.
- **Unauthorized IAM changes**: P0 — Halt and investigate. Page SRE Lead and SOC lead.
- **Kubernetes compromise indicators**: P1 — Alert SRE on-call. Propose containment, await approval.
- **Infrastructure drift detected**: P2 — Jira ticket. Flag for next Terraform plan/apply cycle.
- **Secret exposure in repo**: P1 — Auto-rotate if rotation is automated. Alert `#infra-oncall`.

## Red Flags — Halt and Escalate to Humans

- Any action that could cause cross-service outage
- Modifications to production network topology
- Changes to IAM policies with broad scope (AdministratorAccess, PowerUser)
- Any access to Terraform state files
- DNS or CDN configuration changes
- Evidence of lateral movement from compromised infrastructure

## Boundaries

- Agents must NOT modify Terraform state or IaC code directly
- Agents must NOT make DNS changes
- Agents must NOT access Vault root tokens or master keys
- Agents must NOT modify observability configuration (could blind responders)
- All infrastructure actions logged to CloudTrail and immutable audit trail
