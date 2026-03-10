---
Last Verified: 2026-03-09
Verified By: Cyber Defense Team
Status: Active
---

# Platform Engineering — Agent Operating Protocol

## Scope

Security agents operating in Platform Engineering's domain cover: production SaaS services, staging environments, CI/CD pipelines for platform repos, customer-facing APIs, and associated data stores.

## Autonomy Tiers

### Production Environment

| Action Type | Autonomy Level | Approval Required |
|-------------|---------------|-------------------|
| Alert enrichment and triage | **Autonomous** | None |
| Severity scoring and SLA assignment | **Autonomous** | None |
| Jira ticket creation for findings | **Autonomous** | None |
| CrowdStrike host isolation | **Human-approved** | SOC analyst or Platform Engineering on-call |
| Network containment (security group changes) | **Human-approved** | SOC analyst + Infrastructure on-call |
| API gateway rate-limit override | **Human-approved** | Platform Engineering on-call |
| DNS sinkholing | **Human-approved** | SOC lead |
| Database access revocation | **Human-approved** | Platform Engineering VP + SOC lead |
| Service rollback | **Prohibited** | Not in security agent scope — SRE only |

### Staging Environment

| Action Type | Autonomy Level |
|-------------|---------------|
| Alert enrichment and triage | **Autonomous** |
| Host isolation | **Autonomous** |
| Container termination | **Autonomous** |
| Network containment | **Autonomous** |
| Automated vulnerability scanning | **Autonomous** |

### CI/CD Pipelines

| Action Type | Autonomy Level |
|-------------|---------------|
| GHAS alert triage and severity | **Autonomous** |
| PR blocking for critical/high findings | **Autonomous** |
| Dependency vulnerability alerting | **Autonomous** |
| Build pipeline halt for supply chain risk | **Human-approved** — Beta-4 proposes, Platform Eng decides |

## Escalation Rules

- **P0 (Critical)**: Immediate Slack alert to `#security-incidents` + `#platform-oncall`. Page Platform Engineering on-call and SOC lead. Response SLA: 15 minutes.
- **P1 (High)**: Slack alert to `#security-findings`. SOC analyst triage within 1 hour.
- **P2 (Medium)**: Jira ticket auto-created. Triage within 1 business day.
- **P3 (Low)**: Jira ticket auto-created. Triage within 1 week.

## Red Flags — Halt and Escalate to Humans

- Any action that would cause customer-visible service disruption
- Findings involving customer data exfiltration
- Evidence of active adversary in production environment
- Compliance-impacting findings (PCI scope, SOC 2 controls)
- Any containment action on the billing service (payment processing)

## Boundaries

- Agents must NOT access customer data directly — only metadata and telemetry
- Agents must NOT modify application code or configuration
- Agents must NOT communicate directly with external customers about security findings
- All agent actions in production logged to immutable audit trail
