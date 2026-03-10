---
Last Verified: Not yet verified
Verified By: —
Status: Draft
---

# [Team Name] — Agent Operating Protocol

## Scope

<!-- What systems and environments do security agents operate in for this customer? -->

## Autonomy Tiers

### Production Environment

| Action Type | Autonomy Level | Approval Required |
|-------------|---------------|-------------------|
| Alert enrichment and triage | **Autonomous** | None |
| Jira ticket creation | **Autonomous** | None |
| Containment actions | **Human-approved** | <!-- who approves? --> |

### Non-Production

| Action Type | Autonomy Level |
|-------------|---------------|
| Alert enrichment and triage | **Autonomous** |
| Containment actions | **Autonomous** |

## Escalation Rules

<!-- P0-P3 escalation paths and SLAs -->

## Red Flags — Halt and Escalate to Humans

<!-- Conditions that should always stop automation and require human judgment -->

## Boundaries

<!-- What agents must NOT do in this customer's domain -->
