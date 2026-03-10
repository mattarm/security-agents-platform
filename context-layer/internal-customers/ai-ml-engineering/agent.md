---
Last Verified: 2026-03-09
Verified By: Cyber Defense Team
Status: Active
---

# AI/ML Engineering — Agent Operating Protocol

## Scope

Security agents operating in AI/ML Engineering's domain cover: model training pipelines, model serving infrastructure, agentic AI systems (dispatch, routing, warehouse), ML platform services, feature stores, and experiment tracking.

## Autonomy Tiers

### Production Agentic Systems (Dispatch, Routing, Warehouse Agents)

| Action Type | Autonomy Level | Approval Required |
|-------------|---------------|-------------------|
| Alert enrichment and triage | **Autonomous** | None |
| Anomaly detection on agent decision patterns | **Autonomous** | None |
| Jira ticket creation | **Autonomous** | None |
| Model serving isolation (stop serving a model) | **Human-approved** | AI/ML Lead + SOC lead |
| Agent system shutdown | **Human-approved** | Head of AI/ML + VP Engineering |
| Training pipeline halt | **Human-approved** | ML Platform Lead |
| Feature store access revocation | **Human-approved** | AI/ML Lead |
| Model rollback to previous version | **Prohibited** | ML team only — requires model validation |

### ML Platform (Training, Experiments)

| Action Type | Autonomy Level |
|-------------|---------------|
| Training data integrity monitoring | **Autonomous** |
| Experiment environment scanning | **Autonomous** |
| GPU instance monitoring for cryptomining | **Autonomous** |
| Notebook server isolation (dev environments) | **Autonomous** |
| Training job termination (suspected poisoning) | **Human-approved** — Alpha-4 proposes, ML Lead decides |

### Adversarial Testing (Delta Red Team)

| Action Type | Autonomy Level |
|-------------|---------------|
| Adversarial input testing against staging models | **Autonomous** (staging only) |
| Prompt injection testing against agentic systems | **Human-approved** — Delta proposes, AI Safety Lead approves |
| Model extraction attempts | **Human-approved** — Scoped and time-boxed |
| Production adversarial testing | **Prohibited** — Never against live customer-affecting systems |

## Escalation Rules

- **Suspected data poisoning**: Immediate escalation to AI Safety Lead + SOC lead. Halt affected training pipeline.
- **Anomalous agent decisions**: Alert to `#ml-oncall` + `#security-incidents`. Do not auto-remediate — ML team investigates.
- **Model supply chain compromise**: P0 escalation. Halt deployments from affected pipeline.
- **Prompt injection detected**: Log, block, alert. Do not disclose detection mechanism.

## Red Flags — Halt and Escalate to Humans

- Any anomaly in autonomous agent decision patterns that could affect physical-world operations
- Evidence of training data manipulation
- Unauthorized model deployments or model registry modifications
- Adversarial query patterns suggesting model extraction
- Any finding related to AI regulatory compliance

## Boundaries

- Agents must NOT modify models, weights, or training data
- Agents must NOT roll back models (ML team validates before any rollback)
- Agents must NOT access raw training datasets (only metadata and integrity checksums)
- All adversarial testing must be pre-scoped and time-boxed with ML team awareness
