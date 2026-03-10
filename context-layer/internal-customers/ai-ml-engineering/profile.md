---
Last Verified: 2026-03-09
Verified By: Cyber Defense Team
Status: Active
---

# AI/ML Engineering — Security Customer Profile

## Team Overview

AI/ML Engineering builds and operates the agentic AI capabilities that are the company's competitive differentiator: autonomous dispatch, route optimization, demand forecasting, warehouse automation agents, and the ML platform infrastructure that supports model training, evaluation, and deployment.

## Criticality

**Tier 1** — Competitive differentiator. These agents make autonomous decisions that affect physical-world logistics operations. Compromise or manipulation could cause cargo misrouting, financial loss, or safety incidents.

## Ownership

### Services & Systems
- Autonomous dispatch agent (driver-load matching with real-time optimization)
- Route optimization engine (multi-constraint solver with ML-driven predictions)
- Demand forecasting service (capacity planning, surge prediction)
- Warehouse automation agents (pick/pack optimization, inventory management)
- ML platform (model registry, training pipelines, feature store, experiment tracking)
- Agent orchestration framework (agent lifecycle, decision logging, rollback)
- Model serving infrastructure (real-time inference, batch prediction)

### Key Repositories
- `agentic-dispatch`
- `route-optimizer`
- `demand-forecasting`
- `warehouse-agents`
- `ml-platform`
- `agent-framework`

## Data Classification

| Data Type | Classification | Notes |
|-----------|---------------|-------|
| Training data | **Confidential** | May contain PII, shipment patterns, pricing |
| Model weights | **Restricted** | Core IP, competitive advantage |
| Agent decision logs | **Confidential** | Audit trail for autonomous decisions |
| Feature store data | **Confidential** | Derived from customer shipment data |
| Experiment metadata | **Internal** | Hyperparameters, architecture choices |

## Unique Threat Surface

This team has attack surfaces that don't exist for traditional software teams:

- **Prompt injection** — Agentic systems that accept natural language inputs
- **Data poisoning** — Corrupted training data leading to degraded or manipulated models
- **Model extraction** — Adversarial queries to reverse-engineer model behavior
- **Agent manipulation** — Adversarial inputs causing autonomous agents to make harmful decisions (misrouting cargo, incorrect capacity allocation)
- **Adversarial examples** — Crafted inputs that fool route optimization or demand forecasting
- **Supply chain attacks on ML dependencies** — Compromised model libraries or pre-trained weights

## Regulatory Exposure

- **EU AI Act** — High-risk AI system classification (autonomous logistics decisions)
- **Emerging US AI regulations** — Explainability and bias requirements
- **SOC 2** — AI system controls and auditability
- **Customer contractual requirements** — Explainability of agent decisions affecting their shipments

## Key Contacts

| Role | Name | Contact |
|------|------|---------|
| Head of AI/ML | TBD | |
| ML Platform Lead | TBD | |
| AI Safety Lead | TBD | |
| On-Call Rotation | | `#ml-oncall` in Slack |

## What Security Success Means to This Team

- No model compromise or data poisoning incidents
- Agent decisions are auditable end-to-end with complete decision traces
- Adversarial robustness validated through regular red team exercises
- ML pipeline integrity — no unauthorized model deployments
- Compliance with emerging AI regulations without blocking innovation
- Clear separation between model experimentation and production serving
