---
Last Verified: 2026-03-01
Verified By: Cyber Defense Team
Status: Active
---

# AI/ML Engineering — Security Roadmap

## Current Maturity Assessment

- **Model Security**: Moderate (access control, encryption, decision logging)
- **Agentic AI Safety**: Early (basic guardrails — no prompt injection defense, no adversarial testing cadence)
- **Data Protection**: Moderate (access control strong, PII scanning gaps in historical data)
- **Pipeline Integrity**: Early (checksums exist, no end-to-end signing)
- **Regulatory Readiness**: Early (decision logging exists, explainability framework not started)

## Q2 2026

- [ ] Deploy prompt injection detection and filtering for agentic systems
- [ ] First adversarial red team exercise (Delta agent) against staging agentic systems
- [ ] Complete retroactive PII scan of historical training datasets
- [ ] Establish AI security incident response playbook
- [ ] Define adversarial robustness benchmarks for dispatch and routing agents

## Q3 2026

- [ ] Implement ML pipeline signing (training data → model → deployment integrity chain)
- [ ] Deploy anomaly detection on agent decision patterns (detect manipulation)
- [ ] Establish quarterly adversarial testing cadence with Delta agent
- [ ] Begin EU AI Act compliance assessment for high-risk classification
- [ ] Implement model access logging and query rate limiting (anti-extraction)

## Q4 2026

- [ ] Explainability framework for customer-facing agent decisions
- [ ] Automated AI compliance evidence collection
- [ ] Adversarial robustness CI/CD gate (models must pass adversarial tests before deployment)
- [ ] Data poisoning detection in training pipeline (statistical drift monitoring)
