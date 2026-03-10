---
Last Verified: 2026-03-09
Verified By: Alpha-4 Agent
Status: Active
---

# AI/ML Engineering — Risk Register

<!-- Risks can be closed but never deleted. -->

## RISK-ML-001 — Agentic Systems Vulnerable to Adversarial Input

- **Status**: Active
- **Severity**: Critical
- **Opened**: 2026-02-01
- **Owner**: AI Safety Lead + Security Lead
- **Description**: Autonomous dispatch and routing agents have no prompt injection defense or adversarial input detection. Physical-world consequences: cargo misrouting, incorrect capacity allocation, financial loss. [HYPOTHESIS] Structured input format reduces but does not eliminate risk (confidence: 0.6).
- **Compensating Controls**: Agent decision bounds (hard limits on dispatch distance, load weight), human review of anomalous decisions, rollback capability
- **Mitigation Plan**: Prompt injection defense deployment (Q2 2026), adversarial testing program (Q2 2026)
- **Review Date**: 2026-03-15 (accelerated due to severity)

## RISK-ML-002 — Training Data Poisoning

- **Status**: Active
- **Severity**: High
- **Opened**: 2026-02-15
- **Owner**: ML Platform Lead + Security
- **Description**: No integrity verification chain from data ingestion to model training. Compromised training data could degrade model accuracy or introduce backdoors. Detection would be difficult — model performance degradation could be gradual.
- **Compensating Controls**: Training data checksums at ingestion, model performance monitoring, A/B testing before full production rollout
- **Mitigation Plan**: ML pipeline signing framework (roadmap Q3 2026)
- **Review Date**: 2026-04-15

## RISK-ML-003 — Regulatory Uncertainty (AI Regulations)

- **Status**: Active
- **Severity**: Medium
- **Opened**: 2026-01-10
- **Owner**: Head of AI/ML + Legal
- **Description**: EU AI Act and emerging US regulations may classify autonomous logistics agents as high-risk AI systems. Compliance requirements (explainability, bias testing, human oversight) are not fully established in the platform.
- **Compensating Controls**: Decision audit logging deployed, explainability framework on roadmap
- **Mitigation Plan**: Regulatory assessment initiated (roadmap Q3 2026)
- **Review Date**: 2026-06-01
