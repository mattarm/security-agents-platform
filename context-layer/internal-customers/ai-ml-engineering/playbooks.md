---
Last Verified: Not yet verified
Verified By: —
Status: Draft
---

# AI/ML Engineering — Security Playbooks

## PB-ML-001: Suspected Data Poisoning

**Trigger**: Statistical drift detected in training data, anomalous model behavior, or integrity check failure
**Lead Agent**: Alpha-4 (Threat Intel) + Gamma (SOC)
**Autonomy**: Human-approved — ML team must validate before any remediation

1. Halt affected training pipeline (requires ML Platform Lead approval)
2. Identify scope: which datasets, which models, which time window
3. Compare data checksums against known-good baselines
4. Assess downstream impact: which production models trained on affected data
5. Coordinate with ML team for model validation and potential rollback
6. Preserve evidence for investigation
7. If confirmed: retrain affected models from verified clean data
8. Update risk.md and findings.md with full timeline

## PB-ML-002: Anomalous Agent Decision Pattern

**Trigger**: Agent decision monitoring detects pattern outside normal bounds
**Lead Agent**: Gamma (SOC)
**Autonomy**: Alert only — do NOT auto-remediate. ML team investigates.

1. Alert `#ml-oncall` and `#security-incidents`
2. Capture decision logs for anomalous period
3. Assess physical-world impact (were shipments affected?)
4. ML team determines: adversarial input, model drift, or legitimate edge case
5. If adversarial: escalate to full incident response
6. If model drift: ML team handles model remediation
7. Document in findings.md regardless of root cause

## PB-ML-003: Model Supply Chain Compromise

**Trigger**: Compromised ML library, pre-trained weights, or model dependency
**Lead Agent**: Beta-4 (DevSecOps)
**Autonomy**: Autonomous for detection and alerting; Human-approved for pipeline halt

1. Identify affected dependency and versions in use
2. Assess if compromised version is in production serving path
3. Halt deployments from affected pipeline (requires ML Platform Lead approval)
4. Scan deployed models for indicators of compromise
5. Coordinate rollback to known-good model version if needed
6. Update dependencies and verify integrity
