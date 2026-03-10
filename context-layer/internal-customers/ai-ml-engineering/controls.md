---
Last Verified: 2026-02-15
Verified By: Cyber Defense Team
Status: Active
---

# AI/ML Engineering — Security Controls

## Model & Pipeline Security

| Control | Status | Tool | Notes |
|---------|--------|------|-------|
| Model registry access control | Deployed | MLflow + IAM | Role-based access to model versions |
| Training pipeline integrity | Partial | Custom checksums | Training data hashed at ingestion — gap: no end-to-end pipeline signing |
| Model serving authentication | Deployed | mTLS + IAM | Service-to-service auth for inference endpoints |
| Experiment isolation | Deployed | Separate EKS namespace | Dev experiments isolated from production serving |

## Agentic AI Security

| Control | Status | Tool | Notes |
|---------|--------|------|-------|
| Agent decision logging | Deployed | Custom audit framework | All autonomous decisions logged with full context |
| Input validation | Partial | Custom validators | Basic input sanitization — gap: no adversarial input detection |
| Output guardrails | Partial | Rule-based constraints | Hard limits on dispatch distances, load weights — gap: no ML-based anomaly detection on outputs |
| Prompt injection defense | Not deployed | | **Critical gap** — agentic systems accept structured inputs |
| Agent rollback capability | Deployed | Blue-green model serving | Can revert to previous model version within minutes |

## Data Protection

| Control | Status | Notes |
|---------|--------|-------|
| Training data access control | Deployed | IAM + S3 bucket policies |
| Model weights encryption | Deployed | KMS encryption at rest |
| Feature store access logging | Deployed | CloudTrail + custom audit |
| PII in training data | Partial | PII detection in ingestion pipeline — gap: historical datasets not fully scanned |

## Infrastructure Security

| Control | Status | Notes |
|---------|--------|-------|
| GPU instance monitoring | Deployed | CrowdStrike + custom metrics (cryptomining detection) |
| Notebook server hardening | Partial | Network isolation deployed — gap: no mandatory image scanning for custom notebook images |
| Container security | Deployed | Same controls as platform (Falcon Container, ECR scanning) |

## Gaps and Planned Improvements

- **Prompt injection defense**: Critical gap for agentic systems. Roadmap: input filtering + adversarial detection (Q2 2026)
- **Adversarial robustness testing**: No regular cadence. Roadmap: quarterly red team exercises with Delta agent (Q2 2026)
- **Training pipeline signing**: End-to-end integrity verification. Roadmap: ML supply chain security framework (Q3 2026)
- **PII scanning of historical training data**: Retroactive scan needed. Roadmap: Q2 2026
