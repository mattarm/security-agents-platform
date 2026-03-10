---
Last Verified: 2026-03-09
Verified By: Gamma Agent
Status: Active
---

# DevOps/SRE — Security Findings

<!-- Append-only log. Findings can be marked Resolved but never removed. -->

## FIND-SRE-2026-009 — Service Account with Static Credentials

- **Date**: 2026-03-01
- **Source**: Sigma (credential audit)
- **Severity**: High
- **Status**: Open — Active remediation
- **Description**: [FACT] 4 service accounts using static long-lived credentials (>90 days old). Services: monitoring-exporter, log-forwarder, backup-agent, legacy-webhook.
- **Remediation**: Automation in progress. 2 of 4 migrated to OIDC. Remaining 2 require vendor coordination.
- **Jira**: SEC-2026-082
- **SLA**: Due 2026-03-31 (30 days for High)

## FIND-SRE-2026-007 — No Container Image Signing

- **Date**: 2026-02-15
- **Source**: Beta-4 (supply chain assessment)
- **Severity**: Medium
- **Status**: Open — PoC in progress
- **Description**: [FACT] Container images deployed to EKS are not signed. No admission controller verifies image provenance. [HYPOTHESIS] Supply chain attack could deploy malicious images (confidence: 0.4 — mitigated by ECR-only pull policy).
- **Remediation**: Cosign + Kyverno PoC in progress. Results expected 2026-03-15.
- **Jira**: SEC-2026-075

## FIND-SRE-2026-003 — AWS Config Rule Violations (Infrastructure Drift)

- **Date**: 2026-01-15
- **Source**: Gamma (Security Hub aggregation)
- **Severity**: Medium
- **Status**: Partially Resolved
- **Description**: [FACT] 12 AWS Config Rule violations detected across staging accounts. 8 resolved (security group drift, S3 public access). 4 remaining (EBS encryption defaults in legacy accounts).
- **Remediation**: Legacy account remediation scheduled for Q2 2026 account migration.
- **Jira**: SEC-2026-048
