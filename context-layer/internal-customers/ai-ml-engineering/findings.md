---
Last Verified: 2026-03-09
Verified By: Gamma Agent
Status: Active
---

# AI/ML Engineering — Security Findings

<!-- Append-only log. Findings can be marked Resolved but never removed. -->

## FIND-ML-2026-005 — No Prompt Injection Defense on Dispatch Agent

- **Date**: 2026-02-20
- **Source**: Alpha-4 (threat landscape analysis)
- **Severity**: High
- **Status**: Open — Active remediation
- **Description**: [FACT] Dispatch agent accepts structured inputs from multiple sources (API, internal systems). No input sanitization or prompt injection detection deployed. [HYPOTHESIS] Risk is partially mitigated by structured input format (not free-text), but adversarial structured inputs could manipulate dispatch decisions (confidence: 0.6).
- **Remediation**: Prompt injection defense project initiated. Prototype expected 2026-03-30.
- **Jira**: SEC-2026-072
- **SLA**: Due 2026-03-22 (30 days for High) — **At risk of SLA breach**

## FIND-ML-2026-004 — PII Detected in Historical Training Dataset

- **Date**: 2026-02-10
- **Source**: Beta-4 (data scanning)
- **Severity**: Medium
- **Status**: Open
- **Description**: [FACT] PII scanner detected customer email addresses and phone numbers in 3 historical training datasets (pre-2025 ingestion pipeline). ~4,200 records affected.
- **Remediation**: PII remediation plan in progress. Requires retraining affected models after data scrubbing.
- **Jira**: SEC-2026-068
- **SLA**: Due 2026-06-10 (120 days for Medium)

## FIND-ML-2026-002 — Overly Broad Model Registry Access

- **Date**: 2026-01-10
- **Source**: Sigma (access review)
- **Severity**: Medium
- **Status**: Resolved (2026-02-15)
- **Description**: [FACT] All ML engineers had write access to production model registry. No role separation between experiment and production deployment.
- **Remediation**: RBAC implemented. See outcomes.md entry 2026-02-15.
- **Jira**: SEC-2026-038
