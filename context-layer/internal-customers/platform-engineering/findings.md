---
Last Verified: 2026-03-09
Verified By: Gamma Agent
Status: Active
---

# Platform Engineering — Security Findings

<!-- Append-only log. Findings can be marked Resolved but never removed. -->

## FIND-PE-2026-012 — SQL Injection in Shipment Search API

- **Date**: 2026-03-03
- **Source**: Beta-4 (GHAS CodeQL scan)
- **Severity**: Critical
- **Status**: Resolved (2026-03-05)
- **Description**: [FACT] Parameterized query not used in shipment search endpoint. CodeQL alert CWE-89.
- **Remediation**: PR #1847 — migrated to parameterized queries. Verified by retest.
- **Jira**: SEC-2026-089

## FIND-PE-2026-011 — Outdated TLS Configuration on Internal API

- **Date**: 2026-02-28
- **Source**: Beta-4 (infrastructure scan)
- **Severity**: Medium
- **Status**: Open
- **Description**: [FACT] Internal service-to-service API endpoint accepting TLS 1.0/1.1 connections. Production only.
- **Remediation**: Pending — requires client library updates in 2 dependent services.
- **Jira**: SEC-2026-085
- **SLA**: Due 2026-06-28 (120 days for Medium)

## FIND-PE-2026-008 — API Authentication Bypass (Pen Test)

- **Date**: 2026-02-01
- **Source**: Delta (external pen test)
- **Severity**: High
- **Status**: Resolved (2026-02-08)
- **Description**: [FACT] Edge case in JWT validation allowed expired tokens with specific claim combinations to pass validation. Found during Q4 2025 external pen test.
- **Remediation**: PR #1792 — JWT validation hardened. Verified by pen test vendor retest.
- **Jira**: SEC-2026-041
