---
Last Verified: 2026-03-09
Verified By: Alpha-4 Agent
Status: Active
---

# Platform Engineering — Risk Register

<!-- Risks can be closed but never deleted. -->

## RISK-PE-001 — No Continuous API Security Testing

- **Status**: Active
- **Severity**: High
- **Opened**: 2026-01-15
- **Owner**: Security Lead + Platform Eng Lead
- **Description**: Platform APIs serve 200+ logistics customers. No continuous DAST/fuzzing — only manual quarterly pen tests. API attack surface changes faster than quarterly testing cadence.
- **Compensating Controls**: WAF rules, rate limiting, input validation at application layer
- **Mitigation Plan**: API security tooling evaluation in progress (roadmap Q2 2026)
- **Review Date**: 2026-04-01

## RISK-PE-002 — PCI Scope Expansion Risk

- **Status**: Active
- **Severity**: Medium
- **Opened**: 2026-02-01
- **Owner**: Compliance + Platform Eng VP
- **Description**: New billing features in Q2 may expand PCI scope to additional services. Scope creep increases compliance burden and attack surface.
- **Compensating Controls**: Architecture review gate before billing feature deployment
- **Mitigation Plan**: QSA pre-assessment scheduled for March 2026
- **Review Date**: 2026-03-15

## RISK-PE-003 — No DLP on Outbound API Responses

- **Status**: Accepted
- **Severity**: Medium
- **Opened**: 2026-01-20
- **Owner**: Platform Eng VP
- **Description**: [DECISION] Risk accepted by VP Engineering (2026-01-25): API responses could leak data beyond authorized scope. Accepted because: application-layer access controls are in place, and DLP implementation would add latency to customer-facing APIs.
- **Review Date**: 2026-07-20 (6-month review)
