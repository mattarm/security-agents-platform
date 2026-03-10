---
Last Verified: 2026-03-09
Verified By: Cyber Defense Team
Status: Active
---

# DevOps/SRE — Engagement

## Cadence

| Meeting | Frequency | Attendees | Purpose |
|---------|-----------|-----------|---------|
| Infrastructure security sync | Weekly (Mon) | SRE Lead + Security engineer | Open findings, posture changes, access reviews |
| Security review | Monthly | Head of Infrastructure + Security lead | Risk posture, infrastructure roadmap alignment |
| Cloud security deep dive | Quarterly | Full SRE team + Security team | Architecture review, threat modeling, red team results |

## Active Initiatives

- **Image signing rollout** — Deploying cosign + Kyverno for container image verification (owner: SRE + Beta-4)
- **Credential rotation automation** — Automating remaining manual rotations (owner: SRE + Security)
- **SOC 2 infrastructure evidence** — Automating evidence collection for infrastructure controls (owner: Sigma + SRE)

## Current Plays Running

- Maturity: Zero-trust networking evaluation (Istio service mesh PoC)
- Remediation: Infrastructure drift reduction (Config Rule violations trending down)

## Next Actions

- [ ] SRE: Complete cosign PoC results by 2026-03-15
- [ ] Security: Deliver credential rotation automation for remaining 4 service accounts by 2026-03-30
- [ ] SRE: Schedule Istio PoC kickoff for Q3 2026
