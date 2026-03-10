# Context Layer Conventions

## Artifact Schema

Every artifact must begin with a YAML-style frontmatter block:

```
---
Last Verified: 2026-03-09
Verified By: [human name or agent ID]
Status: Active | Draft | Stale
---
```

## Staleness Policy

- Each artifact carries a "Last Verified" date
- Artifacts not verified within **90 days** are marked `Stale` and flagged as risk signals by Sigma
- Staleness triggers: Sigma generates a finding in `findings.md` and an entry in `risk.md`
- Refresh triggers: QBR, compliance audit, incident, champion/contact change, architecture change

## Update Patterns

| Artifact | Pattern | Rule |
|----------|---------|------|
| `profile.md` | **Edit in place** | Curated profile; overwrite with current state |
| `controls.md` | **Edit in place** | Reflects current deployed controls |
| `roadmap.md` | **Edit in place** | Living document, updated quarterly minimum |
| `engagement.md` | **Edit in place** | Current cadence and active initiatives |
| `outcomes.md` | **Append-only** | New entries prepended with date; never delete history |
| `findings.md` | **Append-only** | Findings can be marked Resolved but never removed |
| `risk.md` | **Close, never delete** | Risks get status changes (Active → Mitigated → Accepted → Closed) |
| `agent.md` | **Edit in place** | Reflects current autonomy configuration |
| `playbooks.md` | **Edit in place** | Updated as procedures change |
| `links.json` | **Edit in place** | Updated when system IDs change |

## Facts vs. Hypotheses

Agents must distinguish sourced facts from inferences:

- **Fact**: `[FACT] CrowdStrike detected Cobalt Strike beacon on host PROD-WEB-04 (detection ID: ldt:abc123)`
- **Hypothesis**: `[HYPOTHESIS] Lateral movement likely attempted based on beacon configuration (confidence: 0.7)`
- **Decision**: `[DECISION] Approved by @jane.doe: Accept risk of delayed patching for EKS nodes until Q3 migration`

All entries must include provenance: who/what produced them, when, and from what source.

## Source-of-Truth Hierarchy

Agents must know which system is authoritative for which data:

| Data Category | Authoritative Source | Context Layer Role |
|---------------|---------------------|-------------------|
| Endpoint telemetry | CrowdStrike Falcon | Reference, not duplicate |
| Identity events | Okta System Log | Reference, not duplicate |
| Vulnerability scan results | GHAS / scanner tooling | Summarize findings |
| Remediation tracking | Jira | Reference ticket IDs |
| Cloud posture | AWS Security Hub / Config | Summarize posture |
| Curated posture narrative | **This repo** | Source of truth |
| Strategic security decisions | **This repo** | Source of truth |
| Autonomy and governance | **This repo** (`agent.md`) | Source of truth |

## Naming Conventions

- Internal customer directories: lowercase, hyphenated (e.g., `platform-engineering`)
- Artifact filenames: exactly as specified in the schema (e.g., `profile.md`, not `team-profile.md`)
- Flagship customer directories: `company-name` in lowercase-hyphenated form
- No spaces in any path component

## Adding a New Internal Customer

1. Create directory: `internal-customers/<team-name>/`
2. Copy all files from `templates/`, removing the `_` prefix
3. Fill in `profile.md` as the first artifact (other artifacts reference it)
4. Set `Last Verified` to current date on `profile.md`, `Not yet verified` on others
5. Review `agent.md` defaults and adjust autonomy tiers
6. Populate `links.json` with actual system identifiers
7. Register in Intelligence Fusion Engine routing config
