# Context Layer: Persistent Security Customer Intelligence

## What This Is

The persistent context layer for the cyber defense team's service delivery. Every internal engineering team is a **security customer** with structured, agent-readable context that accumulates over time.

The artifacts here are the durable backbone. MCP services and live telemetry (CrowdStrike, Okta, AWS CloudTrail) provide real-time signals. This repo provides **curated posture narratives, strategic decisions, and institutional knowledge** that agents need to deliver effective service.

## How It Works

Each internal customer gets a directory with standardized artifacts:

| Artifact | Purpose | Update Pattern |
|----------|---------|----------------|
| `profile.md` | Who they are, what they own, what matters | Edit in place |
| `controls.md` | Security controls deployed in their domain | Edit in place |
| `roadmap.md` | Planned security improvements | Edit in place |
| `engagement.md` | Meeting cadence, current initiatives, next actions | Edit in place |
| `outcomes.md` | Delivered security outcomes | Append-only |
| `findings.md` | Security findings and resolution status | Append-only |
| `risk.md` | Active and resolved risk register | Close, never delete |
| `agent.md` | Agent autonomy tiers and boundaries | Edit in place |
| `playbooks.md` | Customer-specific response procedures | Edit in place |
| `links.json` | Machine-readable cross-references to external systems | Edit in place |

## How Security Agents Use This

The Intelligence Fusion Engine routes signals to agents, and agents read/write against these artifacts:

- **Alpha-4 (Threat Intel)** reads `profile.md` for threat surface relevance, writes to `findings.md` and `risk.md`
- **Beta-4 (DevSecOps)** reads `controls.md` + `roadmap.md`, writes to `outcomes.md` and `findings.md`
- **Gamma (SOC)** reads `agent.md` for containment autonomy, `playbooks.md` for procedures, writes to `findings.md`
- **Delta (Red Team)** reads `profile.md` + `controls.md` to scope engagements, writes to `findings.md` and `risk.md`
- **Sigma (Metrics)** reads everything to compute posture scores, flags staleness as risk

## External Customers

Tiered model — see `external-customers/README.md`:
- **Flagship**: Dedicated context directories
- **Category templates**: Standard service commitments by customer type

## Adding a New Internal Customer

1. Copy `templates/_*.md` and `templates/_links.json` into a new directory under `internal-customers/`
2. Remove the `_` prefix from all files
3. Fill in `profile.md` first — it drives everything else
4. Configure `agent.md` with autonomy tiers
5. Set up `links.json` with system cross-references
6. Set initial "Last Verified" dates

See `CONVENTIONS.md` for schema rules and staleness policies.
