# Agentic Security Delivery: A Context-Driven Operating Model for Cyber Defense

**Extending the Agentic Coding Paradigm to Security Service Delivery**

**Audience**: Security leadership, engineering leadership, and executive team — with sufficient technical specificity for the cyber defense, platform, and AI/ML teams to evaluate and build against.

---

## 1) The Problem We're Solving

Cyber defense teams face a structural scaling problem. As the organization grows — more engineers, more services, more customers, more agentic AI capabilities — the security team's ability to maintain per-team context degrades. The result is predictable:

- **Context fragmentation**: What we know about each team's security posture lives in Slack threads, stale wiki pages, and individual people's heads. When someone leaves or rotates, context is lost.
- **Generic security delivery**: Without team-specific context, we deliver the same alerts, the same severity scores, and the same response playbooks regardless of whether the finding is on a payment processing service (PCI scope) or a developer sandbox.
- **Reactive posture**: We respond to alerts. We don't proactively identify that the AI/ML team's rapid deployment of agentic systems has created a new threat surface that our current controls don't cover.
- **Manual coordination overhead**: Every security interaction requires a human to recall context — which team owns this service? What's their on-call? What containment actions are acceptable in their production? What compliance requirements apply?

This doesn't get better with more headcount. It gets better with a **persistent context layer** that accumulates institutional knowledge and enables agents — both human and AI — to deliver security that's specific to each team's environment, risk profile, and needs.

---

## 2) The Core Idea: Internal Teams as Security Customers

The agentic coding community has converged on a pattern that works: **multiple agents collaborating over the lifecycle of a project using shared, lightweight, human-readable artifacts stored alongside the work**. Files like `agent.md`, `skills.md`, and other markdown artifacts create durable context that survives handoffs, enables multi-agent interoperability, and remains auditable through version control.

We apply the same paradigm to security service delivery. Instead of the project being "the product," **the project is "the internal team."** Instead of agents collaborating to ship code, agents collaborate to **assess, protect, detect, respond, and improve** — with the same benefits:

- **Continuity**: Context persists from one quarter to the next, from one analyst to the next.
- **Interoperability**: Multiple security agents (threat intel, SOC, DevSecOps, red team, metrics) collaborate against the same context backbone.
- **Composable specialization**: A thorough threat assessment (expensive, strategic) produces durable artifacts that operational agents (fast, cheap) execute against daily.
- **Human + agent coordination**: Analysts curate the context; agents operate against it. Both share the same source of truth.
- **Auditability**: Every change is tracked in version control. We can see how our understanding of a team's security posture evolved over time.

---

## 3) The Architecture: Persistent Context + Live Telemetry

### Two Layers

| Layer | What It Is | Examples |
|-------|-----------|---------|
| **Durable context** (this repo) | Curated knowledge about each team — who they are, what they own, what controls are deployed, what risks are accepted, how our agents should operate | profile.md, controls.yaml, risk.md, agent.yaml |
| **Live telemetry** (MCP services) | Real-time signals from security tooling — alerts, detections, vulnerabilities, posture scores | CrowdStrike Falcon, Okta, AWS Security Hub, GHAS, Jira |

The durable context layer answers: **"What do we know about this team?"**
The live telemetry layer answers: **"What is happening to this team right now?"**

Neither is sufficient alone. An alert without context is just noise. Context without telemetry is a stale document. Combined, they enable **environment-aware security decisions** — the same critical vulnerability gets treated differently when it's on a PCI-scoped payment service versus a development sandbox.

### The Agent Ecosystem

Five specialized security agents operate against both layers:

| Agent | Role | How It Uses Context |
|-------|------|-------------------|
| **Alpha-4** (Threat Intel) | Threat landscape monitoring, IOC analysis, campaign attribution | Reads team profiles to determine threat surface relevance. A supply chain attack advisory is routed to teams with affected dependencies, not broadcast to everyone. |
| **Beta-4** (DevSecOps) | CI/CD security, vulnerability management, container/IaC scanning | Reads controls.yaml to know what's deployed. Reads roadmap.md to prioritize what to build next. Doesn't duplicate what's already in place. |
| **Gamma** (SOC) | Alert triage, incident response, containment | Reads agent.yaml before acting — knows that host isolation in Platform Engineering production requires human approval, but in staging it's pre-approved. |
| **Delta** (Red Team) | Penetration testing, adversarial simulation, control validation | Reads controls.yaml + risk.md to scope engagements. Tests the gaps, not what's already validated. |
| **Sigma** (Metrics) | Security posture tracking, SLA compliance, executive reporting | Reads everything. Computes posture scores per team. Flags stale artifacts as risk signals. Produces the numbers for QBRs. |

The **Intelligence Fusion Engine** routes signals between layers — when a CrowdStrike detection fires on a host, the engine identifies which team owns that service (via links.json), loads their context, and routes to the appropriate agent with full team-specific context attached.

---

## 4) What This Looks Like in Practice

### Scenario 1: Critical CVE Disclosure

**Without context layer**: Alert goes to SOC. Analyst spends 20 minutes figuring out who owns the affected service, whether it's in production, whether it's in PCI scope. Sends a generic Slack message. Maybe creates a Jira ticket. Follows up manually.

**With context layer**: Alpha-4 maps CVE to affected dependencies. Cross-references controls.yaml for each team to determine who's exposed. Checks agent.yaml to determine action autonomy. For Platform Engineering (PCI scope, internet-facing): auto-creates P1 Jira ticket with SLA = 15 days (half of standard 30-day High SLA due to PCI multiplier), alerts `#platform-oncall`. For DevOps/SRE (staging only): creates P2 ticket with standard SLA. All of this happens in minutes, not hours, with correct prioritization.

### Scenario 2: New Team Onboarding

**Without context layer**: Security team meets the team once, takes notes somewhere, configures some alerts, and gradually loses context as people rotate.

**With context layer**: Security team conducts intake interview. Populates profile.md, controls.yaml, agent.yaml, links.json. Context is now persistent — any analyst, any agent, any time can load this team's full security picture. As findings accumulate in findings.md and outcomes build in outcomes.md, the context gets richer over time, not thinner.

### Scenario 3: Agentic AI Risk Management

**Without context layer**: Security team knows "the AI team is building some agents" but has no structured understanding of which agents are deployed, what data they access, what decisions they make autonomously, or what adversarial testing has been done.

**With context layer**: AI/ML Engineering's profile.md documents every agentic system and its threat surface. Controls.yaml shows prompt injection defense is a critical gap. Risk.md tracks the accepted risk with compensating controls and mitigation timeline. Agent.yaml specifies that Delta can run adversarial tests against staging but never production. When a new AI regulation passes, Sigma can immediately assess compliance readiness by reading the team's context.

---

## 5) Progressive Autonomy: Building Trust Incrementally

We do not propose full automation on day one. The agent operating model follows a maturity curve:

| Phase | Timeline | What Agents Do | What Humans Do |
|-------|----------|---------------|---------------|
| **Observe** | Months 1-3 | Enrich alerts, triage, score severity, draft Jira tickets, draft Slack messages | Review every recommendation. Approve or correct. Calibration data accumulates. |
| **Advise** | Months 3-6 | Propose containment actions via Slack (Approve/Deny buttons). Track approval rates and accuracy. | Approve or deny proposed actions. Accuracy data drives confidence thresholds. |
| **Assist** | Months 6-12 | High-confidence (>95%) actions execute automatically for well-understood patterns. Low-confidence routes to humans. | Handle exceptions and novel scenarios. Review agent decisions periodically. |
| **Automate** | 12+ months | Autonomous for validated patterns. Proactive threat hunting. Continuous posture optimization. | Strategic oversight. Exception handling. Agent evaluation and governance. |

The `agent.yaml` files encode exactly where each team is on this curve. This is not uniform — some teams may be at "Assist" while others are still at "Observe." The context layer tracks this per-team, per-action-type.

---

## 6) Governance: What Makes This Work in Reality

### Source-of-Truth Hierarchy

Every datum has one authoritative source. Agents know which system to trust:

- **CrowdStrike**: Endpoint telemetry, detections, host inventory
- **Okta**: Identity events, access logs, group membership
- **Jira**: Remediation status, SLA tracking
- **GHAS**: Code vulnerabilities, secret scanning, dependency alerts
- **AWS Security Hub**: Cloud posture, compliance findings
- **Context layer (this repo)**: Curated posture narrative, strategic decisions, autonomy configuration, risk acceptance

### Schema and Conventions

Artifacts follow documented schemas (CONVENTIONS.md). This ensures:
- Agents can parse artifacts reliably
- New team members can read any team's context without training
- Changes are reviewable in pull requests
- Staleness is detectable (every artifact carries a "Last Verified" date)

### Security and Access Control

The context layer contains sensitive information (system identifiers, security gaps, risk decisions). Access controls:
- Repository access restricted to Cyber Defense team + team leads (read access to their own team's context)
- No secrets stored in artifacts — links.json contains identifiers, not credentials
- Sensitive findings reference Jira tickets by ID, not detailed vulnerability descriptions
- All changes tracked in git history for audit compliance

---

## 7) Measurable Outcomes

We deliberately avoid inflated ROI projections. Instead, we define **leading indicators** that can be measured within the first quarter and **lagging indicators** that demonstrate sustained impact.

### Leading Indicators (Measurable in Q1)

- **Time to context**: How long does it take a new analyst (or agent) to understand a team's security posture? Baseline today → measure with context layer.
- **Alert enrichment accuracy**: Do agents route findings to the correct team with correct severity? Measure approval/correction rate.
- **Triage time reduction**: Time from alert → classified + assigned. Measurable immediately.
- **Coverage completeness**: What percentage of internal teams have populated context profiles?

### Lagging Indicators (Q2-Q4)

- **Mean time to detect (MTTD)**: Context-aware triage should reduce time wasted on false positives and misrouted alerts.
- **Mean time to respond (MTTR)**: Agents with pre-approved containment actions (per agent.yaml) respond faster than manual approval workflows.
- **Vulnerability SLA compliance**: Automated SLA tracking and escalation (sla.yaml) should improve on-time remediation rates.
- **Security posture scores**: Per-team posture scores (computed by Sigma from context artifacts) should trend upward.
- **Agent autonomy graduation**: Teams moving from "Observe" to "Advise" to "Assist" demonstrates trust building.

### What We Explicitly Don't Claim

- We don't claim a specific dollar value for security automation. The value is in **scaling the security team's effectiveness** without proportional headcount growth — the specific dollar figure depends on incident frequency, severity distribution, and analyst costs that vary.
- We don't claim this replaces security analysts. It makes them more effective by eliminating context-gathering overhead and automating well-understood patterns.
- We don't claim immediate full autonomy. The progressive model builds trust through demonstrated accuracy over months.

---

## 8) Implementation Plan

### Pilot (Weeks 1-4)

- Onboard 3 internal teams through intake questionnaire
- Populate context artifacts (profile.md, controls.yaml, agent.yaml, links.json)
- Configure Intelligence Fusion Engine routing for pilot teams
- Agents operate in **Observe** mode only — enrich, triage, draft, but don't act

### Foundation (Weeks 4-8)

- Measure leading indicators: triage time, routing accuracy, context completeness
- Refine artifact schemas based on what agents actually need
- Onboard remaining internal teams
- Begin weekly security syncs with pilot teams using context artifacts as agenda backbone

### Advise (Weeks 8-16)

- Agents begin proposing actions (Slack Approve/Deny workflow)
- Track approval rates per agent, per action type, per team
- Teams adjust agent.yaml autonomy tiers based on comfort and accuracy
- Sigma begins producing per-team posture scores from context artifacts

### Assist (Weeks 16-24)

- High-confidence actions graduate to autonomous for teams with strong track records
- Implement confidence threshold tuning (per agent.yaml)
- Establish quarterly posture reviews using context artifacts + Sigma metrics
- Begin adversarial testing program (Delta agent scoped by team context)

### Non-Goals

- This is not a replacement for CrowdStrike, Okta, Jira, or any existing security tooling.
- This is not a documentation project — the artifacts exist for agents to execute against, not for humans to read and file away.
- This is not "one mega-agent for everything" — specialized agents read only the artifacts relevant to their task.

---

## 9) Summary for Leadership

The cyber defense team faces a scaling challenge: more engineering teams, more services, more agentic AI capabilities, and the same number of security analysts. The commercial security platforms (CrowdStrike Charlotte AI, Microsoft Security Copilot, Palo Alto Cortex) don't solve this because they lack **our organizational context** — they don't know which team owns which service, what compliance frameworks apply, what containment actions are acceptable, or what risks have been deliberately accepted.

We solve this by creating a **persistent context layer** — structured, version-controlled, agent-readable artifacts for each internal engineering team — that our security agents read and write against. The same pattern that the agentic coding community uses for multi-agent collaboration on software projects, applied to multi-agent collaboration on security service delivery.

The investment is moderate: a structured onboarding process for internal teams, a defined artifact schema, and routing configuration for the agents we've already built. The return is **compounding context** — every finding, every risk decision, every posture improvement accumulates in the context layer, making every future security interaction faster and more accurate.

The ask: approve the pilot with three internal teams (Platform Engineering, AI/ML Engineering, DevOps/SRE), measure the leading indicators over one quarter, and use the results to decide on broader rollout.
