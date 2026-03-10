# Security Customer Intake Questionnaire

**Purpose**: This questionnaire is used by the Cyber Defense team when onboarding a new internal team as a security customer. The answers populate their context layer artifacts (profile.md, controls.yaml, agent.yaml, etc.).

**How to use**: Schedule a 60-minute session with the team lead and a senior engineer. Walk through these sections conversationally — don't just send the form. The goal is to understand how they work and what they need from security, not to audit them.

---

## 1. Team Identity & Mission

- What is your team's name and how do you refer to yourselves?
- In one sentence, what does your team build and operate?
- How many engineers are on the team?
- Who is the team lead? Who should we contact for security matters?
- What is your on-call rotation and where does it live? (PagerDuty, Opsgenie, Slack channel?)

## 2. What You Own

### Services & Systems

- List every service your team owns and operates in production.
- For each: Is it customer-facing, internal-facing, or both?
- Which services handle the most sensitive data?
- What databases and data stores do you own?
- What message queues, event streams, or async processing do you own?

### Repositories

- What GitHub repositories does your team own?
- Are there shared repositories where you contribute but don't own?

### Infrastructure

- What AWS accounts do your services run in?
- What compute platform? (EKS, ECS, EC2, Lambda, etc.)
- Do you manage your own infrastructure, or does DevOps/SRE manage it for you?

## 3. Data Classification

For each major data type your team handles:

| Data Type | Description | Who can access it? | Where is it stored? |
|-----------|-------------|-------------------|-------------------|
| | | | |

Specific questions:
- Does your team handle customer PII (names, emails, addresses, phone numbers)?
- Does your team handle financial data (payment info, invoicing, pricing)?
- Does your team handle authentication credentials or tokens?
- Does your team handle proprietary data (algorithms, models, trade secrets)?
- Is any of your data subject to data residency requirements (must stay in a specific region)?

## 4. Regulatory & Compliance Exposure

- Which compliance frameworks apply to your services? (SOC 2, PCI-DSS, GDPR, HIPAA, etc.)
- Are any of your services in PCI scope (touch cardholder data)?
- Do you handle EU customer data (GDPR)?
- Are there industry-specific regulations that affect you? (e.g., AI regulations, transportation/logistics regulations)
- Do customers contractually require specific security controls from you?

## 5. Current Security Controls

For each category, tell us what's in place today:

### Code & Build
- Do you have SAST (static analysis) in your CI/CD pipeline? What tool?
- Do you have dependency/SCA scanning? What tool?
- Do you have secret scanning / push protection?
- Do you have container image scanning?
- What does your deployment pipeline look like? (GitOps, manual deploy, etc.)

### Runtime & Monitoring
- Is CrowdStrike Falcon deployed on your hosts/containers?
- Do you have application-level security monitoring? (WAF, RASP, custom detection)
- How do you detect anomalies in your service? (metrics, logs, alerts)

### Data Protection
- Is data encrypted at rest? How? (KMS, application-level, etc.)
- Is data encrypted in transit? What TLS version?
- Do you have database access logging / audit trails?

### Access Control
- How do your engineers access production? (SSO, JIT access, standing access?)
- How do your services authenticate to each other?
- How are secrets managed? (Vault, AWS Secrets Manager, environment variables?)

### What's Missing?
- What security controls do you know you need but don't have yet?
- What keeps you up at night from a security perspective?

## 6. How You Work

- What is your deployment cadence? (Daily, weekly, continuous?)
- What is your incident response process? (Who gets paged, how do you communicate?)
- Do you have a dedicated security champion on the team?
- How do you currently handle security findings / vulnerability remediation?
- What is your appetite for security tooling in CI/CD? (Block the build? Advisory only?)

## 7. What You Need From Us

- What would make security a **force multiplier** for your team rather than a blocker?
- What security tasks do you currently do manually that you'd want automated?
- How should we communicate findings to you? (Jira tickets, Slack, email, weekly meeting?)
- What meeting cadence makes sense? (Weekly sync, biweekly, monthly?)
- Are there upcoming launches, migrations, or architecture changes we should know about?
- What is your biggest security concern right now?

## 8. Agent Autonomy Preferences

We use AI-powered security agents that can take automated actions in your environment. We need to understand your comfort level.

**For your production environment, which actions should our agents be able to take without asking first?**

| Action | Autonomous OK? | Need Approval? | Never? |
|--------|---------------|----------------|--------|
| Alert triage and enrichment | | | |
| Create Jira tickets for findings | | | |
| Block a PR for critical vulnerability | | | |
| Isolate a compromised host | | | |
| Terminate a compromised container | | | |
| Modify a security group (block IP) | | | |
| Revoke a compromised credential | | | |
| Halt a CI/CD pipeline | | | |

- If approval is needed, who should approve? (Team lead? On-call? Specific person?)
- What actions should we NEVER automate in your environment?
- Are there times when automation is more acceptable? (Off-hours? During incidents?)

## 9. External System Connections

Help us set up the cross-references we need:

| System | Your Identifier |
|--------|----------------|
| Jira project key | |
| Slack team channel | |
| Slack on-call channel | |
| PagerDuty service ID | |
| AWS account ID(s) | |
| CrowdStrike host group | |
| Okta group ID | |
| Grafana dashboard URL | |

---

## After the Interview

The Cyber Defense team will:

1. Create your context layer directory (`context-layer/internal-customers/<your-team>/`)
2. Populate your `profile.md` from this conversation and send it for your review
3. Configure `agent.yaml` based on your autonomy preferences
4. Map your current controls into `controls.yaml`
5. Set up `links.json` with your system identifiers
6. Schedule your first regular security sync meeting
7. Brief you on how to read your context artifacts and what to expect from our agents

**Your first artifact review is your chance to correct anything we got wrong.** The profile should accurately represent your team — if it doesn't, tell us.
