# SecurityAgents Platform — Implementation Roadmap

**Last Updated**: 2026-03-09
**Status**: Active
**Audience**: Fresh AI sessions continuing this work; human stakeholders for planning

---

## 1. Current State

### What Exists and Works

The SecurityAgents Platform has five implemented agents coordinated through an Intelligence Fusion Engine:

| Agent | File | Status |
|-------|------|--------|
| Alpha-4 (Threat Intel) | `enhanced-analysis/tiger_team_alpha_4.py` (~23k lines) | Implemented |
| Beta-4 (DevSecOps) | `enhanced-analysis/tiger_team_beta_4.py` (~58k lines) | Implemented |
| Gamma (SOC) | `agents/gamma_blue_team_agent.py` | Implemented |
| Delta (Red Team) | `agents/delta_red_team_agent.py` | Implemented |
| Sigma (Metrics) | `agents/sigma_metrics_agent.py` | Implemented |

**Core infrastructure implemented:**
- Intelligence Fusion Engine (`enhanced-analysis/intelligence_fusion_engine.py`) — cross-domain threat correlation
- Agent Orchestrator (`enhanced-analysis/agent_orchestration_system.py`) — multi-agent task execution
- Production API Server (`enhanced-analysis/production_api_server.py`) — FastAPI with JWT/OAuth 2.0
- CrowdStrike MCP Integration (`crowdstrike-mcp-integration/`) — per-agent skill modules for Alpha-4, Beta-4, Gamma, Delta
- IAM Security (`iam-security/`) — Okta integration, behavioral analytics (Isolation Forest ML), dual SIEM forwarding
- SecOps AI Orchestration (`secops-ai-orchestration/`) — confidence engine, autonomy tiers 0-3, governance controls
- Enterprise Topology (`enterprise-topology/`) — Neo4j graph database with `enterprise_graph.py`, GitHub Enterprise integration
- Slack War Rooms (`slack-war-rooms/`) — SOC collaboration bot
- Infrastructure as Code (`security-agents-infrastructure/`) — Terraform modules for AWS
- Docker Compose stacks for local dev and production deployment

**Context layer established:**
- 3 internal customer directories populated (`context-layer/internal-customers/`): Platform Engineering, AI/ML Engineering, DevOps/SRE
- Each directory contains: `profile.md`, `agent.yaml`, `controls.yaml`, `engagement.md`, `findings.md`, `outcomes.md`, `playbooks.md`, `risk.md`, `roadmap.md`, `links.json`
- Templates directory with prefixed starter files for new customers
- `CONVENTIONS.md` defining artifact schemas, staleness policy, update patterns, fact/hypothesis/decision tagging
- `sla.yaml` with vulnerability SLA baselines, environment multipliers, compliance multipliers
- `INTAKE-QUESTIONNAIRE.md` for onboarding conversations
- `VISION-Agentic-Security-Delivery.md` leadership vision document

### What Does Not Work / Critical Gaps

**Test coverage: effectively zero.** See `docs/TEST-COVERAGE-REQUIREMENTS.md` for the full assessment. No unit tests, no integration tests, no performance tests, no security tests, no end-to-end tests across the core platform. The `secops-ai-orchestration/` subsystem has a pytest.ini and test directory but the rest of the codebase has no test infrastructure. The 80% coverage target in pytest.ini is aspirational, not enforced.

**No unified dependency management.** Each subsystem has its own `requirements.txt`. There is no monorepo tooling, no shared virtual environment, no lockfiles.

**No CI/CD pipeline.** Tests are not gated on PRs. No automated quality checks run on commit.

**.gitignore is minimal** (only `temp-repos/`). Risk of accidentally committing secrets or large files.

**Agents have not been tested against live context layer artifacts.** The context layer exists, the agents exist, but the wiring between them — agents reading `agent.yaml` at decision time, the Fusion Engine enriching packets with team context — is designed but not implemented.

**PagerDuty integration: zero implementation.** This is the highest-value unwired API for incident response workflows.

**TheHive integration: write-only.** Gamma can create cases but cannot query case history or templates.

**Knowledge graph integration with agents: not built.** The `enterprise-topology/src/core/graph/enterprise_graph.py` exists with Neo4j infrastructure, but it is not connected to the Intelligence Fusion Engine or individual agents.

---

## 2. Architecture Decisions

These decisions were made through analysis and are the design constraints for all future work. A fresh AI session should treat these as settled unless the human stakeholder explicitly reopens them.

### Decision 1: Internal Teams as Security Customers

Engineering teams (Platform Engineering, AI/ML Engineering, DevOps/SRE) are treated as security service consumers with persistent context artifacts. These are NOT per-tenant external customer profiles. The context layer models internal teams the security organization serves, not the company's external customers.

External customers use a separate tiered model (`context-layer/external-customers/`): flagship customers get dedicated directories; others use category templates.

### Decision 2: Hybrid Artifact Format

Three formats, each chosen for its consumer:

| Format | Files | Why |
|--------|-------|-----|
| Markdown | `profile.md`, `roadmap.md`, `engagement.md`, `outcomes.md`, `findings.md`, `risk.md`, `playbooks.md` | Human-authored narrative and judgment. Read by humans and reasoning agents. |
| YAML | `agent.yaml`, `controls.yaml`, `sla.yaml` | Agent execution config. Parsed deterministically at decision time. No ambiguity. |
| JSON | `links.json` | Machine-readable system identifiers. API-style lookups. |

Markdown artifacts use YAML frontmatter for metadata. YAML artifacts use comment headers. This split is deliberate — do not consolidate everything into one format.

### Decision 3: Context Layer + Knowledge Graph — Two Complementary Layers

| Layer | Storage | Role |
|-------|---------|------|
| Context layer | Git repo, flat files | Source of truth for curated decisions, posture narratives, autonomy config |
| Knowledge graph | Neo4j, runtime | Derived computation layer for relationship traversal and blast radius analysis |

Critical rules:
- `agent.yaml` is NEVER cached in the graph. It is read directly from the filesystem at decision time. Autonomy decisions must reflect the current file, not a stale graph copy.
- Live telemetry (CrowdStrike detections, Okta events, AWS CloudTrail) stays in MCP services. The graph holds identifiers and relationships, not raw telemetry data.
- The graph is populated FROM the context layer and external tool APIs. The context layer is upstream; the graph is downstream.

### Decision 4: Progressive Autonomy Model

Four phases per team, encoded per-action in `agent.yaml`:

| Phase | Agent Behavior | Human Role |
|-------|---------------|------------|
| Observe | Enrich, triage, score, draft | Review everything |
| Advise | Propose actions (Slack Approve/Deny) | Approve or deny |
| Assist | High-confidence (>95%) auto-execute | Handle exceptions |
| Automate | Autonomous for validated patterns | Strategic oversight |

Confidence thresholds in `agent.yaml`:
```yaml
confidence_thresholds:
  auto_execute_above: 0.95
  propose_and_wait_above: 0.7
  human_review_below: 0.7
  block_below: 0.3
```

Teams progress independently. Platform Engineering may be at "Assist" for alert triage while AI/ML Engineering is still at "Observe." This is per-team AND per-action-type.

### Decision 5: Crawl / Walk / Run Deployment

Start with 2-3 teams. Learn what works and what breaks. Fix the intake questionnaire based on what agents actually need. Scale gradually. No big-bang deployment to all teams simultaneously.

---

## 3. Phase 1: Foundation (Crawl)

**Goal**: First 2-3 teams onboarded with lean intake, auto-discovery running, core context layer operational, agents reading context at decision time.

**Teams**: Platform Engineering, AI/ML Engineering, DevOps/SRE (directories already created).

### Deliverables

#### 1.1 Revised Intake Questionnaire
The current intake questionnaire (`context-layer/INTAKE-QUESTIONNAIRE.md`) has significant gaps identified by agent analysis. Split into two parts:

**Part A — Human-only questions (~30% of needed data):**
- Team identity, mission, data classification
- Compliance scope decisions (which services are PCI/GDPR)
- Agent autonomy preferences (the Approve/Deny table)
- Service criticality tiers
- Red-flag conditions and containment blackout windows
- Red team engagement scope and approvals
- Service-to-service dependencies (tools can approximate, humans must confirm)

**Part B — Auto-discovered (agent pre-populates before the interview):**
- Repo inventory, languages, branches, CODEOWNERS (GitHub API)
- Host inventory, CrowdStrike coverage, vulnerabilities (CrowdStrike API)
- AWS resources: EC2, S3, RDS, Lambda, IAM, security groups (AWS API)
- Okta user/group membership, MFA status (Okta API)
- Open security tickets, remediation velocity (Jira API)

The interview should present Part B findings for confirmation ("We found these 6 repos — is this complete?"), not ask the team to list everything from memory.

#### 1.2 Wire Agents to Context Layer
Modify these files to make agents context-aware:

- `enhanced-analysis/intelligence_fusion_engine.py` — Add `team_context` parameter to intelligence packet enrichment. When a signal arrives (e.g., CrowdStrike detection), resolve which team owns the affected asset via `links.json`, load their `agent.yaml` and `profile.md`, and attach to the packet.
- `enhanced-analysis/agent_orchestration_system.py` — Pass context directory path to agents during task execution. Agents read `agent.yaml` to determine what actions they can take autonomously.
- Individual agent files — Add context-reading methods. Each agent reads only the artifacts relevant to its function (see `context-layer/README.md` for the mapping).

#### 1.3 Auto-Discovery Scripts
Build scripts that call existing APIs to pre-populate context artifacts:

| Source | Data Populated | Implementation Status |
|--------|---------------|----------------------|
| GitHub Enterprise API | Repos, languages, branches, CODEOWNERS, dependency manifests | `enterprise-topology/src/integrations/github/` exists — wrap for context layer output |
| CrowdStrike API | Host inventory, coverage gaps, vulnerabilities, containers | `crowdstrike-mcp-integration/skills/` exists — wrap for context layer output |
| AWS API | EC2, S3, RDS, Lambda, IAM, security groups | `aws-security/infrastructure_analyzer.py` exists — wrap for context layer output |
| Okta API | Login patterns, MFA status, groups | `iam-security/okta_security/` exists — wrap for context layer output |
| Jira API | Open tickets, remediation velocity | `enterprise-topology/` enterprise integration exists — wrap for context layer output |

These are wrappers around existing implementations, not new integrations.

#### 1.4 Basic Test Infrastructure
Stand up pytest across the core platform. Priority order:
1. Integration tests for agent-to-context-layer reads (does Alpha-4 correctly load and parse `profile.md` and `agent.yaml`?)
2. Unit tests for confidence threshold logic (does `block_below: 0.3` actually block?)
3. Unit tests for SLA calculation with multipliers (does PCI scope + internet-facing = 0.25x SLA?)

#### 1.5 Populate Remaining Artifacts
The 3 customer directories exist but have template-quality content. Conduct actual intake interviews with each team and fill in real data. `links.json` needs actual system identifiers (AWS account IDs, CrowdStrike host group IDs, Jira project keys, Slack channels, PagerDuty service IDs).

### Definition of Done — Phase 1

- [ ] Intake interviews completed for 3 teams with real data in all artifacts
- [ ] At least one agent (Gamma recommended — simplest read path) reads `agent.yaml` before taking a containment action and respects the autonomy tiers
- [ ] Auto-discovery scripts produce draft `controls.yaml` content from GitHub + CrowdStrike + AWS data
- [ ] Fusion Engine attaches team context to intelligence packets for pilot teams
- [ ] pytest runs with >0% coverage on core platform (honest starting point)
- [ ] Agents operating in Observe mode for all 3 teams — enriching and drafting, not acting

---

## 4. Phase 2: Integration (Walk)

**Goal**: Wire up unwired APIs, build PagerDuty integration, begin knowledge graph integration, iterate on intake questionnaire based on Phase 1 learnings.

### Deliverables

#### 2.1 PagerDuty Integration (Highest-Value Gap)
Zero implementation exists today. Build:
- On-call schedule lookup (who is on call for Platform Engineering right now?)
- Escalation policy resolution (for P0, page X; for P1, notify Y)
- MTTR data ingestion (how fast does this team respond to pages?)
- Wire into `links.json` (PagerDuty service ID per team) and Gamma agent (on-call resolution for incident response)

#### 2.2 GitHub GHAS Integration
APIs available, not yet wired:
- Dependabot alerts per repo
- CodeQL scan results
- Secret scanning alerts
- Wire into Beta-4 for vulnerability management and `findings.md` population

#### 2.3 AWS Extended Coverage
APIs available, not yet wired:
- EKS clusters and node groups
- ECS task definitions
- Security Hub findings
- AWS Config compliance rules
- Wire into auto-discovery scripts and `controls.yaml` population

#### 2.4 TheHive Read Integration
Currently write-only. Add:
- Case history queries (what incidents has this team had?)
- Template retrieval (which response templates apply?)
- Wire into Gamma for incident history context

#### 2.5 Okta Bulk Enumeration
Currently event-stream only. Add:
- Bulk user/group/application enumeration
- Admin group identification
- Service account inventory
- Wire into IAM context and `controls.yaml`

#### 2.6 Knowledge Graph — Phases 0-2

**Phase 0 (1 week): Validation**
Manual Cypher queries against existing `enterprise-topology` Neo4j instance. Verify the graph answers questions the Fusion Engine actually needs:
- "What team owns this host?"
- "What services depend on this service?"
- "What is the blast radius of this vulnerability?"
Go/no-go decision based on query results.

**Phase 1 (2-3 weeks): Context Layer Ingestion**
Build `enhanced-analysis/graph/context_ingester.py`:
- Parse `profile.md`, `links.json`, `controls.yaml` from each customer directory
- Create graph nodes: Team, Service, Host, Repository, AWSAccount
- Create graph edges: OWNS, RUNS_ON, STORED_IN, COMPLIANT_WITH
- Scheduled sync (not real-time) — batch update from flat files

**Phase 2 (2-3 weeks): Fusion Engine Integration**
Build `enhanced-analysis/graph/context_provider.py`:
- Fusion Engine queries graph for team resolution when a signal arrives
- Graph provides relationship context (blast radius, dependent services) that flat files cannot efficiently compute
- `agent.yaml` is still read from filesystem, not from graph

New files to create:
```
enhanced-analysis/graph/__init__.py
enhanced-analysis/graph/schema_initializer.py
enhanced-analysis/graph/context_ingester.py
enhanced-analysis/graph/context_provider.py
enhanced-analysis/graph/models.py
```

Files to modify:
```
enhanced-analysis/intelligence_fusion_engine.py  (add graph_context param)
enhanced-analysis/production_api_server.py       (add /graph/ routes)
```

#### 2.7 Revised Intake Questionnaire v2
Based on Phase 1 experience, update `INTAKE-QUESTIONNAIRE.md` to address the gaps identified by agent analysis. Priority gaps to add:

| Agent | Gap | Priority |
|-------|-----|----------|
| All agents | Service-to-service dependencies | Critical |
| Beta-4 | IaC tool, container registry, K8s cluster/namespace mapping | High |
| Gamma | Service criticality tiers, per-action approval chains, containment blackout windows | High |
| Delta | Pre-authorized test environments, exclusion lists, testing windows | High |
| Alpha-4 | Industry classification, third-party vendors, threat history | Medium |
| Sigma | Posture baseline denominator, incident history/MTTR, detection coverage blind spots | Medium |
| IAM/Okta | Admin group IDs, privileged group taxonomy, service accounts, JIT access | Medium |

### Definition of Done — Phase 2

- [ ] PagerDuty integration returns on-call and escalation data for all 3 pilot teams
- [ ] GitHub GHAS alerts flow into Beta-4 and auto-populate `findings.md`
- [ ] Knowledge graph Phase 0 go/no-go decision made with documented rationale
- [ ] If go: graph ingests context layer artifacts and Fusion Engine queries it for team resolution
- [ ] At least one agent has moved from Observe to Advise for at least one team (proposing actions via Slack with Approve/Deny)
- [ ] Intake questionnaire v2 published with auto-discovery pre-population flow documented
- [ ] Test coverage reaches 40% on core platform modules that touch context layer

---

## 5. Phase 3: Scale (Run)

**Goal**: Auto-onboarding pipeline, full graph-agent integration, 9+ teams onboarded, agents operating at Assist level for well-understood patterns.

### Deliverables

#### 3.1 Auto-Onboarding Pipeline
When a new team needs onboarding:
1. Run auto-discovery against their known identifiers (AWS account, GitHub org/team, Okta group)
2. Generate draft artifacts (profile.md, controls.yaml, links.json) from discovered data
3. Present draft to team lead for review and correction
4. Conduct abbreviated intake interview (human-only questions, ~30 minutes instead of 60)
5. Register team in Fusion Engine routing
6. Set all agents to Observe mode for 30 days

#### 3.2 Knowledge Graph — Phases 3-4

**Phase 3 (3-4 weeks): Agent Query Integration**
Build `enhanced-analysis/graph/agent_graph_client.py`:
- Per-agent graph query methods
- Alpha-4: "What teams are affected by this CVE?" (traverse dependency graph)
- Beta-4: "What repos use this vulnerable dependency?" (traverse repo-to-dependency graph)
- Gamma: "What is the blast radius if I isolate this host?" (traverse service dependency graph)
- Delta: "What attack paths exist from this entry point?" (traverse network/service graph)
- Sigma: "What is the coverage score for this team?" (aggregate control nodes)

Modify: `enhanced-analysis/agent_orchestration_system.py` (pass graph client to agents)

**Phase 4 (2-3 weeks): Service Dependency Mapping**
Curated `DEPENDS_ON` relationships in the graph:
- Auto-discovered from AWS (security groups, IAM roles, VPC peering)
- Auto-discovered from application configs (environment variables, service URLs)
- Human-confirmed via intake interview (tools can approximate, humans must validate)
- Stored as graph edges with metadata (dependency type, criticality, data flow direction)

#### 3.3 Confidence Calibration
With several months of Observe/Advise data accumulated:
- Analyze approval/correction rates per agent, per action type, per team
- Tune confidence thresholds in `agent.yaml` based on actual accuracy data
- Graduate high-accuracy actions to Assist (auto-execute above 0.95 confidence)
- Document which patterns are reliable and which still need human review

#### 3.4 Sigma Posture Scoring
Sigma agent computes per-team posture scores from context artifacts:
- Control coverage (controls.yaml vs. expected controls for their compliance scope)
- Vulnerability SLA compliance (findings.md resolution times vs. sla.yaml)
- Artifact freshness (staleness policy from CONVENTIONS.md)
- Open risk items (risk.md active entries)
- Agent autonomy maturity (where they are on the Observe-to-Automate curve)

#### 3.5 Full Test Coverage
- 80% coverage target enforced via CI/CD
- Integration tests for all agent-to-context-layer interactions
- Integration tests for all external API connections (mocked)
- Performance tests for Fusion Engine under load
- Security tests for auth flows and data access controls

### Definition of Done — Phase 3

- [ ] 9+ internal teams onboarded with populated context artifacts
- [ ] Auto-onboarding pipeline produces draft artifacts from discovery data
- [ ] Knowledge graph answers blast-radius and dependency queries for agents
- [ ] At least one agent operating at Assist level for at least 3 teams
- [ ] Sigma produces weekly posture scores per team
- [ ] CI/CD pipeline runs tests on every PR
- [ ] Test coverage at 80% on core platform

---

## 6. Tool Integration Status

| Tool | What's Implemented | Available but Unwired | Not Available |
|------|-------------------|----------------------|---------------|
| **CrowdStrike Falcon** | Host inventory, vulnerabilities, coverage gaps, containers, applications. MCP skill modules for Alpha-4, Beta-4, Gamma, Delta. | — | — |
| **GitHub** | Repo inventory, languages, branches, CODEOWNERS, dependency manifests, CI/CD workflows via `enterprise-topology` GitHubEnterpriseClient. | Dependabot alerts, CodeQL results, secret scanning alerts (GHAS APIs available). | — |
| **AWS** | EC2, S3, RDS, Lambda, IAM, security groups via `aws-security/infrastructure_analyzer.py`. | EKS clusters, ECS task definitions, Security Hub findings, AWS Config compliance. | — |
| **Okta** | Event stream processing, login patterns, MFA status, user profiles, group membership via `iam-security/okta_security/`. Behavioral analytics (Isolation Forest ML). | Bulk user/group/app enumeration, admin group identification. | — |
| **Jira** | Open security tickets, remediation velocity via enterprise integration. | — | — |
| **Panther SIEM** | Dual SIEM forwarding (Panther + CrowdStrike LogScale) via `iam-security/siem/`. | — | — |
| **Neo4j** | `enterprise_graph.py` in `enterprise-topology/src/core/graph/`. Docker Compose for Neo4j instance. | Agent query integration, context layer ingestion, Fusion Engine integration (designed, not built). | — |
| **PagerDuty** | Nothing. Zero implementation. | On-call schedules, escalation policies, MTTR data (APIs well-documented). | — |
| **TheHive** | Write-only: case creation from Gamma agent. | Case history queries, template retrieval (GET endpoints exist). | — |
| **CALDERA** | Delta agent integration for attack simulation. | — | — |
| **BloodHound** | Delta agent integration for AD attack path analysis. | — | — |
| **Slack** | War room bot (`slack-war-rooms/`), notification channels. | Approve/Deny button workflows for Advise phase (needs implementation). | — |

---

## 7. Known Gaps

### Intake Questionnaire Gaps by Priority

**Critical (blocks agent operation):**
- Service-to-service dependencies — needed by all agents for blast radius, not in current questionnaire
- Host-to-service mapping — Gamma cannot resolve "which team owns this host" without this
- Service-to-repo mapping — Beta-4 cannot route findings without this

**High (significantly degrades agent effectiveness):**
- Per-service CrowdStrike host groups (Alpha-4 needs for targeted monitoring)
- IaC tool, container registry, K8s cluster/namespace mapping (Beta-4 needs for scanning scope)
- Per-action approval chains with specific approvers (Gamma needs for containment decisions)
- Containment blackout windows (Gamma needs to avoid disrupting during maintenance)
- Pre-authorized test environments and exclusion lists (Delta needs for safe red teaming)
- Per-service compliance scope (all agents need to apply correct SLA multipliers)
- Service criticality tiers with definitions (Gamma, Sigma need for prioritization)
- Red-flag conditions per team (Gamma needs for escalation triggers)

**Medium (improves agent quality):**
- Industry classification (Alpha-4 threat relevance filtering)
- Third-party vendors (Alpha-4 supply chain risk assessment)
- Threat history and geographic context (Alpha-4 threat modeling)
- Default branch per repo (Beta-4 scanning configuration)
- Languages and dependency ecosystems per repo (Beta-4 scanner selection)
- Base images for containers (Beta-4 image scanning)
- Secrets patterns to detect (Beta-4 secret scanning)
- PagerDuty escalation policy IDs (Gamma incident response)
- False-positive suppression patterns (Gamma alert fatigue reduction)
- Posture baseline denominator (Sigma scoring normalization)
- Incident history and MTTR data (Sigma trend analysis)
- Detection coverage blind spots (Sigma gap analysis)
- Admin group IDs and privileged group taxonomy (IAM security)
- Service accounts inventory (IAM security)
- JIT access policies (IAM security)
- Testing windows and exercise type preferences (Delta scheduling)
- Pen test history (Delta scope planning)

**Addressed by Phase:**
- Phase 1: Critical gaps (service mappings), plus high-priority gaps for the 3 pilot teams filled manually during intake
- Phase 2: High gaps addressed in questionnaire v2, medium gaps for pilot teams via auto-discovery
- Phase 3: All gaps addressed through auto-onboarding pipeline

### Auto-Discovery Coverage

Approximately 60-70% of the data needed by agents is auto-discoverable from existing tool APIs. The remaining 30% genuinely requires human judgment (compliance scope decisions, autonomy preferences, criticality tiers, acceptable risk boundaries). The revised intake questionnaire should focus the human conversation on that 30%, not on data the tools already have.

---

## 8. Open Questions

These are unresolved decisions that the next session should consider. They are not blockers for Phase 1 but will need answers before Phase 2 or Phase 3.

1. **Graph update frequency**: How often should the context ingester sync flat files into Neo4j? Hourly batch? On git push webhook? The answer depends on how fast context changes and how stale is acceptable. Batch is simpler; webhook is more responsive.

2. **Slack Approve/Deny implementation**: The Advise phase requires agents to propose actions via Slack with interactive buttons. The `slack-war-rooms/` bot exists but does not have this workflow. How tightly should this integrate with the existing bot vs. being a separate service?

3. **Multi-team vulnerability coordination**: When a CVE affects services owned by multiple teams, who coordinates? Sigma? A human? The Fusion Engine? The graph can identify the blast radius, but the coordination workflow is undefined.

4. **Context layer access control**: The vision doc says "repo access restricted to Cyber Defense team + team leads (read access to their own team's context)." If this is a single Git repo, branch protection and CODEOWNERS can approximate this, but it is not true per-directory access control. Is a single repo sufficient, or do we need per-team repos?

5. **Staleness enforcement**: CONVENTIONS.md says 90-day staleness triggers a risk signal from Sigma. This requires Sigma to run periodic artifact freshness checks. Is this a cron job? A scheduled Celery task? Who acts on the staleness signal?

6. **External customer context**: The `external-customers/` directory exists with a tiered model (flagship vs. category templates). This roadmap focuses on internal customers. External customer context is deferred, but the flagship model needs definition before onboarding any external customers.

7. **Knowledge graph Phase 5 (real-time streaming)**: Deferred indefinitely. Only build if Phase 4 demonstrates that batch sync from context layer + tool APIs is insufficient. Do not pre-build streaming infrastructure.

8. **Test data strategy**: Tests need synthetic security alert datasets, mock API responses, and representative context layer artifacts. No test data exists today. Creating realistic test fixtures is a prerequisite for meaningful test coverage.

9. **Monorepo tooling**: Each subsystem has independent `requirements.txt`. As integration tightens (agents reading context layer, Fusion Engine querying graph), shared dependencies will cause version conflicts. Evaluate whether to adopt a unified dependency management approach (e.g., Poetry workspace, pip-tools with constraints).

10. **Cost tracking**: The realistic value assessment projects $360K-500K annual value. Phase 1 should establish baseline measurements (triage time, context-gathering time, routing accuracy) so value can be measured, not estimated.

---

## Reference: Key File Locations

| What | Where |
|------|-------|
| Project overview and build commands | `CLAUDE.md` |
| This roadmap | `ROADMAP.md` |
| Context layer structure | `context-layer/README.md` |
| Artifact conventions | `context-layer/CONVENTIONS.md` |
| Leadership vision | `context-layer/VISION-Agentic-Security-Delivery.md` |
| Intake questionnaire | `context-layer/INTAKE-QUESTIONNAIRE.md` |
| Vulnerability SLA config | `context-layer/sla.yaml` |
| Customer artifact templates | `context-layer/templates/` |
| Internal customer directories | `context-layer/internal-customers/{platform-engineering,ai-ml-engineering,devops-sre}/` |
| Intelligence Fusion Engine | `enhanced-analysis/intelligence_fusion_engine.py` |
| Agent Orchestrator | `enhanced-analysis/agent_orchestration_system.py` |
| Production API Server | `enhanced-analysis/production_api_server.py` |
| Existing Neo4j graph | `enterprise-topology/src/core/graph/enterprise_graph.py` |
| CrowdStrike MCP skills | `crowdstrike-mcp-integration/skills/` |
| IAM/Okta integration | `iam-security/okta_security/` |
| SecOps governance/compliance | `secops-ai-orchestration/` |
| Test coverage assessment | `docs/TEST-COVERAGE-REQUIREMENTS.md` |
| Realistic value assessment | `docs/REALISTIC-VALUE-ASSESSMENT.md` |
| Knowledge graph analysis | `analysis/KNOWLEDGE-GRAPH-ANALYSIS.md` |
| Archived analysis docs | `docs/archive/` |
