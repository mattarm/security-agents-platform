# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Context

SecurityAgents Platform is an enterprise cyber defense platform built to scale a Cyber Defense team through AI-powered automation and agentic delivery. The platform coordinates five specialized security agents through an intelligence fusion architecture, integrating with CrowdStrike, Okta, Panther SIEM, AWS, and 10 GitHub-hosted security tools (CALDERA, TheHive, BloodHound, etc.).

**Current state**: Core agents and integrations are implemented. Test coverage is a critical gap — see `docs/TEST-COVERAGE-REQUIREMENTS.md` for the honest assessment. The context layer (`context-layer/`) establishes internal engineering teams as security customers with persistent, agent-readable artifacts.

## Architecture

### Core Pattern: Intelligence Fusion
All agents communicate through the Intelligence Fusion Engine (`enhanced-analysis/intelligence_fusion_engine.py`), which performs cross-domain threat correlation using Intelligence Packets. The Agent Orchestrator (`enhanced-analysis/agent_orchestration_system.py`) coordinates multi-agent task execution with dependency management. The Production API Server (`enhanced-analysis/production_api_server.py`) exposes everything via FastAPI with JWT/OAuth 2.0 auth.

### Agent Ecosystem
| Agent | Location | Role |
|-------|----------|------|
| Alpha-4 | `enhanced-analysis/tiger_team_alpha_4.py` | Threat intelligence (OSINT, IOC analysis, campaign attribution) |
| Beta-4 | `enhanced-analysis/tiger_team_beta_4.py` | DevSecOps (SAST, container scanning, IaC security) |
| Gamma | `agents/gamma_blue_team_agent.py` | SOC operations (incident response, threat hunting, TheHive) |
| Delta | `agents/delta_red_team_agent.py` | Red team (CALDERA, BloodHound, attack simulation) |
| Sigma | `agents/sigma_metrics_agent.py` | Security metrics and program tracking |

### Key Subsystems
- **CrowdStrike MCP Integration** (`crowdstrike-mcp-integration/`): MCP client framework with per-agent skill modules in `skills/`
- **IAM Security** (`iam-security/`): Okta integration, behavioral analytics (Isolation Forest ML), automated response, dual SIEM forwarding (Panther/CrowdStrike)
- **SecOps AI Orchestration** (`secops-ai-orchestration/`): AI confidence engine, autonomy tiers (0-3), governance controls with SOC2/ISO compliance tests
- **Slack War Rooms** (`slack-war-rooms/`): SOC collaboration bot
- **Enterprise Topology** (`enterprise-topology/`): Technology stack mapping and analysis
- **Infrastructure as Code** (`security-agents-infrastructure/`): Terraform modules for AWS (VPC, KMS, monitoring)

### Data Layer
- **PostgreSQL**: Persistent storage (asyncpg driver, SQLAlchemy async ORM)
- **Redis**: Real-time caching, Celery task queue backend
- **S3**: Audit logs and evidence storage

## Build & Run Commands

### Local Development (Docker)
```bash
cd enhanced-analysis && docker-compose up -d     # Start full stack (API, postgres, redis, prometheus, grafana)
cd enhanced-analysis && docker-compose -f docker-compose.prod.yml up -d  # Production mode
curl http://localhost:8080/health                  # Verify API
```

### Direct Execution
```bash
python enhanced-analysis/production_api_server.py          # API server
python enhanced-analysis/production_api_server.py --dev     # Dev mode
```

### Running Tests
```bash
# SecOps orchestration tests (has pytest.ini with coverage config)
cd secops-ai-orchestration && pytest                        # All tests
cd secops-ai-orchestration && pytest tests/security/        # Security tests only
cd secops-ai-orchestration && pytest -m compliance          # By marker
cd secops-ai-orchestration && pytest tests/test_orchestrator.py::test_name  # Single test

# CrowdStrike integration tests
pytest crowdstrike-mcp-integration/tests/

# IAM SIEM analytics tests
pytest iam-security/siem-analytics/tests/
```

### Test Markers (secops-ai-orchestration)
`unit`, `integration`, `performance`, `security`, `compliance`, `ai`, `slow`, `requires_aws`, `requires_models`

### Code Quality
```bash
black --check .          # Format check
isort --check-only .     # Import order check
mypy .                   # Type checking
```

## Tech Stack
- **Python 3.10+**, async-first with asyncio/aiohttp/httpx
- **FastAPI + Uvicorn** for API layer
- **Pydantic v2** for data validation
- **Celery + Redis** for background task processing
- **Docker Compose** for local orchestration
- **Terraform** for AWS infrastructure

## Conventions

- Agents follow the `SecurityAgent` base pattern: `__init__` with config + tools, `process_task` async method, `send_intelligence` to fusion engine
- All external API integrations use async clients with circuit breaker patterns (`circuitbreaker` library)
- Structured JSON logging via `structlog`
- Configuration managed through `config_manager.py` and `.env` files
- Test files follow `test_*.py` naming; pytest with `asyncio_mode = auto` for async tests
- Coverage target: 80% minimum (`--cov-fail-under=80` in pytest.ini)

## Important Notes

- The `.gitignore` is minimal (only `temp-repos/`) — be careful not to commit `.env` files, credentials, or large binary artifacts
- Several subsystems have independent `requirements.txt` files — there is no unified virtual environment or monorepo tooling
- The codebase references environment variables for secrets: `OKTA_API_TOKEN`, `GITHUB_TOKEN`, `VIRUSTOTAL_API_KEY`, and database/Redis connection strings
- Agent source files are large (Alpha-4: ~23k lines, Beta-4: ~58k lines) — read specific sections rather than entire files
