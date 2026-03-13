# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Context

SecurityAgents Platform is an enterprise cyber defense platform built to scale a Cyber Defense team through AI-powered automation and agentic delivery. The platform coordinates five specialized security agents through an intelligence fusion architecture, integrating with CrowdStrike, Okta, Panther SIEM, AWS, and 10 GitHub-hosted security tools (CALDERA, TheHive, BloodHound, etc.).

**Current state**: Core agents and integrations are implemented. Test coverage is a critical gap — see `docs/TEST-COVERAGE-REQUIREMENTS.md` for the honest assessment. The context layer (`src/security_agents/core/context-layer/`) establishes internal engineering teams as security customers with persistent, agent-readable artifacts.

## Repository Layout

```
security-agents-platform/
├── src/security_agents/          # Main package
│   ├── core/                     # Fusion engine, orchestrator, API server, config
│   ├── agents/                   # Agent definitions and routing
│   │   └── engines/              # Agent engine source files (Alpha-4, Beta-4, Gamma, Delta, Sigma)
│   ├── skills/                   # Per-agent skill modules (CrowdStrike MCP, etc.)
│   └── integrations/             # External service integrations (IAM, SecOps, Slack, Topology)
├── tests/                        # All test suites
├── infrastructure/               # Terraform modules for AWS (VPC, KMS, monitoring)
├── deploy/                       # Docker Compose files and deployment configs
├── docs/                         # Project documentation
├── archive/                      # Legacy/deprecated code
└── pyproject.toml                # Package config, pytest settings, tool configs
```

## Architecture

### Core Pattern: Intelligence Fusion
All agents communicate through the Intelligence Fusion Engine (`src/security_agents/core/intelligence_fusion_engine.py`), which performs cross-domain threat correlation using Intelligence Packets. The Agent Orchestrator (`src/security_agents/core/agent_orchestration_system.py`) coordinates multi-agent task execution with dependency management. The Production API Server (`src/security_agents/core/production_api_server.py`) exposes everything via FastAPI with JWT/OAuth 2.0 auth.

### Agent Ecosystem
| Agent | Location | Role |
|-------|----------|------|
| Alpha-4 | `src/security_agents/agents/engines/tiger_team_alpha_4.py` | Threat intelligence (OSINT, IOC analysis, campaign attribution) |
| Beta-4 | `src/security_agents/agents/engines/tiger_team_beta_4.py` | DevSecOps (SAST, container scanning, IaC security) |
| Gamma | `src/security_agents/agents/engines/gamma_blue_team_agent.py` | SOC operations (incident response, threat hunting, TheHive) |
| Delta | `src/security_agents/agents/engines/delta_red_team_agent.py` | Red team (CALDERA, BloodHound, attack simulation) |
| Sigma | `src/security_agents/agents/engines/sigma_metrics_agent.py` | Security metrics and program tracking |

### Key Subsystems
- **CrowdStrike MCP Integration** (`src/security_agents/skills/`): MCP client framework with per-agent skill modules
- **IAM Security** (`src/security_agents/integrations/iam-security/`): Okta integration, behavioral analytics (Isolation Forest ML), automated response, dual SIEM forwarding (Panther/CrowdStrike)
- **SecOps AI Orchestration** (`src/security_agents/integrations/secops-ai-orchestration/`): AI confidence engine, autonomy tiers (0-3), governance controls with SOC2/ISO compliance tests
- **Slack War Rooms** (`src/security_agents/integrations/slack-war-rooms/`): SOC collaboration bot
- **Enterprise Topology** (`src/security_agents/integrations/enterprise-topology/`): Technology stack mapping and analysis
- **Infrastructure as Code** (`infrastructure/`): Terraform modules for AWS (VPC, KMS, monitoring)

### Data Layer
- **PostgreSQL**: Persistent storage (asyncpg driver, SQLAlchemy async ORM)
- **Redis**: Real-time caching, Celery task queue backend
- **S3**: Audit logs and evidence storage

## Build & Run Commands

### Installation
```bash
pip install -e .                  # Install package in editable mode (uses pyproject.toml)
pip install -e ".[dev]"           # Include dev/test dependencies
```

### Local Development (Docker)
```bash
cd deploy && docker-compose up -d                          # Start full stack (API, postgres, redis, prometheus, grafana)
cd deploy && docker-compose -f docker-compose.prod.yml up -d  # Production mode
curl http://localhost:8080/health                           # Verify API
```

### Direct Execution
```bash
python -m security_agents.core.production_api_server          # API server
python -m security_agents.core.production_api_server --dev     # Dev mode
```

### Running Tests
```bash
# All tests (pytest config lives in pyproject.toml)
pytest                                                      # Run full suite
pytest tests/security/                                      # Security tests only
pytest -m compliance                                        # By marker
pytest tests/test_orchestrator.py::test_name                # Single test

# Subsystem tests
pytest tests/integrations/                                  # Integration tests
pytest tests/skills/                                        # Skill module tests
```

### Test Markers
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
- Coverage target: 80% minimum (`--cov-fail-under=80` configured in `pyproject.toml`)
- Package installed via `pip install -e .` — all tool config (pytest, black, isort, mypy) lives in `pyproject.toml`

## Important Notes

- The `.gitignore` covers Python artifacts, virtual environments, IDE files, secrets, and OS files
- The project uses a unified `pyproject.toml` for package management — no scattered `requirements.txt` files
- The codebase references environment variables for secrets: `OKTA_API_TOKEN`, `GITHUB_TOKEN`, `VIRUSTOTAL_API_KEY`, and database/Redis connection strings
- Agent engine source files are large (Alpha-4: ~23k lines, Beta-4: ~58k lines) — read specific sections rather than entire files
- Legacy code from the previous flat repo structure is preserved in `archive/` for reference
