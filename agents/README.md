# SecurityAgents - Specialized Security Agents

This directory contains the 5 specialized security agents that form the core of the SecurityAgents platform.

## Available Agents

### 🧠 Alpha-4 (Threat Intelligence)
- **File**: `alpha_4_threat_intel_skills.py`
- **Enhanced Skills**: `../crowdstrike-mcp-integration/skills/alpha_4_threat_intel_skills.py`
- **Capabilities**: Real-time threat actor research, IOC correlation, MITRE ATT&CK mapping

### 🛡️ Gamma (SOC Operations)
- **File**: `gamma_blue_team_agent.py`
- **Enhanced Skills**: `../crowdstrike-mcp-integration/skills/gamma_soc_skills.py`
- **Capabilities**: Incident response, threat hunting, automated containment

### 🔒 Beta-4 (DevSecOps Security)
- **Enhanced Skills**: `../crowdstrike-mcp-integration/skills/beta_4_devsecops_skills.py`
- **Capabilities**: Container scanning, K8s assessment, pipeline security gates

### ⚔️ Delta (Red Team Operations)
- **File**: `delta_red_team_agent.py`
- **Enhanced Skills**: `../crowdstrike-mcp-integration/skills/delta_red_team_skills.py`
- **Capabilities**: Attack simulation, detection validation, purple team exercises

### 📊 Sigma (Security Metrics)
- **File**: `sigma_metrics_agent.py`
- **Documentation**: `SIGMA-AGENT.md`
- **Demo**: `demo_sigma_agent.py`
- **Capabilities**: ODM tracking, automated reporting, executive dashboards

## CrowdStrike MCP Integration

All agents are enhanced with CrowdStrike MCP integration providing:
- Native Falcon platform access
- Real-time threat intelligence
- Advanced query capabilities (FQL)
- Cross-domain correlation

## Slack Integration

All agents are accessible through Slack War Rooms with interactive commands:
- `/alpha` - Threat intelligence commands
- `/gamma` - SOC operations commands
- `/beta` - DevSecOps security commands
- `/delta` - Red team operations commands
- `/sigma` - Security metrics commands

See the [Slack War Rooms documentation](../slack-war-rooms/) for complete usage instructions.