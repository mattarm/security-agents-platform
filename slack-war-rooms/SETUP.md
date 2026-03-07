# Slack War Rooms Setup Guide

## Overview
This guide will help you deploy the Slack War Room Bot for SOC operations, integrating with your enhanced SecurityAgents platform and CrowdStrike MCP.

## Prerequisites

### 1. Slack Workspace Setup
- Admin access to Slack workspace
- Ability to create and manage Slack apps
- Appropriate permissions for bot operations

### 2. CrowdStrike Falcon Access
- CrowdStrike Falcon API credentials (Client ID and Secret)
- Appropriate API scopes for SecurityAgents integration
- MCP server access (if using hosted MCP)

### 3. Infrastructure Requirements
- Docker and Docker Compose installed
- Minimum 2GB RAM, 1 CPU core
- 10GB storage for database and logs
- Network access to Slack and CrowdStrike APIs

## Quick Start

### 1. Clone and Configure
```bash
# Navigate to war rooms directory
cd ~/security-assessment/slack-war-rooms

# Copy environment configuration
cp .env.example .env

# Edit configuration with your credentials
nano .env
```

### 2. Slack App Configuration

#### Create Slack App
1. Go to [Slack API Console](https://api.slack.com/apps)
2. Click "Create New App" → "From scratch"
3. Name: "SecurityAgents War Room Bot"
4. Select your workspace

#### Configure OAuth & Permissions
Add these OAuth scopes:
```
Bot Token Scopes:
- channels:read
- channels:write
- chat:write
- commands
- files:write
- groups:read
- groups:write
- im:read
- im:write
- mpim:read
- mpim:write
- users:read
```

#### Configure Slash Commands
Create these slash commands:
```
/create-war-room - Create new war room
/alpha - Execute Alpha-4 threat intelligence commands  
/gamma - Execute Gamma SOC operations commands
/beta - Execute Beta-4 DevSecOps commands
/delta - Execute Delta red team commands
/evidence - Collect and manage evidence
/war-room-status - Show war room status
```

#### Configure Socket Mode
1. Enable Socket Mode in your app settings
2. Generate App-Level Token with `connections:write` scope
3. Copy the App Token (starts with `xapp-`)

#### Install App to Workspace
1. Go to "Install App" section
2. Install to your workspace
3. Copy the Bot User OAuth Token (starts with `xoxb-`)

### 3. Environment Configuration

Edit `.env` file with your credentials:
```bash
# Slack Configuration
SLACK_BOT_TOKEN=xoxb-your-bot-token-here
SLACK_APP_TOKEN=xapp-your-app-token-here
SLACK_SIGNING_SECRET=your-signing-secret-here

# CrowdStrike Configuration
CROWDSTRIKE_CLIENT_ID=your-falcon-client-id
CROWDSTRIKE_CLIENT_SECRET=your-falcon-client-secret

# Database Configuration (SQLite for quick start)
DB_TYPE=sqlite
DB_PATH=/app/data/war_rooms.db

# War Room Settings
ESCALATION_CHANNELS=#security-escalation,#soc-alerts
```

### 4. Deploy with Docker

#### Quick SQLite Deployment
```bash
# Build and start with SQLite (simplest setup)
docker-compose up --build -d

# View logs
docker-compose logs -f slack-war-room-bot
```

#### Production PostgreSQL Deployment
```bash
# Configure PostgreSQL in .env
DB_TYPE=postgresql
DB_HOST=postgres
DB_USERNAME=war_room_user
DB_PASSWORD=secure_password_here
DB_DATABASE=war_rooms

# Start full stack
docker-compose -f docker-compose.yml up --build -d

# View all service logs
docker-compose logs -f
```

### 5. Verify Installation

#### Check Bot Status
```bash
# Check if bot is running
docker-compose ps

# Check bot logs
docker-compose logs slack-war-room-bot

# Health check
curl http://localhost:8080/health
```

#### Test in Slack
1. Go to your Slack workspace
2. Type `/create-war-room incident_response high Test incident`
3. Bot should respond with war room creation confirmation
4. Test agent commands:
   - `/alpha actor APT28`
   - `/gamma hunt PowerShell lateral movement`
   - `/beta scan nginx:latest`

## War Room Usage

### Creating War Rooms

#### Automatic Creation (Future Feature)
War rooms can be automatically created from:
- CrowdStrike Falcon alerts
- SIEM alerts
- Security tool integrations

#### Manual Creation
```bash
# Basic war room creation
/create-war-room <type> <severity> <title>

# Examples
/create-war-room incident_response critical "Ransomware Attack"
/create-war-room threat_hunting medium "APT28 Investigation"
/create-war-room vulnerability_response high "Log4j Zero Day"
/create-war-room purple_team_exercise low "Monthly Security Validation"
```

### Agent Commands

#### Alpha-4 Threat Intelligence
```bash
/alpha actor APT28                    # Research threat actor
/alpha ioc 192.168.1.100             # Enrich IOC
/alpha hunt APT28                     # Generate hunt queries
/alpha brief 7d                      # Intelligence briefing
```

#### Gamma SOC Operations
```bash
/gamma incident INC-2024-001         # Analyze incident
/gamma hunt "lateral movement"       # Execute hunting
/gamma contain host1,host2,host3     # Initiate containment
/gamma posture                       # Security posture check
```

#### Beta-4 DevSecOps
```bash
/beta scan nginx:latest              # Container security scan
/beta k8s production-cluster         # Kubernetes assessment
/beta pipeline myapp/main            # Pipeline security check
/beta supply-chain myapp             # Supply chain analysis
```

#### Delta Red Team
```bash
/delta exercise "PowerShell test"    # Purple team exercise
/delta simulate APT28                # Threat actor simulation
/delta test T1059.001                # Test MITRE technique
/delta validate detection-rule-001   # Validate detection
```

### Evidence Management

#### Automatic Evidence Collection
- All agent commands automatically create evidence records
- Timestamped with user attribution
- Hash verification for integrity
- Searchable and exportable

#### Manual Evidence Addition
```bash
/evidence add "Malware sample" <file-upload>
/evidence timeline "14:30 - Initial compromise detected"
/evidence note "Contacted threat intel team for attribution"
```

### War Room Lifecycle

#### Investigation Phase
1. War room created (manually or automatically)
2. Relevant team members invited
3. Appropriate agents assigned
4. Investigation begins with agent assistance

#### Collaboration Phase
1. Team discusses findings in real-time
2. Agents provide analysis and recommendations
3. Evidence automatically collected and organized
4. Timeline built incrementally

#### Resolution Phase
1. Containment actions executed
2. Remediation steps implemented
3. Validation performed
4. Documentation completed

#### Archive Phase
1. War room archived automatically after 30 days
2. All evidence preserved for compliance
3. Lessons learned extracted
4. Metrics updated

## Integration with SecurityAgents Platform

### CrowdStrike MCP Integration
The war room bot integrates with your existing SecurityAgents CrowdStrike MCP implementation:

```bash
# Bot connects to same CrowdStrike instance
# Uses same authentication and permissions
# Leverages enhanced agent capabilities
# Real-time threat intelligence and analysis
```

### Agent Communication
```python
# Agents run in same environment
# Shared CrowdStrike MCP session
# Consistent data and analysis
# Cross-agent workflow coordination
```

## Monitoring and Maintenance

### Health Checks
```bash
# Check bot health
curl http://localhost:8080/health

# Database connectivity
docker-compose exec slack-war-room-bot python scripts/db_check.py

# Agent connectivity
docker-compose exec slack-war-room-bot python scripts/agent_check.py
```

### Log Management
```bash
# View real-time logs
docker-compose logs -f

# Bot-specific logs
docker-compose logs -f slack-war-room-bot

# Database logs
docker-compose logs -f postgres
```

### Backup and Recovery
```bash
# Database backup
docker-compose exec postgres pg_dump -U war_room_user war_rooms > backup.sql

# Data directory backup
docker run --rm -v slack-war-rooms_war_room_data:/data -v $(pwd):/backup alpine tar czf /backup/war_room_backup.tar.gz /data

# Restore from backup
# Stop services, restore data, restart
```

## Security Considerations

### Network Security
- Bot communicates with Slack via HTTPS/WSS
- CrowdStrike API access via HTTPS
- Internal container communication isolated
- No unnecessary port exposure

### Data Protection
- All credentials stored as environment variables
- Database encryption at rest (if using external DB)
- Evidence integrity verification
- Audit logging for all actions

### Access Control
- Slack workspace access controls
- Bot permissions limited to required scopes
- War room access based on Slack channel membership
- Evidence access tracked and logged

## Troubleshooting

### Common Issues

#### Bot Not Responding
```bash
# Check bot logs
docker-compose logs slack-war-room-bot

# Verify Slack tokens
python scripts/verify_slack_tokens.py

# Test network connectivity
docker-compose exec slack-war-room-bot curl https://slack.com/api/api.test
```

#### Database Connection Issues
```bash
# Check database status
docker-compose ps postgres

# Test database connection
docker-compose exec slack-war-room-bot python scripts/db_test.py

# View database logs
docker-compose logs postgres
```

#### Agent Commands Failing
```bash
# Verify CrowdStrike credentials
python scripts/verify_crowdstrike.py

# Check agent integration
docker-compose exec slack-war-room-bot python scripts/agent_test.py

# Review agent logs
docker-compose logs slack-war-room-bot | grep -i agent
```

### Support

For additional support:
1. Check logs for error messages
2. Verify all configuration variables
3. Test individual components separately
4. Review Slack app configuration
5. Validate CrowdStrike API access

## Next Steps

After successful deployment:
1. Configure automatic war room creation from security tools
2. Set up custom notification channels
3. Train SOC team on war room workflows
4. Establish evidence retention policies
5. Create custom dashboards and reporting

This completes the setup of your Slack War Room Bot for SecurityAgents SOC operations!