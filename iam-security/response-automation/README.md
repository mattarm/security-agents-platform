# Automated Identity Threat Response System

## Overview
Enterprise-grade automated response system for identity-based security threats, integrating Okta identity management with SIEM platforms (Panther/CrowdStrike) and incident response workflows.

## Architecture
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│     SIEM        │    │   Response      │    │      Okta       │
│  (Panther/CS)   │───▶│    Engine       │───▶│   Admin API     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                    ┌─────────────────┐
                    │  Notification   │
                    │    System       │
                    │ (SOC/Executive) │
                    └─────────────────┘
```

## Key Components

### 1. Response Actions Framework (`/response_actions/`)
- **Account Security**: Account lock, MFA step-up, session termination
- **Privilege Management**: Role revocation, access reduction
- **Device Management**: Device de-registration, trust removal
- **Bulk Operations**: Mass account management for incidents

### 2. SIEM Integrations (`/integrations/`)
- **Panther**: Webhook receiver for current SIEM alerts
- **CrowdStrike Falcon Fusion**: Automated workflow integration
- **Threat Intelligence**: Enrichment and context gathering

### 3. Incident Management (`/incident/`)
- **TheHive Integration**: Automated case creation and updates
- **Escalation Logic**: SOC analyst and executive notification workflows
- **Response Playbooks**: Automated response decision trees

### 4. Monitoring & Compliance (`/monitoring/`)
- **Audit Trails**: Comprehensive action logging
- **Fail-safe Mechanisms**: Manual override capabilities
- **Compliance Reporting**: Regulatory requirement tracking

## Quick Start

1. **Configuration**: Copy `config/config.example.yaml` to `config/config.yaml` and configure
2. **Dependencies**: Run `./scripts/setup.sh` to install requirements
3. **Testing**: Run `python -m pytest tests/` to verify setup
4. **Deployment**: Use Docker Compose or direct Python execution

## Security Features

- **Zero Trust**: All actions require authentication and authorization
- **Audit Everything**: Complete action and decision logging
- **Fail-Safe**: Manual override available for all automated actions
- **Encryption**: All sensitive data encrypted at rest and in transit

## Response Capabilities

### Immediate Actions (< 30 seconds)
- Account lockout
- Session termination
- MFA step-up enforcement

### Investigative Actions (< 5 minutes)
- Role privilege reduction
- Device trust removal
- Access pattern analysis

### Containment Actions (< 15 minutes)
- Bulk user management
- Network access restriction
- Credential reset workflows

## Integration Points

- **Okta Admin API**: Primary identity management
- **Panther SIEM**: Current threat detection platform
- **CrowdStrike Falcon**: Future SIEM migration target
- **TheHive**: Incident response case management
- **SecurityAgents**: Existing security platform integration

## Compliance & Audit

- SOX-compliant action logging
- GDPR data handling procedures
- PCI DSS access control requirements
- ISO 27001 incident response alignment