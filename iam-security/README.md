# Okta Identity Security Integration

## Overview
Comprehensive Okta-based identity security monitoring, threat detection, and automated response system with dual SIEM compatibility (Panther/CrowdStrike).

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Okta APIs     │    │  Event Analytics │    │  SIEM Outputs   │
│  - System Log   │───▶│  - Correlation   │───▶│  - Panther      │
│  - Admin API    │    │  - ML Detection  │    │  - CrowdStrike  │
│  - User API     │    │  - Rules Engine  │    │  - CEF/JSON     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌─────────────────┐
                       │ Response Engine │
                       │ - Disable User  │
                       │ - Kill Session  │
                       │ - Force MFA     │
                       └─────────────────┘
```

## Components

### 1. Core Framework (`okta_security/`)
- **api_client.py**: Okta SDK wrapper with rate limiting and error handling
- **auth_manager.py**: OAuth 2.0 token management and rotation
- **event_collector.py**: Real-time event stream collection

### 2. Analytics Engine (`analytics/`)
- **correlation_engine.py**: Event correlation and session reconstruction
- **threat_detector.py**: ML-based anomaly detection
- **rules_engine.py**: Configurable threat detection rules

### 3. Response System (`response/`)
- **action_executor.py**: Automated response orchestration
- **okta_actions.py**: Direct Okta API response actions
- **notification_manager.py**: Alert and incident management

### 4. SIEM Integration (`siem/`)
- **panther_forwarder.py**: Panther-optimized log formatting
- **crowdstrike_forwarder.py**: CrowdStrike Falcon integration
- **universal_formatter.py**: Common event schema

## Security Features

### Threat Detection
- **Suspicious Logins**: Geographic/time anomalies, impossible travel
- **Privilege Escalation**: Role changes, admin access patterns
- **Account Abuse**: Failed login patterns, credential stuffing
- **Session Hijacking**: Token anomalies, concurrent sessions
- **Application Abuse**: Unusual app access patterns

### Automated Response
- **Immediate**: Session termination, account suspension
- **Conditional**: MFA enforcement, password reset requirements
- **Investigative**: Enhanced logging, session monitoring

## Installation

```bash
pip install -r requirements.txt
cp config/config.example.yml config/config.yml
# Configure Okta API credentials and SIEM endpoints
python -m okta_security.main
```

## Configuration

See `config/config.yml` for full configuration options including:
- Okta API credentials and rate limits
- Threat detection sensitivity levels
- SIEM forwarding configurations
- Automated response policies

## Production Deployment

- **Monitoring**: Prometheus metrics, health checks
- **Resilience**: Circuit breakers, retry logic, dead letter queues
- **Security**: Credential rotation, audit logging, least privilege