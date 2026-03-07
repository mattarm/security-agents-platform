# IAM Security Analytics Engine
## Panther → CrowdStrike Transition Framework

A comprehensive identity threat analytics platform that seamlessly operates across Panther and CrowdStrike SIEM environments, providing advanced UEBA capabilities and real-time threat detection.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    IAM Analytics Engine                     │
├─────────────────────────────────────────────────────────────┤
│  Okta Events → Normalization → UEBA → Detection → Alerts   │
└─────────────────────────────────────────────────────────────┘

Data Flow:
  Okta Logs → Framework Adapter → Platform Processor → UEBA Engine → Alerts
     │              │                    │               │
     │              │                    │               ├─ Panther Rules
     │              │                    │               └─ CrowdStrike LogScale
     │              │                    │
     │              │                    ├─ Behavior Baselines
     │              │                    ├─ ML Anomaly Detection
     │              │                    └─ Risk Scoring
     │              │
     │              ├─ Data Normalization
     │              ├─ Event Enrichment
     │              └─ Platform Translation
     │
     └─ Identity Events, Authentication, Authorization, Admin Actions
```

## Components

### 1. Panther Integration (`/panther/`)
- Python detection rules for identity threats
- Custom schemas for Okta events
- Real-time analytics queries

### 2. CrowdStrike Preparation (`/crowdstrike/`)
- Falcon LogScale query language implementations
- Data model definitions for future migration
- Query optimization frameworks

### 3. UEBA Engine (`/ueba/`)
- Statistical behavior baseline models
- Machine learning anomaly detection
- Risk scoring algorithms
- User behavior profiling

### 4. Cross-Platform Framework (`/framework/`)
- Platform-agnostic adapters
- Event processors and normalizers
- Alert routing and management

### 5. Threat Detection Patterns

#### Implemented Detections:
- **Credential Stuffing**: Multiple failed logins across accounts
- **Privilege Escalation**: Unusual role/group changes
- **Lateral Movement**: Cross-system access patterns
- **Account Takeover**: Behavioral anomalies post-authentication
- **Insider Threats**: Anomalous data access patterns

## Quick Start

1. **Configure Data Sources**:
   ```bash
   cd config/
   cp okta-config.yaml.example okta-config.yaml
   # Edit configuration
   ```

2. **Deploy Panther Rules**:
   ```bash
   cd panther/rules/
   # Upload .py files to Panther console
   ```

3. **Test UEBA Engine**:
   ```bash
   cd ueba/
   python test_baselines.py
   ```

## Migration Timeline

- **Phase 1 (Current)**: Panther integration with UEBA engine
- **Phase 2 (Q3)**: Parallel CrowdStrike development and testing
- **Phase 3 (Q4)**: Migration and platform transition
- **Phase 4 (Q1 Next Year)**: CrowdStrike optimization and Panther sunset

## Key Features

✅ **Real-time Detection**: Sub-minute alert generation  
✅ **Cross-Platform**: Works with both Panther and CrowdStrike  
✅ **ML-Powered**: Advanced anomaly detection algorithms  
✅ **Scalable**: Handles enterprise-scale identity events  
✅ **Configurable**: Tunable risk thresholds and baselines  

## Security Considerations

- All credentials stored in secure configuration management
- RBAC enforcement for analytics access
- Audit trails for all detection rule changes
- Privacy-preserving analytics where possible

---
**Status**: Active Development  
**Owner**: Security Analytics Team  
**Last Updated**: 2026-03-06