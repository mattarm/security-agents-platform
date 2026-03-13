# IAM Security Analytics Engine - Deployment Guide

## Overview

This guide covers the deployment and configuration of the IAM Security Analytics Engine for the Panther→CrowdStrike transition.

## Prerequisites

### System Requirements
- Python 3.9+
- 8GB RAM minimum (16GB recommended for production)
- 100GB disk space for logs and models
- Network access to Okta, Panther, and/or CrowdStrike APIs

### Required API Access
- **Okta**: System log API access with read permissions
- **Panther**: Data Lake API access and alert creation permissions
- **CrowdStrike**: LogScale API access (for migration preparation)

## Installation

### 1. Environment Setup

```bash
# Clone or extract the analytics engine
cd ~/security-assessment/iam-security/siem-analytics/

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Dependencies

Create `requirements.txt`:
```
numpy>=1.21.0
pandas>=1.3.0
scikit-learn>=1.0.0
aiohttp>=3.8.0
pyyaml>=6.0
joblib>=1.1.0
asyncio>=3.4.3
falconpy>=1.2.0
panther-analysis-tool>=0.15.0
```

### 3. Configuration

```bash
# Copy configuration template
cp config/okta-config.yaml config/production-config.yaml

# Edit configuration with your environment details
vim config/production-config.yaml
```

## Configuration

### Okta Integration

```yaml
okta:
  domain: "your-org.okta.com"
  api_token: "${OKTA_API_TOKEN}"
  events:
    types:
      - "system.auth.login"
      - "system.auth.logout"
      - "user.lifecycle.create"
      # ... (see full config for complete list)
```

### Panther Integration

```yaml
platforms:
  panther:
    enabled: true
    api_url: "${PANTHER_API_URL}"
    api_token: "${PANTHER_API_TOKEN}"
```

### CrowdStrike Integration (For Migration)

```yaml
platforms:
  crowdstrike:
    enabled: false  # Enable during migration phase
    falcon_client_id: "${CROWDSTRIKE_CLIENT_ID}"
    falcon_client_secret: "${CROWDSTRIKE_CLIENT_SECRET}"
    cloud_region: "us-1"
```

### Environment Variables

```bash
# Create .env file
cat > .env << EOF
OKTA_API_TOKEN=your_okta_token
PANTHER_API_URL=https://your-panther.runpanther.net
PANTHER_API_TOKEN=your_panther_token
CROWDSTRIKE_CLIENT_ID=your_crowdstrike_client_id
CROWDSTRIKE_CLIENT_SECRET=your_crowdstrike_client_secret
ALERT_WEBHOOK_URL=https://your-webhook.com/alerts
SLACK_WEBHOOK_URL=https://hooks.slack.com/your-webhook
EOF

# Load environment variables
source .env
```

## Deployment Phases

### Phase 1: Panther Integration (Current)

1. **Deploy Detection Rules to Panther**
```bash
# Upload Panther Python rules
cd panther/rules/
# Upload *.py files to Panther console or via panther_analysis_tool
```

2. **Initialize UEBA Baselines**
```bash
# Build initial behavior baselines
python main.py --mode baseline --lookback 720  # 30 days
```

3. **Start Monitoring**
```bash
# Start continuous monitoring
python main.py --mode continuous --duration 168  # 1 week
```

### Phase 2: CrowdStrike Preparation (Q3)

1. **Enable CrowdStrike Adapter**
```yaml
platforms:
  crowdstrike:
    enabled: true
```

2. **Deploy LogScale Queries**
```bash
# Import detection queries into CrowdStrike LogScale
# Use queries from crowdstrike/logscale/iam_detection_queries.logscale
```

3. **Parallel Testing**
```bash
# Run parallel detection on both platforms
python main.py --mode single --detection-type credential_stuffing
```

### Phase 3: Migration (Q4)

1. **Data Migration**
```bash
# Export baselines and migrate
python -c "
from framework.adapters.platform_adapter import CrossPlatformAnalyticsEngine
engine = CrossPlatformAnalyticsEngine()
engine.migrate_detection_rules('panther', 'crowdstrike')
"
```

2. **Switch Primary Platform**
```yaml
platforms:
  panther:
    enabled: false
  crowdstrike:
    enabled: true
```

### Phase 4: Optimization (Q1 Next Year)

1. **Tune Detection Rules**
2. **Optimize LogScale Queries**
3. **Sunset Panther Integration**

## Monitoring and Maintenance

### Health Checks

```bash
# Create systemd service for continuous monitoring
sudo cat > /etc/systemd/system/iam-analytics.service << EOF
[Unit]
Description=IAM Security Analytics Engine
After=network.target

[Service]
Type=simple
User=security
WorkingDirectory=/opt/iam-analytics
Environment=PATH=/opt/iam-analytics/venv/bin
ExecStart=/opt/iam-analytics/venv/bin/python main.py --mode continuous --duration 8760
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl enable iam-analytics
sudo systemctl start iam-analytics
```

### Log Management

```bash
# Configure log rotation
sudo cat > /etc/logrotate.d/iam-analytics << EOF
/opt/iam-analytics/iam_analytics.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 security security
    postrotate
        systemctl reload iam-analytics
    endscript
}
EOF
```

### Performance Monitoring

```bash
# Monitor system resources
htop
iotop
df -h

# Monitor detection performance
tail -f iam_analytics.log | grep "Detection completed"

# Generate performance reports
python main.py --mode report --lookback 168
```

## Alerting Configuration

### Webhook Integration

```yaml
alerts:
  destinations:
    - type: "webhook"
      url: "https://your-siem.com/api/alerts"
      format: "json"
```

### Slack Integration

```yaml
alerts:
  destinations:
    - type: "slack"
      webhook_url: "${SLACK_WEBHOOK_URL}"
      channel: "#security-alerts"
```

### Email Integration

```yaml
alerts:
  destinations:
    - type: "email"
      recipients:
        - "security-team@company.com"
        - "soc@company.com"
```

## Testing

### Unit Tests

```bash
# Run unit tests
cd tests/
python -m pytest test_detection_engine.py -v
python -m pytest test_ueba_baseline.py -v
```

### Integration Tests

```bash
# Test Panther integration
python test_panther_integration.py

# Test CrowdStrike integration
python test_crowdstrike_integration.py

# Test end-to-end detection
python test_e2e_detection.py
```

### Performance Tests

```bash
# Load testing
python performance_tests.py --events 10000 --duration 60
```

## Troubleshooting

### Common Issues

1. **API Authentication Failures**
```bash
# Test API connectivity
python -c "
import asyncio
from framework.adapters.platform_adapter import PantherAdapter
adapter = PantherAdapter({'api_url': 'your_url', 'api_token': 'your_token'})
print(asyncio.run(adapter.connect()))
"
```

2. **High Memory Usage**
```bash
# Monitor memory usage
ps aux | grep python
free -h

# Optimize baseline storage
python -c "
from ueba.models.behavior_baseline import BehaviorBaselineEngine
engine = BehaviorBaselineEngine()
# Implement baseline cleanup
"
```

3. **Detection Latency**
```bash
# Check detection timing
tail -f iam_analytics.log | grep "Detection cycle completed"

# Optimize query performance
# Review and tune detection parameters in config
```

### Debug Mode

```bash
# Enable debug logging
export LOG_LEVEL=DEBUG
python main.py --mode single --detection-type credential_stuffing
```

### Backup and Recovery

```bash
# Backup baselines
cp -r ueba/models/saved_baselines/ backup/$(date +%Y%m%d)/

# Backup configuration
cp config/production-config.yaml backup/$(date +%Y%m%d)/

# Backup detection history
cp detection_history_*.json backup/$(date +%Y%m%d)/
```

## Security Considerations

### API Key Management
- Store API keys in environment variables or secure key management
- Rotate API keys regularly
- Use principle of least privilege for API access

### Network Security
- Run on isolated network segment if possible
- Use TLS for all API communications
- Implement IP allowlisting for API access

### Data Privacy
- Ensure GDPR/privacy compliance for user behavior analytics
- Implement data retention policies
- Use anonymization where possible

### Access Control
- Implement RBAC for analytics access
- Audit access to detection results
- Secure log files with appropriate permissions

## Performance Tuning

### Detection Optimization
- Tune detection thresholds based on false positive rates
- Optimize time windows for different attack patterns
- Use statistical sampling for high-volume events

### Resource Optimization
- Scale detection frequency based on threat level
- Implement caching for UEBA baselines
- Use async processing for improved throughput

### Storage Optimization
- Implement data archiving policies
- Compress historical detection data
- Use database indexing for query performance

## Support and Maintenance

### Regular Tasks
- Weekly: Review false positive rates and tune thresholds
- Monthly: Update UEBA baselines and review model performance
- Quarterly: Review detection rules and update threat patterns

### Incident Response
- Document detection rule changes
- Maintain runbook for common scenarios
- Coordinate with SOC for alert handling

### Updates and Patches
- Test updates in development environment first
- Implement rollback procedures
- Document all configuration changes

---

**Version**: 1.0  
**Last Updated**: 2026-03-06  
**Next Review**: 2026-04-06