# Deployment Guide

This guide covers deploying the Identity Threat Response System in various environments.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quick Start](#quick-start)
3. [Configuration](#configuration)
4. [Deployment Options](#deployment-options)
5. [Security Considerations](#security-considerations)
6. [Monitoring](#monitoring)
7. [Troubleshooting](#troubleshooting)

## Prerequisites

### System Requirements

- **Python**: 3.11 or higher
- **Memory**: 2GB RAM minimum, 4GB recommended
- **Disk**: 10GB free space minimum
- **OS**: Linux (Ubuntu 20.04+, RHEL 8+, CentOS 8+)

### External Dependencies

- **Okta Admin API**: Valid API token with sufficient privileges
- **SIEM Platform**: Panther or CrowdStrike (or both)
- **TheHive**: For incident management (optional but recommended)
- **Email Server**: SMTP access for notifications

### Network Requirements

- **Outbound HTTPS (443)**: To Okta, SIEM platforms, TheHive
- **Inbound HTTP/HTTPS**: For webhook endpoints
- **Internal Network**: Access to notification systems (Slack, email)

## Quick Start

### 1. Clone and Setup

```bash
# Clone the repository
cd ~/security-assessment/iam-security/response-automation

# Run setup script
chmod +x scripts/setup.sh
./scripts/setup.sh --with-system-deps
```

### 2. Configure

```bash
# Edit main configuration
nano config/config.yaml

# Edit environment variables
nano .env
```

### 3. Run

```bash
# Start in development mode
./scripts/run.sh --development

# Or start in production mode
./scripts/run.sh --production
```

### 4. Test

```bash
# Health check
curl http://localhost:8000/health

# Manual threat submission (for testing)
curl -X POST http://localhost:8000/manual/threat \
  -H "Content-Type: application/json" \
  -d '{
    "threat_type": "SUSPICIOUS_LOGIN",
    "level": "MEDIUM",
    "user_id": "test.user@company.com",
    "user_email": "test.user@company.com",
    "ip_address": "192.168.1.100"
  }'
```

## Configuration

### Core Configuration (config/config.yaml)

The main configuration file controls all system behavior. Key sections:

#### Okta Configuration
```yaml
okta:
  domain: "your-company.okta.com"
  api_token: "${OKTA_API_TOKEN}"
  admin_groups:
    - "00g1234567890abcdef"  # Update with actual group IDs
  rate_limits:
    requests_per_minute: 100
    concurrent_requests: 10
```

#### SIEM Integration
```yaml
siem:
  panther:
    enabled: true
    webhook_url: "https://your-panther.com/webhooks"
    api_key: "${PANTHER_API_KEY}"
    alert_types:
      - "SUSPICIOUS_LOGIN"
      - "PRIVILEGE_ESCALATION"
      - "ACCOUNT_COMPROMISE"
```

#### Response Actions
```yaml
response_actions:
  account_lockout:
    enabled: true
    duration_hours: 24
    notify_user: true
    require_approval: false
  
  mfa_step_up:
    enabled: true
    duration_hours: 168
    policy_id: "00p1234567890abcdef"  # Update with actual policy ID
```

#### Notifications
```yaml
notifications:
  soc:
    slack:
      webhook_url: "${SOC_SLACK_WEBHOOK}"
      channel: "#security-alerts"
    email:
      smtp_server: "smtp.company.com"
      from_address: "security@company.com"
      to_addresses:
        - "soc-team@company.com"
```

### Environment Variables (.env)

```bash
# Okta
OKTA_API_TOKEN=00abcd1234567890abcdef1234567890abcdef12

# SIEM
PANTHER_API_KEY=panther_api_key_here
CROWDSTRIKE_CLIENT_ID=crowdstrike_client_id
CROWDSTRIKE_CLIENT_SECRET=crowdstrike_client_secret

# TheHive
THEHIVE_API_KEY=thehive_api_key_here

# Notifications
SOC_SLACK_WEBHOOK=https://hooks.slack.com/services/...
```

## Deployment Options

### Option 1: Direct Python Deployment

Best for development and small deployments.

```bash
# Setup and run
./scripts/setup.sh
./scripts/run.sh --production
```

**Pros**: Simple, direct control
**Cons**: Single point of failure, manual scaling

### Option 2: Docker Deployment

Recommended for production.

```bash
# Build and run
docker-compose up -d

# With monitoring
docker-compose --profile with-monitoring up -d

# With reverse proxy
docker-compose --profile with-proxy up -d
```

**Pros**: Isolated, scalable, consistent
**Cons**: Requires Docker knowledge

### Option 3: Systemd Service

For running as a system service.

```bash
# Install service
sudo ./scripts/install-service.sh

# Manage service
sudo systemctl start identity-response
sudo systemctl enable identity-response
sudo systemctl status identity-response
```

**Pros**: Automatic startup, logging integration
**Cons**: Tied to specific system

### Option 4: Kubernetes Deployment

For large-scale deployments.

```bash
# Apply Kubernetes manifests
kubectl apply -f k8s/
```

**Pros**: Highly scalable, fault-tolerant
**Cons**: Complex setup, requires K8s expertise

## Security Considerations

### API Security

1. **Authentication**: All webhook endpoints should use authentication
2. **TLS**: Always use HTTPS in production
3. **Rate Limiting**: Implement rate limiting for webhook endpoints
4. **IP Whitelisting**: Restrict webhook access to known SIEM IPs

```yaml
# Example nginx configuration
location /webhooks/ {
    allow 10.0.0.0/8;     # Internal network
    allow 192.168.0.0/16; # Private network
    deny all;             # Deny everything else
    
    proxy_pass http://identity-response:8000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}
```

### Secrets Management

1. **Environment Variables**: Never commit secrets to git
2. **Vault Integration**: Consider HashiCorp Vault for production
3. **Encryption**: Audit logs are encrypted at rest
4. **Key Rotation**: Regularly rotate API keys

### Network Security

1. **Firewall Rules**: Restrict access to necessary ports only
2. **VPN**: Consider VPN for administrative access
3. **Monitoring**: Log all network connections
4. **Segmentation**: Isolate from general network

### Audit and Compliance

1. **Comprehensive Logging**: All actions are logged
2. **Immutable Logs**: Logs cannot be modified
3. **Retention**: 7-year retention for compliance
4. **Access Control**: Strict access to audit logs

## Monitoring

### Health Checks

```bash
# Application health
curl http://localhost:8000/health

# Component status
curl http://localhost:8000/metrics
```

### Prometheus Metrics

The system exposes Prometheus metrics at `/metrics`:

- `identity_threats_total`: Total threats processed
- `response_actions_total`: Total response actions executed
- `okta_api_requests_total`: Okta API request count
- `circuit_breaker_state`: Circuit breaker states

### Log Monitoring

Monitor these log files:

- `logs/identity_response.log`: Application logs
- `logs/audit.log`: Encrypted audit logs
- `logs/access.log`: HTTP access logs

### Alerting

Setup alerts for:

- High failure rates (>5% in 5 minutes)
- Circuit breaker open states
- Critical threat events
- System health degradation

Example Prometheus alert rules:

```yaml
groups:
- name: identity_response
  rules:
  - alert: HighFailureRate
    expr: rate(response_actions_total{status="failed"}[5m]) > 0.05
    for: 2m
    labels:
      severity: warning
    annotations:
      summary: "High failure rate in identity response system"
  
  - alert: CircuitBreakerOpen
    expr: circuit_breaker_state == 1
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "Circuit breaker is open"
```

## Troubleshooting

### Common Issues

#### 1. Configuration Errors

```bash
# Validate configuration
python3 -c "
import yaml
with open('config/config.yaml', 'r') as f:
    config = yaml.safe_load(f)
print('Configuration is valid')
"

# Check required fields
grep -r "CHANGE_ME" config/
```

#### 2. API Connection Issues

```bash
# Test Okta connectivity
curl -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
     https://your-domain.okta.com/api/v1/users/me

# Test webhook endpoints
curl -X POST http://localhost:8000/webhooks/panther \
     -H "Content-Type: application/json" \
     -d '{"test": true}'
```

#### 3. Permission Issues

```bash
# Check file permissions
ls -la config/
ls -la logs/

# Fix permissions
chmod 750 config logs
chmod 600 .env
```

#### 4. Memory Issues

```bash
# Monitor memory usage
ps aux | grep python
top -p $(pgrep -f identity-response)

# Increase worker memory limit
export WORKER_MEMORY_LIMIT=512M
```

### Debug Mode

Enable debug logging:

```bash
./scripts/run.sh --log-level debug
```

### Health Checks

```bash
# Full system check
curl -s http://localhost:8000/health | jq '.'

# Component-specific checks
curl -s http://localhost:8000/health | jq '.components'
```

### Log Analysis

```bash
# Recent errors
tail -f logs/identity_response.log | grep ERROR

# Audit trail
python3 scripts/audit_search.py --since "1 hour ago"

# Performance metrics
grep "response_time" logs/identity_response.log | tail -20
```

## Production Checklist

Before deploying to production:

### Security
- [ ] All default passwords changed
- [ ] API keys properly secured
- [ ] TLS certificates configured
- [ ] Firewall rules implemented
- [ ] Audit logging enabled

### Configuration
- [ ] Production environment variables set
- [ ] Notification channels tested
- [ ] Response actions tested in staging
- [ ] Rate limits configured appropriately
- [ ] Emergency contacts defined

### Infrastructure
- [ ] High availability configured
- [ ] Backup and recovery tested
- [ ] Monitoring and alerting setup
- [ ] Load balancing configured
- [ ] Auto-scaling policies defined

### Operations
- [ ] Runbooks created
- [ ] Staff trained on system
- [ ] Incident response procedures defined
- [ ] Maintenance procedures documented
- [ ] Rollback procedures tested

## Support

For support and questions:

1. Check the troubleshooting section above
2. Review application logs for error details
3. Verify configuration against examples
4. Test individual components in isolation

## Updates

To update the system:

```bash
# Backup current configuration
cp -r config config.backup

# Pull latest changes
git pull origin main

# Update dependencies
source venv/bin/activate
pip install -r requirements.txt

# Restart service
sudo systemctl restart identity-response
```