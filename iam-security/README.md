# Okta Identity Security Integration

A comprehensive identity security monitoring and response platform that integrates Okta with advanced threat detection, automated response actions, and multi-SIEM log forwarding.

## Features

### 🔐 **Identity Security Monitoring**
- Real-time Okta system log collection and analysis
- Advanced event correlation and session reconstruction
- Machine learning-based anomaly detection
- Configurable rule-based threat detection
- Behavioral analytics and user profiling

### ⚡ **Automated Threat Response**
- Immediate response to security incidents
- User account suspension and session termination
- MFA enforcement and password reset
- IP address blocking and access control
- Approval workflows with audit trails

### 📊 **Multi-SIEM Integration**
- **Panther SIEM**: HTTP and S3 delivery with compression
- **CrowdStrike Falcon**: LogScale integration with structured data
- Universal event formatting (JSON, CEF, LEEF, XML)
- Batch processing and retry logic
- Dual compatibility for seamless transitions

### 🚨 **Alerting & Notifications**
- Multi-channel notifications (Email, Slack, Teams, Webhooks)
- Severity-based routing and rate limiting
- Template-based messaging with rich formatting
- Integration with PagerDuty and other incident systems

### 📈 **Monitoring & Observability**
- Prometheus metrics and health checks
- Comprehensive statistics and dashboards
- Performance monitoring and alerting
- Audit logging and compliance reporting

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/company/okta-security-integration.git
cd okta-security-integration

# Install dependencies
pip install -r requirements.txt

# Or install as package
pip install -e .
```

### Configuration

1. Copy the example configuration:
```bash
cp config/config.example.yml config/config.yml
```

2. Configure your Okta credentials:
```yaml
okta:
  org_url: "https://your-org.okta.com"
  api_token: "${OKTA_API_TOKEN}"
```

3. Set environment variables:
```bash
export OKTA_API_TOKEN="your_okta_api_token"
export PANTHER_HTTP_ENDPOINT="https://api.runpanther.net/v1/logs"
export PANTHER_API_TOKEN="your_panther_token"
```

### Running the Platform

```bash
# Start the platform
python main.py run --config config/config.yml

# Test connectivity
python main.py test-connectivity

# Collect events for analysis
python main.py collect-events --hours 24
```

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

### Core Components

#### **Okta API Integration** (`okta_security/`)
- **OktaSecurityClient**: Enhanced API wrapper with rate limiting and circuit breakers
- **AuthManager**: OAuth 2.0 and API token management with automatic rotation
- **EventCollector**: Real-time event streaming with enrichment and deduplication

#### **Analytics Engine** (`analytics/`)
- **CorrelationEngine**: Event correlation and attack pattern detection
- **ThreatDetector**: ML-based anomaly detection and behavioral analysis
- **RulesEngine**: Configurable rule-based threat detection with time windows

#### **Response System** (`response/`)
- **ActionExecutor**: Orchestrated response actions with approval workflows
- **OktaActions**: Direct Okta API response actions (suspend, MFA, etc.)
- **NotificationManager**: Multi-channel alerting and incident notifications

#### **SIEM Integration** (`siem/`)
- **UniversalFormatter**: Multi-format event transformation (JSON, CEF, LEEF)
- **PantherForwarder**: Panther SIEM integration with HTTP/S3 delivery
- **CrowdStrikeForwarder**: CrowdStrike Falcon LogScale integration

## Configuration

### Okta Settings

```yaml
okta:
  org_url: "https://your-org.okta.com"
  
  # Option 1: API Token
  api_token: "${OKTA_API_TOKEN}"
  
  # Option 2: OAuth (recommended for production)
  oauth:
    client_id: "${OKTA_CLIENT_ID}"
    private_key_path: "/path/to/private_key.pem"
    scopes:
      - "okta.logs.read"
      - "okta.users.manage"
      - "okta.groups.read"
```

### Threat Detection

```yaml
analytics:
  correlation:
    window_size: 3600  # 1 hour correlation window
    
  threat_detection:
    enable_ml_detection: true
    enable_behavioral_analysis: true
    model_path: "./models/"
    
  rules:
    config_path: "./config/rules.json"
    auto_reload: true
```

### Response Actions

```yaml
response:
  enabled: true
  require_approval: true
  auto_approve_low_severity: true
  
  rate_limits:
    suspend_user:
      max_per_hour: 10
    block_ip:
      max_per_hour: 50
```

### SIEM Integration

```yaml
siem:
  # Panther Configuration
  panther:
    enabled: true
    delivery_method: "both"  # http, s3, both
    http_endpoint: "${PANTHER_HTTP_ENDPOINT}"
    auth_token: "${PANTHER_API_TOKEN}"
    s3_bucket: "panther-logs-bucket"
    batch_size: 1000
    compression: true
  
  # CrowdStrike Configuration  
  crowdstrike:
    enabled: true
    logscale_url: "https://cloud.humio.com"
    repository: "okta-logs"
    ingest_token: "${CROWDSTRIKE_INGEST_TOKEN}"
    batch_size: 1000
```

## Threat Detection Rules

The platform includes built-in detection rules for common identity threats:

### **Authentication Threats**
- Multiple failed login attempts (brute force)
- Login from unknown countries/locations
- Impossible travel detection
- Concurrent sessions from different locations
- Authentication bypass attempts

### **Privilege Escalation**
- Rapid privilege grants and role changes
- Administrative actions after hours
- Unusual application access patterns
- Group membership changes

### **Account Abuse**
- Mass user enumeration
- Credential stuffing attacks
- Account takeover indicators
- Suspicious user agent patterns

### **Policy Violations**
- Password policy bypass attempts
- MFA factor manipulation
- Application policy violations

## Response Actions

### **User Management**
- **suspend_user**: Immediately suspend user account
- **clear_user_sessions**: Terminate all active sessions
- **reset_user_mfa**: Reset MFA factors requiring re-enrollment
- **expire_user_password**: Force password change

### **Access Control**
- **enforce_mfa**: Add user to MFA-required group
- **remove_user_from_group**: Remove privileged access
- **disable_application**: Deactivate application access

### **Network Security**
- **block_ip_address**: Block source IP (via integration)
- **geographic_restrictions**: Apply location-based controls

All actions support:
- ✅ **Approval workflows** with configurable thresholds
- ✅ **Audit logging** with complete action history
- ✅ **Rollback capabilities** for reversible actions
- ✅ **Rate limiting** to prevent operational impact

## SIEM Integration Details

### Panther SIEM

**HTTP Delivery:**
```python
# Optimized JSON format with Panther-specific fields
{
  "p_event_id": "uuid",
  "p_event_time": "2024-01-15T10:30:00Z", 
  "p_log_type": "user.authentication.auth_via_mfa",
  "p_source_ip": "192.168.1.100",
  "p_source_country": "US",
  "okta_actor_id": "user123",
  "okta_auth_provider": "OKTA"
}
```

**S3 Delivery:**
- Automatic partitioning by date: `year=2024/month=01/day=15/`
- Gzip compression for cost optimization
- Metadata tags for processing pipeline

### CrowdStrike Falcon LogScale

**Structured Data Format:**
```python
{
  "@id": "event-uuid",
  "@timestamp": "2024-01-15T10:30:00Z",
  "@type": "user.authentication.auth_via_mfa",
  "user.id": "user123",
  "user.name": "john.doe@company.com",
  "source.ip": "192.168.1.100",
  "source.geo.country_iso_code": "US",
  "okta.auth.provider": "OKTA",
  "event.outcome": "SUCCESS"
}
```

**LogScale Features:**
- Custom parser creation for Okta events
- Automatic field extraction and indexing
- Search alert configuration
- Repository-specific data organization

## Monitoring & Health Checks

### Health Check Endpoint

```bash
curl http://localhost:8080/health
```

Response:
```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "status": "healthy",
  "components": {
    "okta": {
      "okta_connectivity": true,
      "api_permissions": true
    },
    "panther": {
      "http_connectivity": true,
      "overall_status": true
    },
    "event_collector": {
      "streaming_active": true,
      "buffer_health": true
    }
  }
}
```

### Prometheus Metrics

```bash
curl http://localhost:8080/metrics
```

Key metrics:
- `okta_events_processed_total`: Total events processed
- `okta_threats_detected_total`: Threats detected by type
- `okta_actions_executed_total`: Response actions executed
- `okta_active_sessions`: Currently tracked user sessions
- `okta_siem_events_forwarded_total`: Events forwarded by destination

### Statistics Endpoint

```bash
curl http://localhost:8080/statistics
```

Provides detailed operational statistics for all components.

## Development

### Setup Development Environment

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Code formatting
black okta_security/ analytics/ response/ siem/
isort okta_security/ analytics/ response/ siem/

# Type checking
mypy okta_security/ analytics/ response/ siem/

# Linting
flake8 okta_security/ analytics/ response/ siem/
```

### Running Tests

```bash
# Unit tests
pytest tests/unit/ -v

# Integration tests (requires Okta credentials)
pytest tests/integration/ -v

# Coverage report
pytest --cov=okta_security --cov=analytics --cov=response --cov=siem tests/
```

### Adding Custom Rules

Create a custom rule in `config/rules.json`:

```json
{
  "rules": [
    {
      "rule_id": "CUSTOM-001",
      "name": "VIP User Monitoring",
      "description": "Monitor authentication for VIP users",
      "severity": "HIGH",
      "conditions": [
        {
          "field": "eventType",
          "condition_type": "equals",
          "value": "user.authentication.auth_via_mfa"
        },
        {
          "field": "actor.displayName",
          "condition_type": "in_list",
          "value": ["ceo@company.com", "cto@company.com"]
        }
      ],
      "enabled": true,
      "tags": ["vip", "authentication"],
      "auto_response": false,
      "response_actions": ["send_notification"]
    }
  ]
}
```

### Custom SIEM Integration

Add support for new SIEM platforms:

1. **Create Schema** in `siem/universal_formatter.py`:
```python
custom_schema = SchemaDefinition(
    name="custom_siem",
    version="1.0",
    format_type="json",
    field_mappings=[...],
    required_fields=[...]
)
```

2. **Implement Forwarder** in `siem/custom_forwarder.py`:
```python
class CustomForwarder:
    def forward_event(self, event: Dict) -> bool:
        formatted = self.formatter.format_event(event, "custom_siem")
        return self._send_to_siem(formatted)
```

## Security Considerations

### **Credential Management**
- Use environment variables for sensitive configuration
- Implement credential rotation for long-running deployments
- Use OAuth 2.0 over API tokens when possible
- Store private keys securely with proper file permissions

### **Network Security**
- Deploy behind firewall with restricted access
- Use TLS for all external communications
- Implement proper certificate validation
- Consider VPN or private networking for SIEM connections

### **Data Privacy**
- Events may contain PII - ensure proper handling
- Implement data retention policies
- Use field masking for sensitive data in logs
- Comply with relevant privacy regulations (GDPR, CCPA)

### **Access Control**
- Limit Okta API permissions to minimum required
- Use dedicated service accounts
- Implement proper audit logging
- Regular access reviews and permission audits

## Deployment

### **Docker Deployment**

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 8080

CMD ["python", "main.py", "run", "--config", "config/config.yml"]
```

### **Kubernetes Deployment**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: okta-security
spec:
  replicas: 1
  selector:
    matchLabels:
      app: okta-security
  template:
    metadata:
      labels:
        app: okta-security
    spec:
      containers:
      - name: okta-security
        image: okta-security:latest
        ports:
        - containerPort: 8080
        env:
        - name: OKTA_API_TOKEN
          valueFrom:
            secretKeyRef:
              name: okta-secrets
              key: api-token
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
```

### **Production Checklist**

- ✅ **Environment Variables**: All sensitive config in env vars
- ✅ **Monitoring**: Prometheus + Grafana dashboards configured
- ✅ **Alerting**: PagerDuty/notification channels tested
- ✅ **Backup**: Configuration and state backup strategy
- ✅ **High Availability**: Consider multiple replicas for critical deployments
- ✅ **Log Aggregation**: Centralized logging for troubleshooting
- ✅ **Security**: Network policies and access controls in place

## Troubleshooting

### **Common Issues**

#### Okta API Rate Limits
```
ERROR: Rate limit exceeded
```
**Solution**: Increase `rate_limit_buffer` or implement exponential backoff

#### SIEM Connection Failures
```
ERROR: Failed to connect to SIEM endpoint
```
**Solution**: Check network connectivity, credentials, and endpoint URLs

#### High Memory Usage
```
WARNING: Buffer size approaching limit
```
**Solution**: Increase `buffer_size` or reduce `poll_interval`

### **Debug Mode**

Enable detailed logging:
```bash
python main.py run --debug
```

### **Health Checks**

Monitor component health:
```bash
# Overall health
curl http://localhost:8080/health

# Detailed statistics
curl http://localhost:8080/statistics

# Test connectivity
python main.py test-connectivity
```

## Support

- **Documentation**: [docs.company.com/okta-security](https://docs.company.com/okta-security)
- **Issues**: [GitHub Issues](https://github.com/company/okta-security-integration/issues)
- **Security Contact**: security@company.com
- **Support**: support@company.com

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

---

**Built with ❤️ by the Security Team**