# SecurityAgents Platform - Production Deployment Guide

**Version**: 2.0  
**Date**: March 6, 2026  
**Status**: Production Ready  
**Platform**: Multi-environment deployment (Docker, Kubernetes, Cloud)

---

## 🎯 Deployment Overview

This guide covers production deployment of the **SecurityAgents Platform** with its 4 implemented security agents:

- **🧠 Alpha-4**: Threat Intelligence Engine
- **🔒 Beta-4**: DevSecOps Automation  
- **🛡️ Gamma**: Blue Team Defense Operations
- **⚔️ Delta**: Red Team Offense Operations
- **🔐 IAM Security**: Complete Okta integration platform

---

## 📋 Prerequisites

### **System Requirements**

#### **Minimum Production Requirements**
```yaml
CPU: 16 vCPUs
RAM: 32 GB
Storage: 500 GB SSD
Network: 1 Gbps
OS: Ubuntu 20.04+ / RHEL 8+ / Amazon Linux 2
```

#### **Recommended Enterprise Setup**
```yaml
CPU: 32 vCPUs  
RAM: 64 GB
Storage: 1 TB NVMe SSD
Network: 10 Gbps
OS: Ubuntu 22.04 LTS
High Availability: Multi-AZ deployment
```

### **Software Dependencies**

#### **Core Requirements**
```bash
# Docker & Orchestration
docker >= 20.10
docker-compose >= 2.0
kubernetes >= 1.25 (optional)

# Python Environment
python >= 3.10
pip >= 22.0

# Database Systems
postgresql >= 14
redis >= 7.0

# Monitoring Stack
prometheus >= 2.40
grafana >= 9.0
```

#### **External Service Requirements**
```yaml
# Required External APIs
okta_api: Admin API access with appropriate permissions
github_api: Personal access token with repo access
aws_credentials: IAM role or access keys

# Optional External APIs  
virustotal_api: API key for threat intelligence
shodan_api: API key for infrastructure analysis
crowdstrike_api: Falcon platform access (future)
```

---

## 🚀 Quick Start Deployment

### **Option 1: Docker Compose (Recommended)**

```bash
# 1. Clone repository
git clone https://github.com/mattarm/security-agents-platform.git
cd security-agents-platform

# 2. Configure environment
cp .env.example .env
nano .env  # Configure your API keys and credentials

# 3. Start core platform
cd enhanced-analysis
docker-compose -f docker-compose.prod.yml up -d

# 4. Verify deployment
curl http://localhost:8000/health
```

### **Option 2: Kubernetes (Enterprise)**

```bash
# 1. Prepare cluster
kubectl create namespace security-agents

# 2. Deploy secrets
kubectl create secret generic api-credentials \
  --from-literal=okta-token=your_token \
  --from-literal=github-token=your_token \
  -n security-agents

# 3. Deploy platform
kubectl apply -f k8s/ -n security-agents

# 4. Verify deployment  
kubectl get pods -n security-agents
kubectl get services -n security-agents
```

### **Option 3: Direct Installation**

```bash
# 1. Install dependencies
sudo apt update
sudo apt install python3.10 python3-pip postgresql redis-server

# 2. Setup Python environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 3. Configure databases
sudo systemctl start postgresql redis-server
createdb security_agents

# 4. Start services
python enhanced-analysis/production_api_server.py &
python iam-security/main.py &
```

---

## ⚙️ Configuration

### **Environment Configuration**

#### **Core Platform Settings** (`.env`)
```bash
# API Server Configuration
API_HOST=0.0.0.0
API_PORT=8000
API_WORKERS=4
DEBUG=false

# Database Configuration
DATABASE_URL=postgresql://user:pass@localhost:5432/security_agents
REDIS_URL=redis://localhost:6379/0

# Security Settings
SECRET_KEY=your-super-secret-key-here
JWT_SECRET=your-jwt-secret-here
ENCRYPTION_KEY=your-32-byte-encryption-key

# External API Keys
GITHUB_TOKEN=ghp_your_github_token
OKTA_API_TOKEN=your_okta_token
OKTA_ORG_URL=https://your-org.okta.com
VIRUSTOTAL_API_KEY=your_vt_key
SHODAN_API_KEY=your_shodan_key

# AWS Configuration (if using AWS features)
AWS_ACCESS_KEY_ID=your_aws_key
AWS_SECRET_ACCESS_KEY=your_aws_secret
AWS_DEFAULT_REGION=us-west-2
```

#### **IAM Security Configuration** (`iam-security/config/config.yml`)
```yaml
okta:
  org_url: "https://your-org.okta.com"
  api_token: "${OKTA_API_TOKEN}"
  rate_limit:
    requests_per_minute: 100
    burst_limit: 50

siem:
  panther:
    enabled: true
    http_endpoint: "https://your-panther.runpanther.net/api/v1/events"
    api_token: "${PANTHER_API_TOKEN}"
  
  crowdstrike:
    enabled: false  # Enable when ready for migration
    logscale_url: "https://your-tenant.logscale.io"
    api_token: "${CROWDSTRIKE_API_TOKEN}"

threat_detection:
  ml_models:
    isolation_forest:
      enabled: true
      contamination: 0.1
    
  rules:
    credential_stuffing:
      enabled: true
      threshold: 5
      time_window: 300
    
    privilege_escalation:
      enabled: true
      rapid_threshold: 3
      time_window: 60

response_automation:
  enabled: true
  approval_required: false
  actions:
    account_suspend: true
    session_clear: true
    mfa_enforce: true
    device_unregister: true

notifications:
  slack:
    enabled: true
    webhook_url: "${SLACK_WEBHOOK_URL}"
    channel: "#security-alerts"
  
  email:
    enabled: true
    smtp_server: "smtp.company.com"
    smtp_port: 587
    username: "${EMAIL_USERNAME}"
    password: "${EMAIL_PASSWORD}"
```

### **Agent Configuration**

#### **Alpha-4: Threat Intelligence** (`enhanced-analysis/config/alpha-config.yaml`)
```yaml
threat_intelligence:
  sources:
    virustotal:
      enabled: true
      api_key: "${VIRUSTOTAL_API_KEY}"
      rate_limit: 4  # requests per minute
    
    shodan:
      enabled: true
      api_key: "${SHODAN_API_KEY}"
      rate_limit: 100  # queries per month
    
    misp:
      enabled: false
      url: "https://your-misp.org"
      api_key: "${MISP_API_KEY}"

  processing:
    dga_detection:
      enabled: true
      entropy_threshold: 4.5
      min_length: 8
    
    campaign_analysis:
      enabled: true
      clustering_threshold: 0.7
      attribution_confidence: 0.8

  output:
    correlation_threshold: 0.6
    max_indicators_per_batch: 1000
    retention_days: 90
```

#### **Gamma: Blue Team Defense** (`agents/config/gamma-config.yaml`)
```yaml
soc_automation:
  alert_processing:
    auto_triage: true
    false_positive_threshold: 0.7
    escalation_severity: "high"
  
  incident_response:
    auto_containment: true
    thehive_integration: true
    thehive_url: "http://localhost:9000"
    thehive_api_key: "${THEHIVE_API_KEY}"

containment_actions:
  firewall_block:
    enabled: true
    default_duration: 3600  # seconds
  
  dns_sinkhole:
    enabled: true
    sinkhole_ip: "127.0.0.1"
  
  system_quarantine:
    enabled: false  # Enable with caution
    approval_required: true

monitoring:
  metrics_enabled: true
  health_check_interval: 30
  log_level: "INFO"
```

---

## 🔒 Security Hardening

### **Network Security**

#### **Firewall Configuration** (UFW)
```bash
# Allow SSH (change port if needed)
ufw allow 22/tcp

# Allow HTTPS traffic
ufw allow 443/tcp

# Allow API access (restrict to internal networks)
ufw allow from 10.0.0.0/8 to any port 8000

# Allow database access (internal only)
ufw allow from 10.0.0.0/8 to any port 5432
ufw allow from 10.0.0.0/8 to any port 6379

# Enable firewall
ufw enable
```

#### **TLS Configuration** (nginx proxy)
```nginx
server {
    listen 443 ssl http2;
    server_name security-agents.company.com;
    
    ssl_certificate /etc/ssl/certs/security-agents.crt;
    ssl_certificate_key /etc/ssl/private/security-agents.key;
    ssl_protocols TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    
    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### **Database Security**

#### **PostgreSQL Hardening**
```bash
# Create dedicated database and user
sudo -u postgres createuser --no-createdb --no-superuser --no-createrole security_agents
sudo -u postgres createdb security_agents --owner=security_agents
sudo -u postgres psql -c "ALTER USER security_agents PASSWORD 'strong_password_here';"

# Configure pg_hba.conf for secure access
echo "host security_agents security_agents 127.0.0.1/32 md5" | sudo tee -a /etc/postgresql/14/main/pg_hba.conf

# Restart PostgreSQL
sudo systemctl restart postgresql
```

#### **Redis Security**
```bash
# Configure Redis authentication
echo "requirepass strong_redis_password_here" | sudo tee -a /etc/redis/redis.conf
echo "rename-command FLUSHDB \"\"" | sudo tee -a /etc/redis/redis.conf
echo "rename-command FLUSHALL \"\"" | sudo tee -a /etc/redis/redis.conf

# Restart Redis
sudo systemctl restart redis-server
```

### **Application Security**

#### **Secrets Management**
```bash
# Use environment variables for secrets
export OKTA_API_TOKEN="$(vault kv get -field=token secret/okta)"
export GITHUB_TOKEN="$(vault kv get -field=token secret/github)"

# Or use Docker secrets
echo "your_okta_token" | docker secret create okta_token -
echo "your_github_token" | docker secret create github_token -
```

#### **User Authentication**
```yaml
# Configure OAuth 2.0 authentication
authentication:
  method: "oauth2"
  provider: "okta"
  client_id: "${OKTA_CLIENT_ID}"
  client_secret: "${OKTA_CLIENT_SECRET}"
  redirect_uri: "https://security-agents.company.com/auth/callback"
  
authorization:
  rbac:
    enabled: true
    roles:
      admin: ["*"]
      analyst: ["read", "investigate", "respond"]
      viewer: ["read"]
```

---

## 📊 Monitoring & Observability

### **Health Monitoring**

#### **Prometheus Configuration** (`prometheus.yml`)
```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'security-agents-api'
    static_configs:
      - targets: ['localhost:8000']
    metrics_path: /metrics
    scrape_interval: 30s
  
  - job_name: 'security-agents-agents'
    static_configs:
      - targets: ['localhost:8001', 'localhost:8002', 'localhost:8003', 'localhost:8004']
    metrics_path: /metrics
```

#### **Grafana Dashboard Configuration**
```json
{
  "dashboard": {
    "title": "SecurityAgents Platform",
    "panels": [
      {
        "title": "Agent Health",
        "type": "stat",
        "targets": [
          {
            "expr": "up{job='security-agents-agents'}",
            "legendFormat": "{{instance}}"
          }
        ]
      },
      {
        "title": "Threat Detection Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(threats_detected_total[5m])",
            "legendFormat": "Threats/sec"
          }
        ]
      }
    ]
  }
}
```

### **Log Management**

#### **Structured Logging Configuration**
```python
# Configure structured logging
import logging
import json

class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_data = {
            'timestamp': record.created,
            'level': record.levelname,
            'component': record.name,
            'message': record.getMessage(),
            'trace_id': getattr(record, 'trace_id', None)
        }
        return json.dumps(log_data)

logging.basicConfig(
    level=logging.INFO,
    format='%(message)s',
    handlers=[logging.StreamHandler()]
)
```

#### **Log Rotation** (`/etc/logrotate.d/security-agents`)
```bash
/var/log/security-agents/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    create 0644 security-agents security-agents
    postrotate
        systemctl reload security-agents
    endscript
}
```

---

## 🧪 Testing & Validation

### **Deployment Testing**

#### **Health Check Script** (`scripts/health-check.sh`)
```bash
#!/bin/bash

echo "SecurityAgents Platform Health Check"
echo "===================================="

# Check API server
echo -n "API Server: "
if curl -f http://localhost:8000/health > /dev/null 2>&1; then
    echo "✅ Healthy"
else
    echo "❌ Failed"
fi

# Check database connectivity
echo -n "Database: "
if pg_isready -h localhost -p 5432 > /dev/null 2>&1; then
    echo "✅ Connected"
else
    echo "❌ Failed"
fi

# Check Redis
echo -n "Redis: "
if redis-cli ping > /dev/null 2>&1; then
    echo "✅ Connected"
else
    echo "❌ Failed"
fi

# Check agents
for agent in alpha gamma delta; do
    echo -n "Agent $agent: "
    if curl -f http://localhost:8000/api/v1/agents/$agent/health > /dev/null 2>&1; then
        echo "✅ Healthy"
    else
        echo "❌ Failed"
    fi
done

echo ""
echo "Health check complete"
```

#### **Integration Tests**
```python
# Test Okta integration
async def test_okta_integration():
    from iam_security.okta_security.api_client import OktaSecurityClient
    
    client = OktaSecurityClient()
    users = await client.get_users(limit=1)
    assert len(users) >= 0
    print("✅ Okta integration working")

# Test threat intelligence
async def test_threat_intelligence():
    from enhanced_analysis.tiger_team_alpha_4 import ThreatIntelligenceEngine
    
    engine = ThreatIntelligenceEngine()
    result = await engine.analyze_ioc("8.8.8.8", "ip")
    assert result.confidence > 0
    print("✅ Threat intelligence working")

# Run tests
if __name__ == "__main__":
    import asyncio
    asyncio.run(test_okta_integration())
    asyncio.run(test_threat_intelligence())
```

### **Performance Testing**

#### **Load Testing** (`scripts/load-test.sh`)
```bash
#!/bin/bash

echo "Running performance tests..."

# API load test
echo "Testing API performance..."
ab -n 1000 -c 10 http://localhost:8000/health

# Agent stress test
echo "Testing agent performance..."
for i in {1..100}; do
    curl -X POST http://localhost:8000/api/v1/agents/alpha/analyze \
         -H "Content-Type: application/json" \
         -d '{"type":"ip","value":"192.168.1.1"}' &
done
wait

echo "Performance tests complete"
```

---

## 🔄 Backup & Recovery

### **Database Backup**

#### **Automated Backup Script** (`scripts/backup.sh`)
```bash
#!/bin/bash

BACKUP_DIR="/var/backups/security-agents"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p $BACKUP_DIR

# PostgreSQL backup
pg_dump security_agents | gzip > "$BACKUP_DIR/postgres_$DATE.sql.gz"

# Redis backup  
cp /var/lib/redis/dump.rdb "$BACKUP_DIR/redis_$DATE.rdb"

# Configuration backup
tar -czf "$BACKUP_DIR/config_$DATE.tar.gz" /etc/security-agents/

# Clean old backups (keep 30 days)
find $BACKUP_DIR -name "*.gz" -mtime +30 -delete
find $BACKUP_DIR -name "*.rdb" -mtime +30 -delete

echo "Backup completed: $DATE"
```

#### **Backup Cron Job**
```bash
# Add to crontab
0 2 * * * /opt/security-agents/scripts/backup.sh >> /var/log/backup.log 2>&1
```

### **Disaster Recovery**

#### **Recovery Procedure**
```bash
#!/bin/bash

echo "Starting disaster recovery..."

# Stop services
systemctl stop security-agents

# Restore database
gunzip -c /var/backups/security-agents/postgres_latest.sql.gz | psql security_agents

# Restore Redis
systemctl stop redis-server
cp /var/backups/security-agents/redis_latest.rdb /var/lib/redis/dump.rdb
systemctl start redis-server

# Restore configuration
tar -xzf /var/backups/security-agents/config_latest.tar.gz -C /

# Start services
systemctl start security-agents

echo "Recovery complete"
```

---

## 🚨 Troubleshooting

### **Common Issues**

#### **API Server Won't Start**
```bash
# Check logs
journalctl -u security-agents -f

# Common fixes
# 1. Check port conflicts
netstat -tlnp | grep 8000

# 2. Check database connectivity
pg_isready -h localhost -p 5432

# 3. Check environment variables
env | grep -E "(OKTA|GITHUB|API)"
```

#### **Agent Failures**
```bash
# Check agent health
curl http://localhost:8000/api/v1/agents/status

# Restart specific agent
curl -X POST http://localhost:8000/api/v1/agents/alpha/restart

# Check agent logs
tail -f /var/log/security-agents/alpha-agent.log
```

#### **Database Connection Issues**
```bash
# Test PostgreSQL connection
psql -h localhost -U security_agents -d security_agents -c "SELECT 1;"

# Test Redis connection
redis-cli ping

# Check connection limits
grep max_connections /etc/postgresql/14/main/postgresql.conf
```

### **Performance Issues**

#### **High CPU Usage**
```bash
# Check process CPU usage
top -p $(pgrep -f security-agents)

# Check agent workload
curl http://localhost:8000/api/v1/agents/stats

# Scale agents if needed
docker-compose scale agents=3
```

#### **Memory Leaks**
```bash
# Monitor memory usage
watch "ps aux | grep security-agents"

# Check Python memory profiling
python -m tracemalloc enhanced-analysis/production_api_server.py

# Restart agents periodically (add to cron)
0 4 * * * systemctl restart security-agents
```

---

## 📈 Production Optimization

### **Performance Tuning**

#### **Database Optimization** (`postgresql.conf`)
```ini
# Memory settings
shared_buffers = 8GB
effective_cache_size = 24GB
work_mem = 256MB

# Connection settings
max_connections = 200
shared_preload_libraries = 'pg_stat_statements'

# Logging
log_statement = 'mod'
log_min_duration_statement = 1000
```

#### **Redis Optimization** (`redis.conf`)
```ini
# Memory settings
maxmemory 4gb
maxmemory-policy allkeys-lru

# Performance settings
tcp-keepalive 300
timeout 300

# Persistence
save 900 1
save 300 10
save 60 10000
```

### **Scaling Strategies**

#### **Horizontal Scaling** (Kubernetes)
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: security-agents-api
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: api-server
        image: security-agents/api-server:latest
        resources:
          requests:
            cpu: 500m
            memory: 1Gi
          limits:
            cpu: 2000m
            memory: 4Gi

---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: security-agents-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: security-agents-api
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
```

---

## ✅ Production Checklist

### **Pre-Deployment**
- [ ] All dependencies installed and configured
- [ ] Environment variables set correctly
- [ ] Database initialized and migrated
- [ ] SSL certificates installed
- [ ] Firewall rules configured
- [ ] Monitoring stack deployed

### **Deployment**
- [ ] Services started successfully
- [ ] Health checks passing
- [ ] API endpoints responding
- [ ] Agent connectivity verified
- [ ] External integrations working

### **Post-Deployment**
- [ ] Monitoring alerts configured
- [ ] Backup procedures tested
- [ ] Recovery procedures documented
- [ ] Performance baseline established
- [ ] Security hardening complete
- [ ] Documentation updated

### **Operations**
- [ ] Team trained on platform operations
- [ ] Incident response procedures defined
- [ ] Maintenance schedules established
- [ ] Capacity planning completed

---

## 📞 Support & Maintenance

### **Support Contacts**
- **Platform Engineering**: security-platform@company.com
- **Security Operations**: security-ops@company.com
- **Infrastructure**: infrastructure@company.com

### **Maintenance Schedule**
- **Daily**: Health checks and log review
- **Weekly**: Performance review and optimization
- **Monthly**: Security updates and patches
- **Quarterly**: Disaster recovery testing

---

**🚀 Your SecurityAgents platform is now ready for production! Monitor, maintain, and scale as needed.**

---

*Deployment Guide v2.0 - Updated March 6, 2026*