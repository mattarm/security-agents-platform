# SecurityAgents Platform - Production Deployment Guide

**Version**: 2.0  
**Last Updated**: March 6, 2026  
**Deployment Type**: Docker Compose + Container Orchestration

---

## Overview

This guide covers the complete deployment of the SecurityAgents Platform in production environments. The platform consists of multiple services working together to provide comprehensive security intelligence analysis.

### Architecture Components

- **API Server**: FastAPI-based REST API for external integrations
- **Orchestrator**: Central coordination service for multi-agent tasks
- **Workers**: Background processing agents (Alpha-4 Threat Intel, Beta-4 DevSecOps)
- **Database**: PostgreSQL with high availability configuration
- **Cache/Queue**: Redis for caching and message queuing
- **Monitoring**: Prometheus, Grafana, and Loki for observability
- **Load Balancer**: Traefik with automatic SSL/TLS

---

## Prerequisites

### System Requirements

**Minimum Production Requirements:**
- **CPU**: 8 cores (16 threads)
- **RAM**: 16GB minimum, 32GB recommended
- **Storage**: 500GB SSD minimum, 1TB recommended
- **Network**: 1Gbps connection
- **OS**: Ubuntu 20.04+, CentOS 8+, or RHEL 8+

**High Availability Setup:**
- **Nodes**: 3+ servers for redundancy
- **Load Balancer**: External load balancer or Traefik cluster
- **Database**: PostgreSQL cluster with replication
- **Storage**: Shared storage or distributed filesystem

### Software Dependencies

```bash
# Install Docker and Docker Compose
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Install Docker Compose v2
sudo curl -L "https://github.com/docker/compose/releases/download/v2.23.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Verify installation
docker --version
docker-compose --version
```

---

## Environment Setup

### 1. Create Environment Configuration

```bash
# Create production environment file
cat > .env.production << EOF
# Environment
ENVIRONMENT=production
DOMAIN=yourdomain.com

# Database
POSTGRES_DB=security_agents
POSTGRES_USER=secagents_user
POSTGRES_PASSWORD=$(openssl rand -base64 32)

# Redis
REDIS_PASSWORD=$(openssl rand -base64 32)

# Security
JWT_SECRET=$(openssl rand -base64 64)
ENCRYPTION_KEY=$(openssl rand -base64 32)

# External API Keys
VIRUSTOTAL_API_KEY=your_virustotal_key
SHODAN_API_KEY=your_shodan_key
GITHUB_TOKEN=your_github_token
AWS_ACCESS_KEY_ID=your_aws_key
AWS_SECRET_ACCESS_KEY=your_aws_secret

# SSL/TLS
ACME_EMAIL=admin@yourdomain.com

# Authentication
TRAEFIK_AUTH=$(echo -n 'admin:password' | openssl passwd -apr1 -stdin)
GRAFANA_ADMIN_PASSWORD=$(openssl rand -base64 16)
EOF

# Secure the environment file
chmod 600 .env.production
```

### 2. Create Directory Structure

```bash
# Create required directories
mkdir -p {config,logs,scripts,backups,ssl}
mkdir -p config/{grafana,prometheus,loki,nginx}
mkdir -p logs/{api,orchestrator,workers}

# Set proper permissions
chmod 755 config logs scripts backups
chmod 700 ssl
```

### 3. Configure External Network

```bash
# Create external network for Traefik
docker network create traefik
```

---

## Configuration Files

### 1. PostgreSQL Configuration

```bash
# Create PostgreSQL configuration
cat > config/postgresql.conf << EOF
# PostgreSQL Production Configuration
max_connections = 200
shared_buffers = 512MB
effective_cache_size = 2GB
maintenance_work_mem = 128MB
checkpoint_completion_target = 0.9
wal_buffers = 16MB
default_statistics_target = 100
random_page_cost = 1.1
effective_io_concurrency = 200
work_mem = 4MB
min_wal_size = 1GB
max_wal_size = 4GB

# Security
ssl = on
ssl_cert_file = '/var/lib/postgresql/server.crt'
ssl_key_file = '/var/lib/postgresql/server.key'
ssl_ca_file = '/var/lib/postgresql/root.crt'

# Logging
log_destination = 'stderr'
logging_collector = on
log_directory = 'log'
log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'
log_min_duration_statement = 1000
log_connections = on
log_disconnections = on
log_lock_waits = on
log_temp_files = 0
EOF
```

### 2. Prometheus Configuration

```bash
# Create Prometheus configuration
cat > config/prometheus.prod.yml << EOF
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "rules/*.yml"

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'security-agents-api'
    static_configs:
      - targets: ['api:8080']
    metrics_path: '/metrics'
    scrape_interval: 30s

  - job_name: 'traefik'
    static_configs:
      - targets: ['traefik:8080']

  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres:5432']

  - job_name: 'redis'
    static_configs:
      - targets: ['redis:6379']

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093
EOF
```

### 3. Database Initialization

```bash
# Create database initialization script
cat > scripts/init-db.sql << EOF
-- SecurityAgents Platform Database Initialization

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";

-- Create schemas
CREATE SCHEMA IF NOT EXISTS security_agents;
CREATE SCHEMA IF NOT EXISTS intelligence;
CREATE SCHEMA IF NOT EXISTS metrics;

-- Create application user
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_user') THEN
        CREATE ROLE app_user LOGIN PASSWORD 'secure_app_password';
    END IF;
END
\$\$;

-- Grant permissions
GRANT USAGE ON SCHEMA security_agents TO app_user;
GRANT USAGE ON SCHEMA intelligence TO app_user;
GRANT USAGE ON SCHEMA metrics TO app_user;

-- Create tables (add your schema here)
-- Example tables:
CREATE TABLE IF NOT EXISTS security_agents.analysis_requests (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    request_id VARCHAR(255) UNIQUE NOT NULL,
    requester VARCHAR(255) NOT NULL,
    analysis_type VARCHAR(50) NOT NULL,
    target TEXT NOT NULL,
    priority VARCHAR(20) NOT NULL,
    parameters JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS intelligence.threat_campaigns (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    campaign_id VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    threat_actor VARCHAR(255),
    confidence DECIMAL(5,2),
    risk_score DECIMAL(5,2),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS metrics.system_metrics (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    metric_name VARCHAR(100) NOT NULL,
    metric_value DECIMAL(10,2),
    labels JSONB,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_analysis_requests_created_at ON security_agents.analysis_requests(created_at);
CREATE INDEX IF NOT EXISTS idx_threat_campaigns_created_at ON intelligence.threat_campaigns(created_at);
CREATE INDEX IF NOT EXISTS idx_system_metrics_timestamp ON metrics.system_metrics(timestamp);

-- Grant table permissions to app user
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA security_agents TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA intelligence TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA metrics TO app_user;

-- Grant sequence permissions
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA security_agents TO app_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA intelligence TO app_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA metrics TO app_user;
EOF
```

---

## Deployment Steps

### 1. Pre-deployment Checklist

```bash
# Verify environment variables
source .env.production
echo "Database: $POSTGRES_DB"
echo "Domain: $DOMAIN"
echo "JWT Secret length: ${#JWT_SECRET}"

# Verify external API connectivity
curl -f "https://www.virustotal.com/vtapi/v2/ip-address/report?apikey=$VIRUSTOTAL_API_KEY&ip=8.8.8.8" || echo "VirusTotal API check failed"

# Check system resources
free -h
df -h
docker system df
```

### 2. Build and Deploy

```bash
# Build the application
docker-compose -f docker-compose.prod.yml build --no-cache

# Start infrastructure services first
docker-compose -f docker-compose.prod.yml up -d postgres redis loki

# Wait for database to be ready
sleep 30

# Run database migrations
docker-compose -f docker-compose.prod.yml run --rm api migrate

# Start all services
docker-compose -f docker-compose.prod.yml up -d

# Verify deployment
docker-compose -f docker-compose.prod.yml ps
```

### 3. Post-deployment Verification

```bash
# Check service health
curl -f "https://api.$DOMAIN/health"
curl -f "https://dashboard.$DOMAIN" -u admin:password

# Verify database connectivity
docker-compose -f docker-compose.prod.yml exec postgres pg_isready -U $POSTGRES_USER -d $POSTGRES_DB

# Check logs for errors
docker-compose -f docker-compose.prod.yml logs api | grep ERROR
docker-compose -f docker-compose.prod.yml logs orchestrator | grep ERROR

# Test API functionality
curl -X POST "https://api.$DOMAIN/analysis" \
  -H "Authorization: Bearer demo-key-123" \
  -H "Content-Type: application/json" \
  -d '{
    "analysis_type": "comprehensive",
    "target": "/tmp/test",
    "priority": "medium"
  }'
```

---

## Monitoring and Alerting

### 1. Access Monitoring Dashboards

- **Grafana**: https://dashboard.yourdomain.com (admin/password)
- **Prometheus**: https://metrics.yourdomain.com
- **Traefik**: https://traefik.yourdomain.com

### 2. Key Metrics to Monitor

```yaml
# System Health
- CPU usage per service
- Memory consumption
- Disk space utilization
- Network I/O

# Application Metrics
- Request rate and latency
- Error rate by endpoint
- Queue depth and processing time
- Database connection pool status

# Security Metrics
- Failed authentication attempts
- Rate limit violations
- Threat detections per hour
- Intelligence correlation rate
```

### 3. Alerting Rules

```bash
# Create alerting rules
cat > config/prometheus/rules/security_agents.yml << EOF
groups:
- name: security_agents
  rules:
  - alert: HighErrorRate
    expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.1
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: "High error rate detected"

  - alert: DatabaseDown
    expr: up{job="postgres"} == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "PostgreSQL database is down"

  - alert: HighMemoryUsage
    expr: (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes) < 0.1
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High memory usage detected"
EOF
```

---

## Scaling and High Availability

### 1. Horizontal Scaling

```bash
# Scale API services
docker-compose -f docker-compose.prod.yml up -d --scale api=5

# Scale worker services
docker-compose -f docker-compose.prod.yml up -d --scale worker=8

# Monitor scaling
docker-compose -f docker-compose.prod.yml ps
```

### 2. Database High Availability

```yaml
# PostgreSQL with streaming replication
postgres-primary:
  image: postgres:16-alpine
  environment:
    POSTGRES_REPLICATION_MODE: master
    POSTGRES_REPLICATION_USER: replicator
    POSTGRES_REPLICATION_PASSWORD: repl_password

postgres-replica:
  image: postgres:16-alpine
  environment:
    POSTGRES_REPLICATION_MODE: slave
    POSTGRES_MASTER_HOST: postgres-primary
    POSTGRES_REPLICATION_USER: replicator
    POSTGRES_REPLICATION_PASSWORD: repl_password
```

### 3. Load Balancer Configuration

```nginx
# Nginx upstream configuration
upstream security_agents_api {
    least_conn;
    server api-1:8080 max_fails=3 fail_timeout=30s;
    server api-2:8080 max_fails=3 fail_timeout=30s;
    server api-3:8080 max_fails=3 fail_timeout=30s;
}
```

---

## Backup and Disaster Recovery

### 1. Database Backups

```bash
# Create backup script
cat > scripts/backup.sh << 'EOF'
#!/bin/bash
set -e

BACKUP_DIR="/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DB_BACKUP="$BACKUP_DIR/db_backup_$TIMESTAMP.sql.gz"

# Create database backup
docker-compose -f docker-compose.prod.yml exec -T postgres pg_dump -U $POSTGRES_USER -d $POSTGRES_DB | gzip > "$DB_BACKUP"

# Upload to cloud storage (optional)
# aws s3 cp "$DB_BACKUP" s3://your-backup-bucket/database/

# Cleanup old backups (keep last 30 days)
find $BACKUP_DIR -name "db_backup_*.sql.gz" -mtime +30 -delete

echo "Backup completed: $DB_BACKUP"
EOF

chmod +x scripts/backup.sh

# Schedule with cron
echo "0 2 * * * /path/to/scripts/backup.sh" | crontab -
```

### 2. Configuration Backup

```bash
# Backup configuration and secrets
tar -czf "config_backup_$(date +%Y%m%d).tar.gz" \
    .env.production \
    config/ \
    docker-compose.prod.yml

# Store securely
gpg --symmetric --cipher-algo AES256 config_backup_*.tar.gz
```

---

## Security Hardening

### 1. System Security

```bash
# Configure firewall
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp    # SSH
ufw allow 80/tcp    # HTTP
ufw allow 443/tcp   # HTTPS
ufw --force enable

# Disable root SSH access
sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
systemctl restart ssh
```

### 2. Container Security

```bash
# Run Docker security benchmark
docker run --rm -it \
    --pid host \
    --userns host \
    --cap-add audit_control \
    -e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST \
    -v /var/lib:/var/lib:ro \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    --label docker_bench_security \
    docker/docker-bench-security
```

### 3. SSL/TLS Configuration

```bash
# Generate strong Diffie-Hellman parameters
openssl dhparam -out ssl/dhparam.pem 4096

# Configure strong SSL settings in Traefik
cat > config/traefik-tls.yml << EOF
tls:
  options:
    default:
      minVersion: "VersionTLS12"
      cipherSuites:
        - "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
        - "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305"
        - "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
EOF
```

---

## Troubleshooting

### Common Issues

1. **Service Won't Start**
```bash
# Check logs
docker-compose -f docker-compose.prod.yml logs service_name

# Check resource usage
docker stats

# Verify configuration
docker-compose -f docker-compose.prod.yml config
```

2. **Database Connection Issues**
```bash
# Check database status
docker-compose -f docker-compose.prod.yml exec postgres pg_isready

# Verify credentials
docker-compose -f docker-compose.prod.yml exec postgres psql -U $POSTGRES_USER -d $POSTGRES_DB -c "SELECT version();"
```

3. **SSL Certificate Issues**
```bash
# Check certificate status
docker-compose -f docker-compose.prod.yml logs traefik | grep acme

# Manually force certificate renewal
docker-compose -f docker-compose.prod.yml exec traefik rm /letsencrypt/acme.json
docker-compose -f docker-compose.prod.yml restart traefik
```

### Performance Tuning

```bash
# Monitor resource usage
docker-compose -f docker-compose.prod.yml exec api python -c "
import psutil
print(f'CPU: {psutil.cpu_percent()}%')
print(f'Memory: {psutil.virtual_memory().percent}%')
"

# Optimize database
docker-compose -f docker-compose.prod.yml exec postgres psql -U $POSTGRES_USER -d $POSTGRES_DB -c "ANALYZE;"
```

---

## Maintenance

### Regular Maintenance Tasks

1. **Weekly**:
   - Review system logs for errors
   - Check disk space and cleanup old logs
   - Verify backup integrity
   - Update security patches

2. **Monthly**:
   - Review and rotate API keys
   - Update Docker images
   - Performance optimization review
   - Security audit

3. **Quarterly**:
   - Disaster recovery testing
   - Capacity planning review
   - Security penetration testing
   - Documentation updates

### Update Procedure

```bash
# Backup current state
./scripts/backup.sh

# Pull latest images
docker-compose -f docker-compose.prod.yml pull

# Update application with zero downtime
docker-compose -f docker-compose.prod.yml up -d --no-deps api

# Verify health
curl -f "https://api.$DOMAIN/health"

# Update other services
docker-compose -f docker-compose.prod.yml up -d
```

---

## Support and Contact

For deployment issues or questions:
- **Documentation**: Check this guide and service logs
- **Monitoring**: Use Grafana dashboards for system insights
- **Logs**: Check service logs in `/logs/` directory or via `docker-compose logs`

**Emergency Contacts**:
- System Administrator: [admin@yourdomain.com]
- Security Team: [security@yourdomain.com]
- 24/7 Support: [support@yourdomain.com]

---

*This deployment guide is part of the SecurityAgents Platform v2.0. Last updated: March 6, 2026*