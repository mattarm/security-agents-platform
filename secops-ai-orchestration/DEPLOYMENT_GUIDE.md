# SecOps AI Platform - Deployment Guide

## Tiger Team Beta-2: AI Orchestration with Graduated Autonomy

This guide provides step-by-step instructions for deploying the SecOps AI Platform with Claude integration and graduated autonomy framework.

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    SecOps AI Platform                       │
├─────────────────────────────────────────────────────────────┤
│  AI Orchestration Layer                                     │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐ │
│  │ Claude Bedrock  │  │ Confidence      │  │ Autonomy     │ │
│  │ Multi-Model     │  │ Scoring Engine  │  │ Controller   │ │
│  │ Router          │  │                 │  │ (4 Tiers)    │ │
│  └─────────────────┘  └─────────────────┘  └──────────────┘ │
├─────────────────────────────────────────────────────────────┤
│  Enterprise Governance                                      │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐ │
│  │ Decision        │  │ Bias Detection  │  │ Privacy      │ │
│  │ Auditing        │  │ & Monitoring    │  │ Controls     │ │
│  └─────────────────┘  └─────────────────┘  └──────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## 📋 Prerequisites

### System Requirements
- **Operating System**: Linux/macOS (Windows with WSL2)
- **Python**: 3.9+ with pip
- **Memory**: 4GB RAM minimum, 8GB recommended
- **Storage**: 10GB available space
- **Network**: Internet access for AWS services

### Required Tools
- **AWS CLI**: v2.0+ configured with appropriate credentials
- **Terraform**: v1.0+ for infrastructure deployment
- **Git**: For repository management
- **curl**: For API testing

### AWS Prerequisites
- **AWS Account** with appropriate permissions
- **IAM Permissions** for:
  - VPC creation and management
  - Bedrock service access
  - KMS key management
  - CloudWatch logs
  - EC2 and security groups
- **AWS Bedrock Access** to Claude models (request access if needed)

### Required AWS Service Limits
- **VPC**: 5 VPCs per region (default)
- **EC2**: 20 security groups per VPC (default)
- **Bedrock**: Model access enabled for:
  - `anthropic.claude-3-haiku-20240307-v1:0`
  - `anthropic.claude-3-sonnet-20240229-v1:0`
  - `anthropic.claude-3-opus-20240229-v1:0`

## 🚀 Quick Start

### 1. Clone Repository
```bash
git clone <repository-url>
cd secops-ai-orchestration
```

### 2. Run Automated Deployment
```bash
# Development environment
./deploy.sh --environment dev

# Production environment
./deploy.sh --environment prod --region us-east-1
```

The deployment script will:
- ✅ Check prerequisites
- ✅ Deploy AWS infrastructure
- ✅ Configure the application
- ✅ Run tests
- ✅ Start services
- ✅ Validate deployment

## 📖 Detailed Deployment Steps

### Step 1: Environment Setup

#### 1.1 Configure AWS Credentials
```bash
aws configure
# Enter your AWS Access Key ID, Secret Access Key, Region, and Output format
```

#### 1.2 Verify AWS Access
```bash
aws sts get-caller-identity
aws bedrock list-foundation-models --region us-east-1
```

### Step 2: Infrastructure Deployment

#### 2.1 Initialize Terraform
```bash
cd infrastructure/
terraform init
```

#### 2.2 Review Infrastructure Plan
```bash
terraform plan -var="environment=prod" -var="project_name=secops-ai"
```

#### 2.3 Deploy Infrastructure
```bash
terraform apply -var="environment=prod" -var="project_name=secops-ai"
```

This creates:
- **VPC** with private/public subnets
- **VPC Endpoints** for Bedrock, S3, and KMS
- **Security Groups** with least-privilege access
- **KMS Key** for customer-managed encryption
- **IAM Roles** for Bedrock access
- **CloudWatch Log Groups** for audit trails

### Step 3: Application Configuration

#### 3.1 Create Configuration File
```bash
cp .env.example .env
```

#### 3.2 Update Configuration
Edit `.env` with your specific values:
```bash
# Required AWS Configuration
SECOPS_AI_AWS_REGION=us-east-1
SECOPS_AI_AWS_ACCESS_KEY_ID=your_access_key
SECOPS_AI_AWS_SECRET_ACCESS_KEY=your_secret_key
SECOPS_AI_BEDROCK_VPC_ENDPOINT=https://bedrock-runtime.us-east-1.amazonaws.com

# Security Configuration
SECOPS_AI_SECRET_KEY=your-secure-secret-key-here
SECOPS_AI_AUDIT_ENCRYPTION_KEY=your-audit-encryption-key

# Optional Slack Integration
SECOPS_AI_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

### Step 4: Application Deployment

#### 4.1 Install Dependencies
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

#### 4.2 Run Tests
```bash
pytest tests/ -v --cov=.
```

#### 4.3 Start Application
```bash
# Development mode
python main.py

# Production mode with Gunicorn
gunicorn main:app --workers 4 --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:8080
```

## 🔧 Configuration

### Autonomy Tier Configuration

The graduated autonomy framework uses four tiers:

| Tier | Description | Confidence | Action | Oversight |
|------|-------------|------------|--------|-----------|
| 0 | Auto-close false positives | >95% | Immediate | Post-audit |
| 1 | Enrich and create tickets | >80% | Async validation | Human review queue |
| 2 | Recommend containment | >60% | Slack approval required | Interactive buttons |
| 3 | Human-led assistance | Any | AI copilot | Conversational interface |

### Model Cost Optimization

Configure cost targets in `.env`:
```bash
# Target $100-250/month total
SECOPS_AI_MAX_MONTHLY_COST_USD=250.0
SECOPS_AI_COST_OPTIMIZATION_ENABLED=true

# Model distribution targets:
# Haiku (70%): $50-100/month
# Sonnet (25%): $30-80/month  
# Opus (5%): $20-70/month
```

### Compliance Framework

Enable compliance frameworks:
```bash
SECOPS_AI_COMPLIANCE_FRAMEWORKS=["SOC2", "ISO27001"]
SECOPS_AI_AUDIT_RETENTION_DAYS=2555  # 7 years
```

## 🧪 Testing

### Unit Tests
```bash
pytest tests/ -v
```

### Integration Tests
```bash
# Test alert processing
curl -X POST http://localhost:8080/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Test Security Alert",
    "description": "Suspicious network activity",
    "severity": "medium",
    "source": "firewall",
    "evidence": {"source_ip": "192.168.1.100"},
    "metadata": {"test": true}
  }'
```

### Health Check
```bash
curl http://localhost:8080/health
```

### Load Testing (Optional)
```bash
# Install Apache Bench
sudo apt-get install apache2-utils

# Test with 100 requests, 10 concurrent
ab -n 100 -c 10 -H "Content-Type: application/json" \
   -p test_alert.json \
   http://localhost:8080/analyze
```

## 📊 Monitoring

### Application Metrics
- **URL**: `http://localhost:8080/metrics`
- **Includes**: Processing time, model usage, cost tracking, autonomy distribution

### Health Monitoring
- **URL**: `http://localhost:8080/health`
- **Monitors**: All components (AI engine, confidence engine, autonomy controller, audit logger, compliance engine)

### AWS CloudWatch
- **Log Groups**:
  - `/aws/secops-ai/prod/ai-processing`
  - `/aws/secops-ai/prod/audit-trail`
- **Metrics**: Custom metrics for model usage and performance

## 🔒 Security

### Network Security
- **VPC Isolation**: All AI processing in private subnets
- **Zero Internet Egress**: VPC endpoints for all AWS services
- **Security Groups**: Least-privilege access rules
- **NACLs**: Additional network-level protection

### Data Security
- **Customer-Managed KMS**: All data encrypted with your keys
- **Audit Trail Encryption**: Immutable audit logs with cryptographic integrity
- **PII Detection**: Automatic detection and masking of sensitive data

### Access Control
- **IAM Roles**: Principle of least privilege
- **VPC Endpoints**: Service access within VPC only
- **Human Approval Gates**: Graduated autonomy with human oversight

## 🔄 Operations

### Backup and Recovery
```bash
# Backup audit database
cp data/audit_log.db backup/audit_log_$(date +%Y%m%d).db

# Backup configuration
tar -czf backup/config_$(date +%Y%m%d).tar.gz .env infrastructure/
```

### Log Management
```bash
# View application logs
tail -f secops-ai.log

# View audit logs
sqlite3 data/audit_log.db "SELECT * FROM audit_events ORDER BY timestamp DESC LIMIT 10;"

# CloudWatch logs
aws logs tail /aws/secops-ai/prod/ai-processing --follow
```

### Updates and Maintenance
```bash
# Update application
git pull
pip install -r requirements.txt
sudo systemctl restart secops-ai

# Update infrastructure
cd infrastructure/
terraform plan
terraform apply
```

## 📈 Scaling

### Horizontal Scaling
- **Multiple Workers**: Increase Gunicorn workers
- **Load Balancer**: Deploy behind ALB for multiple instances
- **Database**: Consider PostgreSQL for high-volume deployments

### Performance Optimization
- **Model Caching**: Implement model response caching
- **Async Processing**: Use background tasks for heavy operations
- **Database Indexing**: Optimize audit log queries

## 🚨 Troubleshooting

### Common Issues

#### 1. AWS Bedrock Access Denied
```bash
# Check Bedrock access
aws bedrock list-foundation-models --region us-east-1

# Request model access if needed
# Go to AWS Console > Bedrock > Model access
```

#### 2. VPC Endpoint Connection Issues
```bash
# Verify VPC endpoint
aws ec2 describe-vpc-endpoints --filters "Name=service-name,Values=com.amazonaws.us-east-1.bedrock-runtime"

# Check security group rules
aws ec2 describe-security-groups --group-ids sg-xxxxxxxx
```

#### 3. High Processing Times
```bash
# Check model usage distribution
curl http://localhost:8080/metrics | jq '.model_usage'

# Review confidence thresholds
# Consider lowering thresholds to use faster models
```

#### 4. Audit Database Issues
```bash
# Check database permissions
ls -la data/audit_log.db

# Recreate database if corrupted
rm data/audit_log.db
python3 -c "from ai_engine.audit_logger import AuditLogger; import asyncio; asyncio.run(AuditLogger({'audit_db_path': 'data/audit_log.db'}).health_check())"
```

### Debug Mode
```bash
# Enable debug logging
export SECOPS_AI_DEBUG=true
python main.py
```

### Support Contacts
- **Infrastructure Issues**: Cloud Engineering Team
- **Application Issues**: AI/ML Engineering Team  
- **Security Issues**: Security Architecture Team
- **Compliance Issues**: Compliance Team

## 📚 Additional Resources

- **API Documentation**: `http://localhost:8080/docs`
- **Architecture Diagrams**: `docs/architecture/`
- **Compliance Reports**: Generated via `/compliance/report` endpoint
- **Performance Metrics**: Available via `/metrics` endpoint
- **Audit Trail Search**: Use `/audit/search` endpoint

## ✅ Success Criteria Checklist

- [ ] **Claude Integration**: All 3 models deployed with cost optimization
- [ ] **Autonomy Tiers**: Tier 0-3 implementation with confidence thresholds  
- [ ] **Confidence Engine**: Multi-factor scoring with bias detection
- [ ] **Decision Auditing**: Complete reasoning chains with audit trails
- [ ] **Cost Optimization**: Target $100-250/month for 122 alerts/day
- [ ] **Performance**: <15 minute MTTD for automated triage
- [ ] **Governance**: SOC 2 compliance with bias monitoring
- [ ] **Security**: VPC isolation with customer-managed encryption
- [ ] **Scalability**: Handle 1000+ alerts/day with horizontal scaling
- [ ] **Reliability**: Circuit breakers and graceful degradation