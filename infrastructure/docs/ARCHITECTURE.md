# SecurityAgents AWS Infrastructure Architecture

*Enterprise-grade AWS Bedrock infrastructure with zero-trust security for AI-powered security operations*

## Overview

This infrastructure implements **Phase 2A** of the SecurityAgents platform: secure AWS Bedrock deployment with enterprise-grade security, monitoring, and compliance controls. The design follows zero-trust principles with complete internet isolation and customer-managed encryption.

## Architecture Principles

### 1. Zero-Trust Security
- **No Internet Gateway**: All AWS API access via VPC endpoints only
- **Private Subnets Only**: AI workloads completely isolated from internet
- **Customer-Managed KMS**: AES-256 encryption for all data at rest
- **Least Privilege IAM**: Fine-grained access controls with MFA requirements
- **Complete Audit Trail**: CloudTrail logging for all actions with immutable storage

### 2. Enterprise Compliance
- **SOC 2 Type II Ready**: Comprehensive audit controls and evidence collection
- **ISO 27001 Alignment**: Defense in depth security architecture
- **Multi-AZ Deployment**: High availability with automated failover
- **Data Classification**: Internal/Confidential data handling
- **Regulatory Compliance**: GDPR-aligned data protection

### 3. Cost Optimization
- **Right-Sized Resources**: Development environment optimized for cost
- **Intelligent Storage Tiering**: S3 lifecycle policies for audit logs
- **Reserved Capacity**: KMS key optimization with bucket keys
- **Budget Controls**: Automated cost alerting and budget management

## Infrastructure Components

### VPC Module (`modules/vpc/`)
**Zero-trust networking for AI workloads**

```
VPC: 10.100.0.0/16 (Development)
├── Private Subnets (AI Workloads)
│   ├── secagents-dev-private-a (10.100.10.0/26) - 59 IPs
│   └── secagents-dev-private-b (10.100.11.0/26) - 59 IPs
├── Database Subnets (Monitoring/Audit)
│   ├── secagents-dev-database-a (10.100.20.0/28) - 11 IPs
│   └── secagents-dev-database-b (10.100.21.0/28) - 11 IPs
└── VPC Endpoints (AWS API Access)
    ├── Bedrock Runtime API
    ├── Bedrock Management API
    └── CloudWatch Logs API
```

**Security Features:**
- **No Internet Gateway**: Internet access completely blocked
- **VPC Flow Logs**: All network traffic logged and monitored
- **Network ACLs**: Defense in depth at subnet level
- **Security Groups**: Least privilege access control
- **Private DNS**: VPC endpoint resolution within private network

**Key Outputs:**
- `vpc_id`: Main VPC identifier
- `private_subnet_ids`: Subnets for AI workload deployment
- `bedrock_runtime_endpoint_id`: Secure Bedrock API access
- `security_compliance`: Validation of zero-trust configuration

### Security Module (`modules/security/`)
**Customer-managed encryption and enterprise IAM**

**KMS Configuration:**
- **Customer-Managed Key**: Full control over encryption keys
- **Automatic Rotation**: Annual key rotation for security
- **Multi-Service Access**: Bedrock, CloudWatch, S3, DynamoDB support
- **Audit Logging**: All key usage logged to CloudTrail

**IAM Roles:**
```
SecurityAgents Platform Roles:
├── security-admin-role (MFA Required)
│   ├── KMS key management
│   ├── Infrastructure administration
│   └── Compliance auditing
└── ai-workload-execution-role
    ├── Bedrock model invocation
    ├── CloudWatch logging
    └── S3 audit access (read-only)
```

**CloudTrail Audit:**
- **Multi-Region**: Complete AWS API coverage
- **Encrypted Storage**: S3 bucket with customer KMS encryption
- **Lifecycle Management**: Cost-optimized retention (7 years)
- **Immutable Logs**: Write-once, read-many audit trail

**Key Outputs:**
- `kms_key_arn`: Customer-managed encryption key
- `ai_workload_execution_role_arn`: Role for AI services
- `cloudtrail_arn`: Audit trail for compliance
- `security_compliance_status`: Enterprise security validation

### Bedrock Module (`modules/bedrock/`)
**Secure AI model deployment with comprehensive logging**

**Model Configuration:**
- **Allowed Models**: Anthropic Claude 3 (Sonnet, Haiku, Opus)
- **Default Model**: Claude 3 Sonnet (balanced performance/cost)
- **Access Control**: IAM policies restrict model access
- **Usage Monitoring**: Complete invocation logging and metrics

**Logging Architecture:**
```
Bedrock Logging Pipeline:
├── Real-time Logging
│   ├── CloudWatch Logs (30-day retention)
│   ├── Structured JSON format
│   └── KMS encrypted
├── Long-term Storage
│   ├── S3 bucket (encrypted)
│   ├── Lifecycle transitions (IA → Glacier → Deep Archive)
│   └── 365-day retention
└── Monitoring & Alerting
    ├── Error rate alarms
    ├── Latency monitoring
    └── Cost tracking
```

**Performance Monitoring:**
- **Error Rate**: < 5 errors per 5 minutes
- **Latency**: < 30 seconds for complex analysis
- **Throughput**: 1000+ security events per hour capability
- **Cost Control**: $200 monthly budget for development

**Key Outputs:**
- `bedrock_model_invocation_log_group_name`: Audit logs
- `cloudwatch_dashboard_name`: Performance monitoring
- `compliance_status`: SOC 2 compliance validation

### Monitoring Module (`modules/monitoring/`)
**Comprehensive observability and security alerting**

**Security Event Detection:**
```
Security Monitoring Pipeline:
├── VPC Flow Log Analysis
│   ├── Rejected connection attempts
│   ├── Unusual traffic patterns
│   └── Network-based threat indicators
├── Authentication Monitoring
│   ├── Failed authentication attempts
│   ├── Unusual access patterns
│   └── Privilege escalation attempts
└── AI Usage Monitoring
    ├── Model invocation anomalies
    ├── Suspicious query patterns
    └── Performance degradation
```

**Dashboard Architecture:**
- **Executive Dashboard**: Business metrics and KPIs
- **Operational Dashboard**: Technical performance and errors
- **Security Dashboard**: Threat detection and compliance status
- **Cost Dashboard**: Budget tracking and optimization recommendations

**Alert Configuration:**
```
Alert Severity Levels:
├── Critical (Immediate SMS/Email)
│   ├── Security breaches
│   ├── System outages
│   └── Budget overruns
├── High (5-minute delay)
│   ├── Performance degradation
│   ├── Error rate spikes
│   └── Unusual activity
└── Medium (15-minute delay)
    ├── Resource warnings
    ├── Cost alerts
    └── Maintenance notifications
```

**Key Outputs:**
- `security_alerts_topic_arn`: Critical security notifications
- `executive_dashboard_url`: Business performance monitoring
- `compliance_monitoring_status`: SOC 2/ISO 27001 alignment

## Environment Configuration

### Development Environment (`environments/dev/`)
**Optimized for testing and cost efficiency**

**Configuration Highlights:**
- **VPC CIDR**: 10.100.0.0/16 (isolated from production)
- **Availability Zones**: 2 (sufficient for development)
- **Log Retention**: 30 days (cost-optimized)
- **Budget Limits**: $500/month total, $200/month Bedrock
- **Enhanced Monitoring**: Debug logging and detailed metrics enabled

**Security Relaxations for Development:**
- Shorter KMS key deletion window (7 days vs 30)
- Reduced compliance requirements (SOC 2 not enforced)
- Development team access roles
- Immediate alerting for faster debugging

### Staging Environment (`environments/staging/`)
**Production-like testing with enterprise controls** *(Planned)*

### Production Environment (`environments/prod/`)
**Full enterprise deployment with maximum security** *(Planned)*

## Deployment Guide

### Prerequisites

1. **AWS CLI Configuration**
   ```bash
   aws configure
   aws sts get-caller-identity  # Verify access
   ```

2. **Bedrock Access Verification**
   ```bash
   aws bedrock list-foundation-models --region us-east-1
   ```

3. **Terraform Installation**
   ```bash
   brew install terraform
   terraform version  # Verify >= 1.0
   ```

### Step-by-Step Deployment

1. **Clone and Configure**
   ```bash
   cd ~/security-assessment/security-agents-infrastructure/environments/dev
   cp terraform.tfvars.example terraform.tfvars
   # Edit terraform.tfvars with your configuration
   ```

2. **Initialize Terraform**
   ```bash
   terraform init
   terraform validate
   terraform plan
   ```

3. **Deploy Infrastructure**
   ```bash
   terraform apply
   # Review the plan and type 'yes' to confirm
   ```

4. **Validate Deployment**
   ```bash
   # Test Bedrock connectivity
   aws bedrock invoke-model \
     --model-id anthropic.claude-3-sonnet-20240229-v1:0 \
     --body '{"anthropic_version":"bedrock-2023-05-31","max_tokens":1000,"messages":[{"role":"user","content":"Test secure connection"}]}' \
     --cli-binary-format raw-in-base64-out \
     --output text --query 'body' | base64 --decode
   ```

5. **Access Monitoring**
   - Executive Dashboard: (URL in terraform outputs)
   - Operational Dashboard: (URL in terraform outputs)
   - CloudWatch Logs: Check `bedrock-model-invocation` log group

## Security Architecture Deep Dive

### Zero-Trust Implementation

**Network Isolation:**
```
Internet ❌ → VPC (10.100.0.0/16)
              ├── Private Subnets (AI Workloads)
              │   ├── Security Groups (Least Privilege)
              │   ├── Network ACLs (Defense in Depth)
              │   └── VPC Endpoints (AWS API Access)
              └── Database Subnets (Monitoring)
                  ├── Encrypted Storage
                  └── Audit Logging
```

**Data Flow Security:**
1. **Ingress**: Only from authorized security groups within VPC
2. **Processing**: AI workloads in isolated private subnets
3. **AWS API Calls**: Via VPC endpoints with IAM policies
4. **Audit**: All actions logged to encrypted CloudTrail
5. **Egress**: No internet access allowed

### Encryption Everywhere

**Data at Rest:**
- **KMS Customer-Managed**: All storage encrypted with customer keys
- **S3 Buckets**: Server-side encryption with bucket keys (cost optimization)
- **CloudWatch Logs**: KMS encryption for sensitive log data
- **EBS Volumes**: Encrypted for any compute resources (future)

**Data in Transit:**
- **TLS 1.3**: All API communications encrypted
- **VPC Endpoints**: Private connectivity to AWS services
- **IAM Policies**: Enforce encrypted connections only

## Performance and Scalability

### Current Capacity (Development)
- **Throughput**: 100-500 security events per hour
- **Latency**: < 5 seconds for standard analysis
- **Storage**: 30-day log retention, unlimited archive
- **Availability**: 99% (development SLA)

### Production Scaling Plan
- **Throughput**: 1000+ security events per hour
- **Latency**: < 5 seconds standard, < 30 seconds complex
- **Storage**: 365-day active retention, 7-year archive
- **Availability**: 99.9% with multi-AZ deployment

### Auto-Scaling Architecture (Future)
```
Auto-Scaling Components:
├── ECS Fargate (AI Processing)
│   ├── Target scaling based on queue depth
│   ├── Min: 2 tasks, Max: 20 tasks
│   └── Scale-out: 2 minutes, Scale-in: 5 minutes
├── Application Load Balancer
│   ├── Health checks every 30 seconds
│   └── Multi-AZ distribution
└── DynamoDB (Real-time Data)
    ├── On-demand billing
    └── Auto-scaling read/write capacity
```

## Cost Analysis

### Development Environment Costs

**Monthly Estimates (US East 1):**
- **VPC Endpoints**: $21.60 (3 endpoints × $7.20)
- **CloudWatch Logs**: $15-30 (30-day retention)
- **Bedrock Usage**: $50-200 (varies by usage)
- **CloudTrail**: $2-5 (API calls)
- **KMS**: $1-3 (key usage)
- **S3 Storage**: $2-10 (audit logs)
- **SNS/CloudWatch**: $1-5 (alerting)

**Total Estimated**: $93-275/month (well under $500 budget)

### Cost Optimization Features

1. **S3 Lifecycle Policies**
   - Standard → IA after 30 days
   - IA → Glacier after 90 days
   - Glacier → Deep Archive after 365 days

2. **KMS Optimization**
   - S3 bucket keys reduce API calls by 99%
   - Multi-service key sharing reduces key costs

3. **CloudWatch Optimization**
   - Log retention aligned with compliance needs
   - Metric collection at 60-second intervals

4. **VPC Endpoint Optimization**
   - Minimal required endpoints for functionality
   - Shared endpoints across availability zones

## Compliance Framework

### SOC 2 Type II Controls

**Security Controls:**
- [ ] **CC6.1**: Logical access controls restrict unauthorized access
- [ ] **CC6.2**: Network access controls prevent unauthorized network access
- [ ] **CC6.3**: Access controls secure transmission of data
- [ ] **CC6.6**: Encryption protects data at rest and in transit
- [ ] **CC6.7**: System data is protected from unauthorized access

**Availability Controls:**
- [ ] **CC7.1**: System capacity supports achievement of objectives
- [ ] **CC7.2**: Monitoring controls detect capacity issues
- [ ] **CC7.4**: System recovery procedures restore service levels

**Processing Integrity Controls:**
- [ ] **CC8.1**: Processing integrity procedures ensure data accuracy

### ISO 27001 Alignment

**Access Control (A.9):**
- [ ] **A.9.1**: Business requirements for access control
- [ ] **A.9.2**: User access management
- [ ] **A.9.4**: Use of privileged utility programs

**Cryptography (A.10):**
- [ ] **A.10.1**: Cryptographic controls policy
- [ ] **A.10.2**: Key management procedures

**Operations Security (A.12):**
- [ ] **A.12.4**: Logging and monitoring
- [ ] **A.12.6**: Management of technical vulnerabilities

## TODO Items and Next Steps

### P0 - Critical (Week 1-2)
- [ ] **VPC Endpoints**: Add DynamoDB and S3 gateway endpoints for cost optimization
- [ ] **CloudTrail Data Events**: Configure S3 and DynamoDB data event logging
- [ ] **GuardDuty Integration**: Enable AWS GuardDuty for threat detection
- [ ] **Security Hub Integration**: Configure Security Hub for compliance monitoring
- [ ] **AWS Config**: Set up configuration compliance monitoring

### P1 - High Priority (Week 3-4)
- [ ] **Lambda Security Processor**: Implement advanced security event processing
- [ ] **Custom CloudWatch Metrics**: Add business KPI tracking
- [ ] **Performance Dashboard**: Create detailed Bedrock performance monitoring
- [ ] **Cost Anomaly Detection**: Configure AWS Cost Anomaly Detection
- [ ] **Backup Strategy**: Implement automated backup for configuration and logs

### P2 - Medium Priority (Week 5-6)
- [ ] **Secrets Manager Integration**: Store sensitive configuration in AWS Secrets Manager
- [ ] **Systems Manager Integration**: Use Parameter Store for configuration management
- [ ] **Enhanced Monitoring**: Add custom Lambda functions for security analysis
- [ ] **API Gateway Integration**: Prepare for MCP server deployment
- [ ] **Container Platform**: ECS/Fargate setup for AI workload deployment

### P3 - Future Enhancements
- [ ] **Multi-Region Deployment**: Disaster recovery and global availability
- [ ] **Advanced Analytics**: ML-based anomaly detection
- [ ] **Integration Testing**: Automated infrastructure testing
- [ ] **Performance Optimization**: Bedrock model optimization and caching
- [ ] **Compliance Automation**: Automated SOC 2 evidence collection

## Troubleshooting Guide

### Common Issues

**Bedrock Access Denied:**
```bash
# Check IAM permissions
aws iam simulate-principal-policy \
  --policy-source-arn $(aws sts get-caller-identity --query Arn --output text) \
  --action-names bedrock:InvokeModel \
  --resource-arns "*"

# Verify VPC endpoint connectivity
nslookup bedrock-runtime.us-east-1.amazonaws.com
```

**VPC Endpoint Resolution:**
```bash
# Check VPC endpoint status
aws ec2 describe-vpc-endpoints \
  --vpc-endpoint-ids $(terraform output -json vpc_info | jq -r '.value.bedrock_runtime_endpoint')

# Test endpoint connectivity from VPC
aws logs filter-log-events \
  --log-group-name $(terraform output -json vpc_info | jq -r '.value.vpc_flow_log_group')
```

**CloudWatch Logs Missing:**
```bash
# Verify log group permissions
aws logs describe-log-groups \
  --log-group-name-prefix "/aws/bedrock/"

# Check IAM role permissions
aws iam get-role-policy \
  --role-name $(terraform output -json security_info | jq -r '.value.ai_workload_role_name') \
  --policy-name bedrock-access
```

### Support Contacts

**Infrastructure Issues:**
- Team: Alpha-1 Infrastructure
- Email: alpha-1-infrastructure@company.com
- Slack: #alpha-1-infrastructure

**Security Questions:**
- Team: Security Operations
- Email: security-team@company.com
- Slack: #security-operations

**Cost/Budget Issues:**
- Team: FinOps
- Email: finops@company.com
- Slack: #cost-optimization

---

*This architecture document is maintained by the Alpha-1 Infrastructure team for the SecurityAgents Phase 2A deployment. Last updated: 2026-03-06*