---
Last Verified: 2026-03-01
Verified By: Cyber Defense Team
Status: Active
---

# Platform Engineering — Security Controls

## Endpoint & Runtime Protection

| Control | Status | Tool | Notes |
|---------|--------|------|-------|
| EDR on all hosts | Deployed | CrowdStrike Falcon | All EC2 instances and EKS nodes |
| Container runtime protection | Deployed | CrowdStrike Falcon Container | EKS pod-level monitoring |
| Web Application Firewall | Deployed | AWS WAF | API gateway and customer portal |
| DDoS protection | Deployed | AWS Shield Standard | CloudFront distribution |

## Application Security

| Control | Status | Tool | Notes |
|---------|--------|------|-------|
| SAST in CI/CD | Deployed | GitHub Advanced Security (CodeQL) | All platform repos |
| Secret scanning | Deployed | GHAS Secret Scanning + push protection | Enabled org-wide |
| Dependency scanning | Deployed | Dependabot | Auto-PR for critical/high |
| Container image scanning | Deployed | ECR image scanning | Block on Critical CVEs |
| API security testing | Partial | Manual pen testing | Quarterly cadence — gap: no continuous API security |

## Data Protection

| Control | Status | Notes |
|---------|--------|-------|
| Encryption at rest | Deployed | AWS KMS CMK for RDS, S3, EBS |
| Encryption in transit | Deployed | TLS 1.3 for all external; TLS 1.2+ for internal |
| PII tokenization | Deployed | Customer PII tokenized in analytics pipelines |
| Database access logging | Deployed | RDS audit logging to CloudTrail |
| Backup encryption | Deployed | Encrypted snapshots with cross-region replication |

## Access Control

| Control | Status | Notes |
|---------|--------|-------|
| SSO for all services | Deployed | Okta SSO with MFA required |
| Database access | Deployed | IAM-authenticated RDS access, no password auth |
| API authentication | Deployed | OAuth 2.0 + JWT for customer APIs |
| Secrets management | Deployed | AWS Secrets Manager, auto-rotation for RDS credentials |

## Gaps and Planned Improvements

- **API security testing**: Currently manual/quarterly. Roadmap: continuous API fuzzing in CI/CD (Q2 2026)
- **Runtime application self-protection (RASP)**: Not deployed. Under evaluation.
- **Data loss prevention**: No DLP controls on outbound API responses. Risk accepted for now.
