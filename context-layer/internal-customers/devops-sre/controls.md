---
Last Verified: 2026-03-01
Verified By: Cyber Defense Team
Status: Active
---

# DevOps/SRE — Security Controls

## Cloud Security Posture

| Control | Status | Tool | Notes |
|---------|--------|------|-------|
| AWS Security Hub | Deployed | Security Hub (CIS, PCI) | All accounts, aggregated to security account |
| GuardDuty | Deployed | GuardDuty | All accounts, findings routed to SIEM |
| AWS Config | Deployed | Config Rules | Compliance rules for infrastructure drift |
| CloudTrail | Deployed | Multi-account, multi-region | Immutable logs in dedicated S3 bucket |
| VPC Flow Logs | Deployed | All VPCs | Sampled, forwarded to SIEM |

## Identity & Access

| Control | Status | Notes |
|---------|--------|-------|
| SSO + MFA for AWS Console | Deployed | Okta → AWS SSO, hardware MFA for admin roles |
| No standing admin access | Deployed | Just-in-time access via Okta + approval workflow |
| Service account credential rotation | Partial | Automated for RDS, manual for some third-party integrations |
| Root account lockdown | Deployed | MFA hardware token, no API keys, alerting on any root activity |

## Container & Kubernetes

| Control | Status | Notes |
|---------|--------|-------|
| EKS node hardening | Deployed | CIS-hardened AMIs, auto-patching |
| Pod security standards | Deployed | Restricted policy (no privileged, no hostPath) |
| Network policies | Deployed | Calico network policies, default-deny |
| Image signing | Partial | ECR scanning deployed — gap: no image signature verification (cosign) |
| Runtime protection | Deployed | CrowdStrike Falcon Container |

## CI/CD Security

| Control | Status | Notes |
|---------|--------|-------|
| Secret detection | Deployed | GHAS push protection + pre-commit hooks |
| Pipeline security | Deployed | GitHub Actions with OIDC, no long-lived credentials |
| IaC scanning | Deployed | Checkov in CI for Terraform |
| Dependency scanning | Deployed | Dependabot + GHAS |
| Artifact integrity | Partial | Container images tagged by SHA — gap: no SLSA provenance |

## Network Security

| Control | Status | Notes |
|---------|--------|-------|
| VPC segmentation | Deployed | Production, staging, dev in separate VPCs |
| Private subnets | Deployed | No direct internet access for production workloads |
| VPC endpoints | Deployed | S3, ECR, KMS, STS, CloudWatch |
| Zero-trust service mesh | Not deployed | **Gap** — services authenticate via network position, not identity |

## Gaps and Planned Improvements

- **Zero-trust service mesh**: Planned Istio deployment for mTLS between services (Q3 2026)
- **Image signature verification**: Cosign + Kyverno for admission control (Q2 2026)
- **SLSA provenance**: Supply chain integrity for build artifacts (Q3 2026)
- **Service account rotation**: Automate remaining manual rotations (Q2 2026)
