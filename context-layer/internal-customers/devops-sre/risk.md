---
Last Verified: 2026-03-09
Verified By: Alpha-4 Agent
Status: Active
---

# DevOps/SRE — Risk Register

<!-- Risks can be closed but never deleted. -->

## RISK-SRE-001 — No Zero-Trust Service Mesh

- **Status**: Active
- **Severity**: High
- **Opened**: 2026-01-15
- **Owner**: SRE Lead + Security Lead
- **Description**: Services authenticate based on network position (VPC/security group membership), not service identity. Lateral movement after initial compromise is unrestricted within a VPC segment.
- **Compensating Controls**: Network segmentation (separate VPCs), pod network policies (Calico default-deny), CrowdStrike runtime detection
- **Mitigation Plan**: Istio service mesh PoC (Q3 2026), production deployment (Q4 2026)
- **Review Date**: 2026-04-15

## RISK-SRE-002 — Supply Chain Integrity Gap

- **Status**: Active
- **Severity**: Medium
- **Opened**: 2026-02-15
- **Owner**: SRE Lead
- **Description**: Container images are not signed. No admission controller verifies image provenance. Build artifacts lack SLSA provenance attestation. An attacker who compromises the build pipeline or container registry could deploy malicious images.
- **Compensating Controls**: ECR-only pull policy, image scanning in CI/CD, EKS node IAM restricts ECR access
- **Mitigation Plan**: Cosign + Kyverno (Q2 2026), SLSA Level 2 (Q3 2026)
- **Review Date**: 2026-03-30

## RISK-SRE-003 — Terraform State as High-Value Target

- **Status**: Active
- **Severity**: High
- **Opened**: 2026-01-20
- **Owner**: SRE Lead + Security
- **Description**: Terraform state contains full infrastructure topology, resource IDs, and some sensitive outputs. State stored in S3 with encryption and versioning, but compromise would reveal complete infrastructure map.
- **Compensating Controls**: S3 bucket encryption (KMS CMK), bucket policy restricting access to CI/CD role only, CloudTrail logging on state bucket, state locking via DynamoDB
- **Mitigation Plan**: Evaluate state encryption at rest with additional key management (Q3 2026). Consider Terraform Cloud for state management.
- **Review Date**: 2026-04-20
