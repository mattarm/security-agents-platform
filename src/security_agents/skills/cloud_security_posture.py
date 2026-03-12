#!/usr/bin/env python3
"""
Cloud Security Posture Skill — multi-cloud configuration assessment and compliance.

Primary owner: Beta-4 (DevSecOps)
Also usable by: Gamma (Blue Team — drift detection and incident context)

Capabilities:
  - AWS/Azure/GCP configuration assessment against CIS benchmarks
  - Security group and IAM policy analysis
  - Encryption compliance checking
  - Public exposure detection (S3 buckets, storage accounts, etc.)
  - Configuration drift detection from baseline
  - Compliance mapping (CIS, PCI-DSS, SOC2, HIPAA)
  - Auto-remediation recommendations
"""

import hashlib
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional
from enum import Enum

from security_agents.core.models import (
    SkillResult, IntelligencePacket, IntelligenceType, Priority,
)
from security_agents.skills.base_skill import BaseSecuritySkill

class ComplianceFramework(Enum):
    CIS = "cis"
    PCI_DSS = "pci_dss"
    SOC2 = "soc2"
    HIPAA = "hipaa"
    NIST_800_53 = "nist_800_53"

class FindingSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class CloudSecurityPostureSkill(BaseSecuritySkill):
    """Multi-cloud security posture assessment and compliance monitoring."""

    SKILL_NAME = "cloud_security_posture"
    DESCRIPTION = (
        "Cloud configuration assessment against CIS benchmarks, IAM policy analysis, "
        "encryption compliance, public exposure detection, drift detection, and "
        "compliance mapping for CIS, PCI-DSS, SOC2, and HIPAA"
    )
    VERSION = "1.0.0"
    COMPATIBLE_AGENTS = ["beta_4_devsecops", "gamma_blue_team"]
    REQUIRED_INTEGRATIONS = []

    # -------------------------------------------------------------------------
    # CIS Benchmark Rules
    # -------------------------------------------------------------------------

    CIS_BENCHMARK_RULES = [
        {
            "rule_id": "CIS-AWS-1.1",
            "description": "Avoid use of root account",
            "severity": "critical",
            "resource_type": "iam_user",
            "check_fn": "Verify root account has no active access keys and MFA is enabled",
            "frameworks": ["cis", "pci_dss", "soc2", "nist_800_53"],
        },
        {
            "rule_id": "CIS-AWS-1.4",
            "description": "Ensure MFA is enabled for all IAM users with console access",
            "severity": "high",
            "resource_type": "iam_user",
            "check_fn": "Check that every IAM user with a console password has MFA configured",
            "frameworks": ["cis", "pci_dss", "soc2", "hipaa"],
        },
        {
            "rule_id": "CIS-AWS-1.16",
            "description": "Ensure IAM policies are attached only to groups or roles",
            "severity": "medium",
            "resource_type": "iam_policy",
            "check_fn": "Verify no IAM policies are directly attached to users",
            "frameworks": ["cis", "soc2"],
        },
        {
            "rule_id": "CIS-AWS-2.1",
            "description": "Ensure CloudTrail is enabled in all regions",
            "severity": "critical",
            "resource_type": "cloudtrail",
            "check_fn": "Verify a multi-region CloudTrail trail exists and is active",
            "frameworks": ["cis", "pci_dss", "soc2", "hipaa", "nist_800_53"],
        },
        {
            "rule_id": "CIS-AWS-2.6",
            "description": "Ensure S3 bucket access logging is enabled on CloudTrail bucket",
            "severity": "medium",
            "resource_type": "s3_bucket",
            "check_fn": "Check CloudTrail S3 bucket has access logging enabled",
            "frameworks": ["cis", "pci_dss", "soc2"],
        },
        {
            "rule_id": "CIS-AWS-2.9",
            "description": "Ensure VPC flow logging is enabled in all VPCs",
            "severity": "high",
            "resource_type": "vpc",
            "check_fn": "Verify every VPC has at least one active flow log",
            "frameworks": ["cis", "pci_dss", "soc2", "nist_800_53"],
        },
        {
            "rule_id": "CIS-AWS-3.1",
            "description": "Ensure S3 buckets are not publicly accessible",
            "severity": "critical",
            "resource_type": "s3_bucket",
            "check_fn": "Check bucket policy and ACL do not allow public access",
            "frameworks": ["cis", "pci_dss", "soc2", "hipaa", "nist_800_53"],
        },
        {
            "rule_id": "CIS-AWS-4.1",
            "description": "Ensure no security group allows ingress from 0.0.0.0/0 to port 22",
            "severity": "high",
            "resource_type": "security_group",
            "check_fn": "Check no inbound rule allows SSH from any source",
            "frameworks": ["cis", "pci_dss", "nist_800_53"],
        },
        {
            "rule_id": "CIS-AWS-4.2",
            "description": "Ensure no security group allows ingress from 0.0.0.0/0 to port 3389",
            "severity": "high",
            "resource_type": "security_group",
            "check_fn": "Check no inbound rule allows RDP from any source",
            "frameworks": ["cis", "pci_dss", "nist_800_53"],
        },
        {
            "rule_id": "CIS-AWS-5.1",
            "description": "Ensure EBS volumes are encrypted",
            "severity": "high",
            "resource_type": "ebs_volume",
            "check_fn": "Verify all EBS volumes have encryption enabled",
            "frameworks": ["cis", "pci_dss", "hipaa", "nist_800_53"],
        },
        {
            "rule_id": "CIS-AWS-5.2",
            "description": "Ensure RDS instances are encrypted",
            "severity": "high",
            "resource_type": "rds_instance",
            "check_fn": "Verify all RDS instances have storage encryption enabled",
            "frameworks": ["cis", "pci_dss", "hipaa", "nist_800_53"],
        },
        {
            "rule_id": "CIS-AWS-5.3",
            "description": "Ensure S3 bucket default encryption is enabled",
            "severity": "medium",
            "resource_type": "s3_bucket",
            "check_fn": "Verify all S3 buckets have default encryption configured",
            "frameworks": ["cis", "pci_dss", "hipaa"],
        },
    ]

    # Compliance framework control mappings
    FRAMEWORK_CONTROLS = {
        "cis": "CIS AWS Foundations Benchmark v1.5",
        "pci_dss": "PCI DSS v4.0",
        "soc2": "SOC 2 Type II — Trust Services Criteria",
        "hipaa": "HIPAA Security Rule — 45 CFR Part 164",
        "nist_800_53": "NIST SP 800-53 Rev. 5",
    }

    async def _setup(self):
        """Initialize posture tracking state."""
        self.baselines: Dict[str, Dict[str, Any]] = {}  # account_id -> baseline config
        self.findings: List[Dict[str, Any]] = []
        self.posture_history: List[Dict[str, Any]] = []

    async def _execute(self, parameters: Dict[str, Any]) -> SkillResult:
        """
        Dispatch to the appropriate cloud security posture action.

        Supported actions:
          assess_configuration — run CIS benchmark assessment
          check_iam_policies  — analyze IAM policies for overprivilege
          detect_public_exposure — find publicly accessible resources
          check_encryption    — verify encryption compliance
          assess_compliance   — map findings to compliance frameworks
          detect_drift        — compare current state against baseline
          get_posture_score   — compute overall posture score
        """
        action = parameters.get("action", "assess_configuration")

        dispatch = {
            "assess_configuration": self._assess_configuration,
            "check_iam_policies": self._check_iam_policies,
            "detect_public_exposure": self._detect_public_exposure,
            "check_encryption": self._check_encryption,
            "assess_compliance": self._assess_compliance,
            "detect_drift": self._detect_drift,
            "get_posture_score": self._get_posture_score,
        }

        handler = dispatch.get(action)
        if not handler:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"Unknown action '{action}'. Supported: {list(dispatch.keys())}"],
            )
        return await handler(parameters)

    # =========================================================================
    # Configuration Assessment
    # =========================================================================

    async def _assess_configuration(self, params: Dict[str, Any]) -> SkillResult:
        """Run CIS benchmark assessment against provided cloud resources."""
        resources = params.get("resources", [])
        cloud_provider = params.get("cloud_provider", "aws")
        account_id = params.get("account_id", "unknown")

        if not resources:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["'resources' parameter required — list of cloud resource configurations"],
            )

        findings = []
        passed = 0
        failed = 0

        # Build resource type index for fast lookup
        resource_index: Dict[str, List[Dict]] = {}
        for resource in resources:
            rtype = resource.get("resource_type", "unknown")
            resource_index.setdefault(rtype, []).append(resource)

        for rule in self.CIS_BENCHMARK_RULES:
            applicable_resources = resource_index.get(rule["resource_type"], [])
            if not applicable_resources:
                continue

            for resource in applicable_resources:
                is_compliant, detail = self._evaluate_rule(rule, resource)

                if is_compliant:
                    passed += 1
                else:
                    failed += 1
                    finding = {
                        "finding_id": f"CSP-{uuid.uuid4().hex[:8]}",
                        "rule_id": rule["rule_id"],
                        "description": rule["description"],
                        "severity": rule["severity"],
                        "resource_type": rule["resource_type"],
                        "resource_id": resource.get("resource_id", "unknown"),
                        "resource_name": resource.get("name", ""),
                        "detail": detail,
                        "remediation": self._get_remediation(rule, resource),
                        "frameworks": rule["frameworks"],
                        "account_id": account_id,
                        "assessed_at": datetime.now().isoformat(),
                    }
                    findings.append(finding)
                    self.findings.append(finding)

        total_checks = passed + failed
        pass_rate = round(passed / max(1, total_checks) * 100, 1)

        # Store as baseline if requested
        if params.get("set_as_baseline", False):
            self.baselines[account_id] = {
                "resources": resources,
                "captured_at": datetime.now().isoformat(),
                "findings_count": len(findings),
            }

        # Emit intelligence for critical findings
        packets = []
        critical_findings = [f for f in findings if f["severity"] == "critical"]
        if critical_findings:
            packets.append(IntelligencePacket(
                packet_id=f"PKT-CSP-{uuid.uuid4().hex[:8]}",
                source_agent=self.agent_id,
                target_agents=["all"],
                intelligence_type=IntelligenceType.INFRASTRUCTURE,
                priority=Priority.HIGH,
                confidence=90.0,
                timestamp=datetime.now(),
                data={
                    "event": "critical_misconfigurations",
                    "account_id": account_id,
                    "cloud_provider": cloud_provider,
                    "critical_count": len(critical_findings),
                    "findings": [
                        {"rule_id": f["rule_id"], "resource_id": f["resource_id"]}
                        for f in critical_findings[:10]
                    ],
                },
                correlation_keys=[account_id, cloud_provider],
            ))

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "assessment_summary": {
                    "account_id": account_id,
                    "cloud_provider": cloud_provider,
                    "total_checks": total_checks,
                    "passed": passed,
                    "failed": failed,
                    "pass_rate": pass_rate,
                    "resources_scanned": len(resources),
                },
                "findings": findings,
                "severity_breakdown": {
                    "critical": sum(1 for f in findings if f["severity"] == "critical"),
                    "high": sum(1 for f in findings if f["severity"] == "high"),
                    "medium": sum(1 for f in findings if f["severity"] == "medium"),
                    "low": sum(1 for f in findings if f["severity"] == "low"),
                },
            },
            intelligence_packets=packets,
        )

    def _evaluate_rule(self, rule: Dict[str, Any], resource: Dict[str, Any]) -> tuple:
        """
        Evaluate a CIS benchmark rule against a resource.
        Returns (is_compliant: bool, detail: str).
        """
        rule_id = rule["rule_id"]
        config = resource.get("configuration", {})

        if rule_id == "CIS-AWS-1.1":
            has_keys = config.get("root_access_keys_active", True)
            has_mfa = config.get("root_mfa_enabled", False)
            if has_keys:
                return False, "Root account has active access keys"
            if not has_mfa:
                return False, "Root account does not have MFA enabled"
            return True, ""

        if rule_id == "CIS-AWS-1.4":
            has_console = config.get("console_access", False)
            has_mfa = config.get("mfa_enabled", False)
            if has_console and not has_mfa:
                return False, f"IAM user has console access without MFA"
            return True, ""

        if rule_id == "CIS-AWS-1.16":
            direct_policies = config.get("directly_attached_policies", [])
            if direct_policies:
                return False, f"User has {len(direct_policies)} directly attached policies"
            return True, ""

        if rule_id == "CIS-AWS-2.1":
            is_multi_region = config.get("is_multi_region", False)
            is_active = config.get("is_logging", False)
            if not is_multi_region or not is_active:
                return False, "CloudTrail is not enabled for all regions"
            return True, ""

        if rule_id == "CIS-AWS-2.6":
            access_logging = config.get("access_logging_enabled", False)
            if not access_logging:
                return False, "S3 access logging is not enabled on CloudTrail bucket"
            return True, ""

        if rule_id == "CIS-AWS-2.9":
            flow_logs = config.get("flow_logs_enabled", False)
            if not flow_logs:
                return False, "VPC flow logging is not enabled"
            return True, ""

        if rule_id == "CIS-AWS-3.1":
            public_access = config.get("public_access", False)
            public_acl = config.get("public_acl", False)
            if public_access or public_acl:
                return False, "S3 bucket is publicly accessible"
            return True, ""

        if rule_id in ("CIS-AWS-4.1", "CIS-AWS-4.2"):
            port = 22 if rule_id == "CIS-AWS-4.1" else 3389
            ingress_rules = config.get("ingress_rules", [])
            for ir in ingress_rules:
                if (ir.get("from_port", 0) <= port <= ir.get("to_port", 0)
                        and ir.get("cidr") in ("0.0.0.0/0", "::/0")):
                    return False, f"Security group allows ingress from 0.0.0.0/0 to port {port}"
            return True, ""

        if rule_id in ("CIS-AWS-5.1", "CIS-AWS-5.2"):
            encrypted = config.get("encrypted", False)
            if not encrypted:
                resource_label = "EBS volume" if rule_id == "CIS-AWS-5.1" else "RDS instance"
                return False, f"{resource_label} is not encrypted"
            return True, ""

        if rule_id == "CIS-AWS-5.3":
            default_encryption = config.get("default_encryption_enabled", False)
            if not default_encryption:
                return False, "S3 bucket does not have default encryption enabled"
            return True, ""

        # Unknown rule — assume pass
        return True, ""

    def _get_remediation(self, rule: Dict[str, Any], resource: Dict[str, Any]) -> str:
        """Return remediation guidance for a failed rule."""
        remediations = {
            "CIS-AWS-1.1": "Delete root access keys and enable hardware MFA on the root account.",
            "CIS-AWS-1.4": "Enable MFA for the IAM user. Use virtual or hardware MFA device.",
            "CIS-AWS-1.16": "Detach policies from the user and attach them to a group or role instead.",
            "CIS-AWS-2.1": "Create a multi-region CloudTrail trail with management event logging.",
            "CIS-AWS-2.6": "Enable S3 server access logging on the CloudTrail S3 bucket.",
            "CIS-AWS-2.9": "Enable VPC flow logs for the VPC, sending to CloudWatch Logs or S3.",
            "CIS-AWS-3.1": "Enable S3 Block Public Access at the bucket level. Review and restrict bucket policy and ACLs.",
            "CIS-AWS-4.1": "Remove inbound rules allowing 0.0.0.0/0 access to port 22. Use VPN or bastion host.",
            "CIS-AWS-4.2": "Remove inbound rules allowing 0.0.0.0/0 access to port 3389. Use VPN or bastion host.",
            "CIS-AWS-5.1": "Enable encryption on the EBS volume using AWS KMS (default or CMK).",
            "CIS-AWS-5.2": "Enable encryption on the RDS instance. Note: requires instance recreation for existing unencrypted instances.",
            "CIS-AWS-5.3": "Enable default encryption on the S3 bucket using SSE-S3 or SSE-KMS.",
        }
        return remediations.get(rule["rule_id"], "Refer to CIS benchmark documentation for remediation steps.")

    # =========================================================================
    # IAM Policy Analysis
    # =========================================================================

    async def _check_iam_policies(self, params: Dict[str, Any]) -> SkillResult:
        """Analyze IAM policies for overprivilege, wildcards, and risky permissions."""
        policies = params.get("policies", [])
        if not policies:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["'policies' parameter required — list of IAM policy documents"],
            )

        findings = []
        for policy in policies:
            policy_name = policy.get("policy_name", "unknown")
            statements = policy.get("statements", [])

            for stmt in statements:
                issues = self._analyze_iam_statement(stmt)
                for issue in issues:
                    findings.append({
                        "policy_name": policy_name,
                        "statement_id": stmt.get("sid", ""),
                        "issue": issue["issue"],
                        "severity": issue["severity"],
                        "detail": issue["detail"],
                        "recommendation": issue["recommendation"],
                    })

        risk_score = self._compute_iam_risk_score(findings)

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "policies_analyzed": len(policies),
                "findings": findings,
                "total_issues": len(findings),
                "iam_risk_score": risk_score,
                "severity_breakdown": {
                    "critical": sum(1 for f in findings if f["severity"] == "critical"),
                    "high": sum(1 for f in findings if f["severity"] == "high"),
                    "medium": sum(1 for f in findings if f["severity"] == "medium"),
                },
            },
        )

    def _analyze_iam_statement(self, stmt: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze a single IAM policy statement for security issues."""
        issues = []
        effect = stmt.get("effect", "").lower()
        actions = stmt.get("actions", [])
        resources = stmt.get("resources", [])
        conditions = stmt.get("conditions", {})

        if effect != "allow":
            return issues

        # Check for wildcard actions
        if "*" in actions:
            issues.append({
                "issue": "wildcard_actions",
                "severity": "critical",
                "detail": "Statement grants all actions (*). This violates least-privilege.",
                "recommendation": "Restrict actions to only those required for the workload.",
            })

        # Check for wildcard resources
        if "*" in resources:
            severity = "critical" if any(a == "*" for a in actions) else "high"
            issues.append({
                "issue": "wildcard_resources",
                "severity": severity,
                "detail": "Statement applies to all resources (*). Scope to specific ARNs.",
                "recommendation": "Restrict resources to specific ARNs needed for the workload.",
            })

        # Check for dangerous actions
        dangerous_actions = {
            "iam:*": "Full IAM control allows privilege escalation",
            "iam:CreateUser": "Can create new IAM users",
            "iam:AttachUserPolicy": "Can attach policies to users (escalation risk)",
            "iam:PutUserPolicy": "Can create inline policies on users",
            "sts:AssumeRole": "Can assume roles (lateral movement risk if resource is *)",
            "s3:*": "Full S3 control — potential data exfiltration",
            "ec2:*": "Full EC2 control — can modify network and compute",
            "lambda:*": "Full Lambda control — can execute arbitrary code",
            "kms:Decrypt": "Can decrypt data if resource is *",
        }
        for action in actions:
            if action in dangerous_actions:
                issues.append({
                    "issue": f"dangerous_action:{action}",
                    "severity": "high",
                    "detail": dangerous_actions[action],
                    "recommendation": f"Review whether {action} is necessary. Apply conditions or restrict resources.",
                })

        # Check for missing conditions
        if not conditions and "*" in resources:
            issues.append({
                "issue": "no_conditions",
                "severity": "medium",
                "detail": "Allow statement on wildcard resources has no conditions. Consider adding IP, MFA, or tag conditions.",
                "recommendation": "Add conditions such as aws:SourceIp, aws:MultiFactorAuthPresent, or resource tags.",
            })

        return issues

    def _compute_iam_risk_score(self, findings: List[Dict]) -> float:
        """Compute aggregate IAM risk score from findings."""
        if not findings:
            return 0.0
        weights = {"critical": 25.0, "high": 15.0, "medium": 8.0, "low": 3.0}
        score = sum(weights.get(f["severity"], 0) for f in findings)
        return round(min(100.0, score), 1)

    # =========================================================================
    # Public Exposure Detection
    # =========================================================================

    async def _detect_public_exposure(self, params: Dict[str, Any]) -> SkillResult:
        """Detect publicly accessible cloud resources."""
        resources = params.get("resources", [])
        if not resources:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["'resources' parameter required"],
            )

        exposed = []
        for resource in resources:
            exposure = self._check_exposure(resource)
            if exposure["is_exposed"]:
                exposed.append(exposure)

        packets = []
        if exposed:
            packets.append(IntelligencePacket(
                packet_id=f"PKT-EXPOSURE-{uuid.uuid4().hex[:8]}",
                source_agent=self.agent_id,
                target_agents=["all"],
                intelligence_type=IntelligenceType.INFRASTRUCTURE,
                priority=Priority.HIGH if any(e["severity"] == "critical" for e in exposed) else Priority.MEDIUM,
                confidence=95.0,
                timestamp=datetime.now(),
                data={
                    "event": "public_exposure_detected",
                    "exposed_count": len(exposed),
                    "resources": [e["resource_id"] for e in exposed[:10]],
                },
                correlation_keys=[e["resource_id"] for e in exposed[:10]],
            ))

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "total_scanned": len(resources),
                "exposed_count": len(exposed),
                "exposed_resources": exposed,
            },
            intelligence_packets=packets,
        )

    def _check_exposure(self, resource: Dict[str, Any]) -> Dict[str, Any]:
        """Check a single resource for public exposure."""
        rtype = resource.get("resource_type", "")
        config = resource.get("configuration", {})
        resource_id = resource.get("resource_id", "unknown")
        is_exposed = False
        exposure_type = ""
        severity = "info"

        if rtype == "s3_bucket":
            if config.get("public_access") or config.get("public_acl"):
                is_exposed = True
                exposure_type = "public_s3_bucket"
                severity = "critical" if config.get("contains_sensitive_data") else "high"

        elif rtype == "security_group":
            for rule in config.get("ingress_rules", []):
                if rule.get("cidr") in ("0.0.0.0/0", "::/0"):
                    port = rule.get("from_port", 0)
                    if port in (22, 3389, 3306, 5432, 27017, 6379, 9200):
                        is_exposed = True
                        exposure_type = f"public_port_{port}"
                        severity = "critical"
                        break

        elif rtype == "rds_instance":
            if config.get("publicly_accessible", False):
                is_exposed = True
                exposure_type = "public_rds"
                severity = "critical"

        elif rtype == "elasticsearch":
            if config.get("endpoint_public", False):
                is_exposed = True
                exposure_type = "public_elasticsearch"
                severity = "critical"

        elif rtype == "storage_account":
            if config.get("allow_blob_public_access", False):
                is_exposed = True
                exposure_type = "public_blob_storage"
                severity = "high"

        return {
            "resource_id": resource_id,
            "resource_type": rtype,
            "is_exposed": is_exposed,
            "exposure_type": exposure_type,
            "severity": severity,
            "remediation": self._exposure_remediation(exposure_type) if is_exposed else "",
        }

    def _exposure_remediation(self, exposure_type: str) -> str:
        remediations = {
            "public_s3_bucket": "Enable S3 Block Public Access. Review and restrict bucket policy and ACLs.",
            "public_port_22": "Remove 0.0.0.0/0 ingress on port 22. Use VPN, bastion host, or SSM Session Manager.",
            "public_port_3389": "Remove 0.0.0.0/0 ingress on port 3389. Use VPN or bastion host.",
            "public_port_3306": "Remove public access to MySQL. Place behind private subnet with VPN access.",
            "public_port_5432": "Remove public access to PostgreSQL. Place behind private subnet.",
            "public_port_27017": "Remove public access to MongoDB. Use VPC peering or PrivateLink.",
            "public_port_6379": "Remove public access to Redis. Redis should never be internet-facing.",
            "public_port_9200": "Remove public access to Elasticsearch. Use VPC endpoints.",
            "public_rds": "Disable 'Publicly Accessible' on the RDS instance. Use VPC private subnets.",
            "public_elasticsearch": "Move Elasticsearch to VPC. Disable public endpoint.",
            "public_blob_storage": "Disable 'Allow Blob public access' on the storage account.",
        }
        return remediations.get(exposure_type, "Restrict public access to this resource.")

    # =========================================================================
    # Encryption Compliance
    # =========================================================================

    async def _check_encryption(self, params: Dict[str, Any]) -> SkillResult:
        """Verify encryption compliance across cloud resources."""
        resources = params.get("resources", [])
        if not resources:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["'resources' parameter required"],
            )

        findings = []
        encrypted_count = 0
        unencrypted_count = 0

        for resource in resources:
            config = resource.get("configuration", {})
            rtype = resource.get("resource_type", "")
            resource_id = resource.get("resource_id", "unknown")

            at_rest = config.get("encrypted", config.get("default_encryption_enabled", False))
            in_transit = config.get("enforce_ssl", config.get("tls_enforced", True))
            key_type = config.get("encryption_key_type", "none")  # aws_managed, cmk, none

            if at_rest:
                encrypted_count += 1
            else:
                unencrypted_count += 1
                findings.append({
                    "resource_id": resource_id,
                    "resource_type": rtype,
                    "issue": "no_encryption_at_rest",
                    "severity": "high",
                    "detail": f"{rtype} {resource_id} does not have encryption at rest enabled",
                    "remediation": f"Enable encryption at rest using AWS KMS for {rtype}",
                })

            if not in_transit:
                findings.append({
                    "resource_id": resource_id,
                    "resource_type": rtype,
                    "issue": "no_encryption_in_transit",
                    "severity": "high",
                    "detail": f"{rtype} {resource_id} does not enforce TLS for data in transit",
                    "remediation": "Enable and enforce TLS/SSL for all connections",
                })

            if at_rest and key_type == "aws_managed":
                findings.append({
                    "resource_id": resource_id,
                    "resource_type": rtype,
                    "issue": "using_default_key",
                    "severity": "low",
                    "detail": "Using AWS-managed key instead of customer-managed CMK",
                    "remediation": "Consider using a customer-managed KMS key for better key rotation control",
                })

        total = encrypted_count + unencrypted_count
        encryption_rate = round(encrypted_count / max(1, total) * 100, 1)

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "encryption_summary": {
                    "total_resources": total,
                    "encrypted": encrypted_count,
                    "unencrypted": unencrypted_count,
                    "encryption_rate": encryption_rate,
                },
                "findings": findings,
            },
        )

    # =========================================================================
    # Compliance Assessment
    # =========================================================================

    async def _assess_compliance(self, params: Dict[str, Any]) -> SkillResult:
        """Map current findings to compliance framework requirements."""
        framework = params.get("framework", "cis")
        if framework not in self.FRAMEWORK_CONTROLS:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"Unknown framework '{framework}'. Supported: {list(self.FRAMEWORK_CONTROLS.keys())}"],
            )

        # Filter findings to this framework
        applicable_rules = [r for r in self.CIS_BENCHMARK_RULES if framework in r["frameworks"]]
        matched_findings = [f for f in self.findings if framework in f.get("frameworks", [])]

        total_controls = len(applicable_rules)
        failing_controls = len(set(f["rule_id"] for f in matched_findings))
        passing_controls = total_controls - failing_controls
        compliance_rate = round(passing_controls / max(1, total_controls) * 100, 1)

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "framework": framework,
                "framework_name": self.FRAMEWORK_CONTROLS[framework],
                "total_controls": total_controls,
                "passing": passing_controls,
                "failing": failing_controls,
                "compliance_rate": compliance_rate,
                "failing_findings": matched_findings,
                "recommendations": self._compliance_recommendations(framework, compliance_rate, matched_findings),
            },
        )

    def _compliance_recommendations(
        self, framework: str, rate: float, findings: List[Dict]
    ) -> List[str]:
        recs = []
        if rate < 70:
            recs.append(f"Compliance rate for {framework.upper()} is {rate}% — below acceptable threshold. Prioritize critical findings.")
        critical = [f for f in findings if f.get("severity") == "critical"]
        if critical:
            recs.append(f"{len(critical)} critical findings must be remediated for {framework.upper()} compliance.")
        if framework == "pci_dss":
            recs.append("PCI-DSS requires quarterly external vulnerability scans by an ASV.")
        if framework == "hipaa":
            recs.append("HIPAA requires encryption of all PHI at rest and in transit.")
        if not recs:
            recs.append(f"Good compliance posture for {framework.upper()}. Maintain current controls.")
        return recs

    # =========================================================================
    # Drift Detection
    # =========================================================================

    async def _detect_drift(self, params: Dict[str, Any]) -> SkillResult:
        """Compare current configuration against stored baseline."""
        account_id = params.get("account_id", "unknown")
        current_resources = params.get("resources", [])

        if account_id not in self.baselines:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"No baseline found for account '{account_id}'. Run assess_configuration with set_as_baseline=True first."],
            )

        baseline = self.baselines[account_id]
        baseline_resources = baseline.get("resources", [])

        # Build lookup maps
        baseline_map = {r.get("resource_id"): r for r in baseline_resources}
        current_map = {r.get("resource_id"): r for r in current_resources}

        drifts = []

        # Check for modified resources
        for rid, current in current_map.items():
            if rid in baseline_map:
                changes = self._diff_configs(baseline_map[rid].get("configuration", {}), current.get("configuration", {}))
                if changes:
                    drifts.append({
                        "resource_id": rid,
                        "resource_type": current.get("resource_type", ""),
                        "drift_type": "modified",
                        "changes": changes,
                        "risk": self._assess_drift_risk(changes),
                    })
            else:
                drifts.append({
                    "resource_id": rid,
                    "resource_type": current.get("resource_type", ""),
                    "drift_type": "added",
                    "changes": [],
                    "risk": "medium",
                })

        # Check for deleted resources
        for rid in baseline_map:
            if rid not in current_map:
                drifts.append({
                    "resource_id": rid,
                    "resource_type": baseline_map[rid].get("resource_type", ""),
                    "drift_type": "deleted",
                    "changes": [],
                    "risk": "high",
                })

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "account_id": account_id,
                "baseline_captured_at": baseline.get("captured_at", ""),
                "total_drifts": len(drifts),
                "drifts": drifts,
                "drift_by_type": {
                    "modified": sum(1 for d in drifts if d["drift_type"] == "modified"),
                    "added": sum(1 for d in drifts if d["drift_type"] == "added"),
                    "deleted": sum(1 for d in drifts if d["drift_type"] == "deleted"),
                },
            },
        )

    def _diff_configs(self, baseline: Dict, current: Dict) -> List[Dict]:
        """Compare two configuration dicts and return differences."""
        changes = []
        all_keys = set(list(baseline.keys()) + list(current.keys()))
        for key in all_keys:
            old_val = baseline.get(key)
            new_val = current.get(key)
            if old_val != new_val:
                changes.append({
                    "field": key,
                    "baseline_value": old_val,
                    "current_value": new_val,
                })
        return changes

    def _assess_drift_risk(self, changes: List[Dict]) -> str:
        """Assess risk level of configuration changes."""
        high_risk_fields = {
            "public_access", "public_acl", "publicly_accessible", "encrypted",
            "mfa_enabled", "ingress_rules", "allow_blob_public_access",
            "root_access_keys_active", "flow_logs_enabled",
        }
        for change in changes:
            if change["field"] in high_risk_fields:
                return "high"
        return "low"

    # =========================================================================
    # Posture Score
    # =========================================================================

    async def _get_posture_score(self, params: Dict[str, Any]) -> SkillResult:
        """Compute an overall cloud security posture score."""
        # Score components: weighted from all findings
        severity_weights = {"critical": 10.0, "high": 6.0, "medium": 3.0, "low": 1.0, "info": 0.0}
        total_deductions = sum(severity_weights.get(f.get("severity", "low"), 0) for f in self.findings)

        # Start from 100, deduct based on findings, floor at 0
        base_score = 100.0
        posture_score = round(max(0.0, base_score - total_deductions), 1)

        # Letter grade
        if posture_score >= 90:
            grade = "A"
        elif posture_score >= 80:
            grade = "B"
        elif posture_score >= 70:
            grade = "C"
        elif posture_score >= 60:
            grade = "D"
        else:
            grade = "F"

        snapshot = {
            "timestamp": datetime.now().isoformat(),
            "score": posture_score,
            "grade": grade,
            "total_findings": len(self.findings),
        }
        self.posture_history.append(snapshot)

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "posture_score": posture_score,
                "grade": grade,
                "total_findings": len(self.findings),
                "finding_breakdown": {
                    "critical": sum(1 for f in self.findings if f.get("severity") == "critical"),
                    "high": sum(1 for f in self.findings if f.get("severity") == "high"),
                    "medium": sum(1 for f in self.findings if f.get("severity") == "medium"),
                    "low": sum(1 for f in self.findings if f.get("severity") == "low"),
                },
                "trend": [
                    {"timestamp": s["timestamp"], "score": s["score"]}
                    for s in self.posture_history[-10:]
                ],
                "top_recommendations": self._top_posture_recommendations(),
            },
        )

    def _top_posture_recommendations(self) -> List[str]:
        """Generate top recommendations to improve posture score."""
        recs = []
        critical = [f for f in self.findings if f.get("severity") == "critical"]
        if critical:
            recs.append(f"Remediate {len(critical)} critical findings immediately — these represent the highest risk.")
        exposure = [f for f in self.findings if "public" in f.get("detail", "").lower()]
        if exposure:
            recs.append(f"Eliminate {len(exposure)} public exposure findings to reduce attack surface.")
        encryption = [f for f in self.findings if "encrypt" in f.get("issue", "")]
        if encryption:
            recs.append(f"Address {len(encryption)} encryption gaps to meet data protection requirements.")
        if not recs:
            recs.append("Posture is strong. Continue monitoring for configuration drift.")
        return recs
