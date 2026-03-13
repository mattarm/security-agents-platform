#!/usr/bin/env python3
"""
AWS Infrastructure Assessment Skill — security posture evaluation of AWS resources.

Primary owner: Beta-4 (DevSecOps), Delta (Red Team)
Wraps: security-agents-infrastructure/modules/ (vpc, security Terraform modules)

Capabilities:
  - VPC configuration review (flow logs, NACL, subnet isolation)
  - IAM policy analysis (privilege escalation, unused permissions)
  - S3 bucket exposure checks (public access, encryption, logging)
  - Security group rule validation (overly permissive rules, ingress exposure)
  - Encryption-at-rest and in-transit assessment
  - Consolidated finding generation with severity and remediation
"""

import uuid
import ipaddress
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Set
from collections import defaultdict

from security_agents.core.models import (
    SkillResult, IntelligencePacket, IntelligenceType, Priority, Severity,
)
from security_agents.skills.base_skill import BaseSecuritySkill

# ---------------------------------------------------------------------------
# Well-known dangerous patterns
# ---------------------------------------------------------------------------

DANGEROUS_PORTS = {22, 3389, 3306, 5432, 1433, 27017, 6379, 9200, 11211}

DANGEROUS_IAM_ACTIONS = {
    "iam:*", "sts:AssumeRole", "iam:CreateUser", "iam:CreateAccessKey",
    "iam:AttachUserPolicy", "iam:AttachRolePolicy", "iam:PutUserPolicy",
    "iam:PutRolePolicy", "iam:CreatePolicyVersion", "iam:PassRole",
    "lambda:CreateFunction", "lambda:InvokeFunction",
    "ec2:RunInstances", "s3:*", "kms:Decrypt",
}

PRIVILEGED_ACTIONS = {
    "iam:CreateUser", "iam:CreateRole", "iam:AttachUserPolicy",
    "iam:AttachRolePolicy", "iam:PutUserPolicy", "iam:PutRolePolicy",
    "iam:CreatePolicyVersion", "iam:PassRole",
}

class AWSInfrastructureSkill(BaseSecuritySkill):
    """AWS infrastructure security assessment and posture evaluation."""

    SKILL_NAME = "aws_infrastructure"
    DESCRIPTION = (
        "AWS security assessment covering VPC configuration, IAM policy analysis, "
        "S3 exposure checks, security group validation, encryption evaluation, "
        "and consolidated finding generation"
    )
    VERSION = "1.0.0"
    COMPATIBLE_AGENTS = ["beta_4_devsecops", "delta_red_team"]
    REQUIRED_INTEGRATIONS = ["aws"]

    # ---------------------------------------------------------------------
    # Lifecycle
    # ---------------------------------------------------------------------

    async def _setup(self):
        """Initialize internal state."""
        self.findings: List[Dict[str, Any]] = []
        self.assessed_resources: Dict[str, Dict[str, Any]] = {}
        self.finding_counter = 0

    # ---------------------------------------------------------------------
    # Action dispatch
    # ---------------------------------------------------------------------

    async def _execute(self, parameters: Dict[str, Any]) -> SkillResult:
        """
        Dispatch to the appropriate action.

        Supported actions:
          assess_vpc            -- review VPC configuration
          audit_iam             -- analyse IAM policies for risks
          check_s3_exposure     -- check S3 buckets for public exposure
          scan_security_groups  -- validate security group rules
          evaluate_encryption   -- assess encryption at rest / in transit
          generate_findings     -- produce consolidated findings report
        """
        action = parameters.get("action", "generate_findings")
        dispatch = {
            "assess_vpc": self._assess_vpc,
            "audit_iam": self._audit_iam,
            "check_s3_exposure": self._check_s3_exposure,
            "scan_security_groups": self._scan_security_groups,
            "evaluate_encryption": self._evaluate_encryption,
            "generate_findings": self._generate_findings,
        }
        handler = dispatch.get(action)
        if handler is None:
            return SkillResult(
                success=False,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                errors=[
                    f"Unknown action '{action}'. "
                    f"Supported: {', '.join(dispatch.keys())}"
                ],
            )
        return await handler(parameters)

    # =====================================================================
    # assess_vpc
    # =====================================================================

    async def _assess_vpc(self, params: Dict[str, Any]) -> SkillResult:
        """Review VPC configuration for security best practices."""
        vpc = params.get("vpc", {})
        vpc_id = vpc.get("vpc_id", f"vpc-{uuid.uuid4().hex[:8]}")

        issues: List[Dict[str, Any]] = []
        checks_passed: List[str] = []

        # Check CIDR block size
        cidr = vpc.get("cidr_block", "10.0.0.0/16")
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            if network.prefixlen < 16:
                issues.append(self._make_finding(
                    "vpc_oversized_cidr", "high",
                    f"VPC {vpc_id} uses a /{network.prefixlen} CIDR block, which is overly broad.",
                    f"Consider narrowing to /16 or smaller for {vpc_id}.",
                    vpc_id,
                ))
            else:
                checks_passed.append("cidr_block_size")
        except ValueError:
            issues.append(self._make_finding(
                "vpc_invalid_cidr", "medium",
                f"VPC {vpc_id} has an invalid CIDR block: {cidr}.",
                "Verify and correct the CIDR block configuration.",
                vpc_id,
            ))

        # Check flow logs
        flow_logs_enabled = vpc.get("flow_logs_enabled", False)
        if not flow_logs_enabled:
            issues.append(self._make_finding(
                "vpc_no_flow_logs", "high",
                f"VPC {vpc_id} does not have flow logs enabled.",
                "Enable VPC Flow Logs to CloudWatch or S3 for security monitoring.",
                vpc_id,
            ))
        else:
            checks_passed.append("flow_logs_enabled")

        # Check DNS settings
        dns_hostnames = vpc.get("dns_hostnames_enabled", False)
        dns_support = vpc.get("dns_support_enabled", True)
        if dns_hostnames and not dns_support:
            issues.append(self._make_finding(
                "vpc_dns_misconfigured", "low",
                f"VPC {vpc_id} has DNS hostnames enabled without DNS support.",
                "Enable DNS support or disable DNS hostnames for consistency.",
                vpc_id,
            ))
        else:
            checks_passed.append("dns_configuration")

        # Check for internet gateway
        has_igw = vpc.get("internet_gateway_attached", False)
        if has_igw:
            private_subnets = vpc.get("private_subnets", [])
            public_subnets = vpc.get("public_subnets", [])
            if not private_subnets and public_subnets:
                issues.append(self._make_finding(
                    "vpc_no_private_subnets", "high",
                    f"VPC {vpc_id} has an internet gateway but no private subnets.",
                    "Create private subnets for workloads that do not require direct internet access.",
                    vpc_id,
                ))
            else:
                checks_passed.append("subnet_isolation")
        else:
            checks_passed.append("no_internet_gateway")

        # Check NACLs
        nacls = vpc.get("nacls", [])
        for nacl in nacls:
            if nacl.get("allows_all_inbound", False):
                issues.append(self._make_finding(
                    "vpc_permissive_nacl", "medium",
                    f"NACL {nacl.get('nacl_id', 'unknown')} in VPC {vpc_id} allows all inbound traffic.",
                    "Restrict NACL inbound rules to required traffic only.",
                    vpc_id,
                ))

        # Check multi-AZ
        az_count = vpc.get("availability_zone_count", 1)
        if az_count < 2:
            issues.append(self._make_finding(
                "vpc_single_az", "medium",
                f"VPC {vpc_id} spans only {az_count} availability zone(s).",
                "Deploy across at least 2 AZs for high availability.",
                vpc_id,
            ))
        else:
            checks_passed.append("multi_az_deployment")

        self.assessed_resources[vpc_id] = {
            "type": "vpc", "assessed_at": datetime.now(timezone.utc).isoformat(),
        }

        severity = "critical" if any(i["severity"] == "critical" for i in issues) else (
            "high" if any(i["severity"] == "high" for i in issues) else (
                "medium" if issues else "low"
            )
        )

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "vpc_id": vpc_id,
                "overall_severity": severity,
                "issues_found": len(issues),
                "checks_passed": checks_passed,
                "issues": issues,
            },
        )

    # =====================================================================
    # audit_iam
    # =====================================================================

    async def _audit_iam(self, params: Dict[str, Any]) -> SkillResult:
        """Analyse IAM policies for privilege escalation and over-permission."""
        policies = params.get("policies", [])
        roles = params.get("roles", [])

        if not policies and not roles:
            return SkillResult(
                success=False,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                errors=["Provide at least one of 'policies' or 'roles'."],
            )

        issues: List[Dict[str, Any]] = []
        analysed_count = 0

        # Analyse policies
        for policy in policies:
            policy_name = policy.get("policy_name", "unnamed")
            policy_arn = policy.get("arn", "unknown")
            statements = policy.get("statements", [])
            analysed_count += 1

            for stmt in statements:
                effect = stmt.get("Effect", "Deny")
                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                resources = stmt.get("Resource", [])
                if isinstance(resources, str):
                    resources = [resources]
                condition = stmt.get("Condition", {})

                if effect != "Allow":
                    continue

                # Check for wildcard actions
                if "*" in actions or "iam:*" in actions:
                    issues.append(self._make_finding(
                        "iam_wildcard_actions", "critical",
                        f"Policy '{policy_name}' grants wildcard actions.",
                        "Replace wildcard actions with specific least-privilege permissions.",
                        policy_arn,
                    ))

                # Check for wildcard resources with sensitive actions
                if "*" in resources:
                    dangerous = [a for a in actions if a in DANGEROUS_IAM_ACTIONS]
                    if dangerous:
                        issues.append(self._make_finding(
                            "iam_dangerous_wildcard", "critical",
                            f"Policy '{policy_name}' grants {', '.join(dangerous[:3])} on all resources.",
                            "Scope Resource to specific ARNs.",
                            policy_arn,
                        ))

                # Check for privilege escalation paths
                priv_esc = [a for a in actions if a in PRIVILEGED_ACTIONS]
                if priv_esc and not condition:
                    issues.append(self._make_finding(
                        "iam_privilege_escalation_risk", "high",
                        f"Policy '{policy_name}' allows privilege escalation via "
                        f"{', '.join(priv_esc[:3])} without conditions.",
                        "Add conditions (e.g., MFA, source IP) to limit privilege escalation.",
                        policy_arn,
                    ))

                # Check for missing MFA condition on sensitive actions
                sensitive = [a for a in actions if a.startswith("iam:") or a.startswith("sts:")]
                if sensitive and not condition.get("Bool", {}).get("aws:MultiFactorAuthPresent"):
                    issues.append(self._make_finding(
                        "iam_no_mfa_condition", "medium",
                        f"Policy '{policy_name}' does not require MFA for IAM/STS actions.",
                        "Add aws:MultiFactorAuthPresent condition.",
                        policy_arn,
                    ))

        # Analyse roles
        for role in roles:
            role_name = role.get("role_name", "unnamed")
            role_arn = role.get("arn", "unknown")
            analysed_count += 1

            # Check assume role policy trust
            trust = role.get("assume_role_policy", {})
            trust_statements = trust.get("Statement", [])
            for stmt in trust_statements:
                principal = stmt.get("Principal", {})

                # Check for wildcard principal
                if principal == "*" or principal.get("AWS") == "*":
                    issues.append(self._make_finding(
                        "iam_role_wildcard_trust", "critical",
                        f"Role '{role_name}' trusts all AWS principals.",
                        "Restrict the trust policy to specific accounts or services.",
                        role_arn,
                    ))

                # Check for cross-account trust without external ID
                aws_principals = principal.get("AWS", [])
                if isinstance(aws_principals, str):
                    aws_principals = [aws_principals]
                condition = stmt.get("Condition", {})
                if aws_principals and not condition.get("StringEquals", {}).get("sts:ExternalId"):
                    for p in aws_principals:
                        if ":root" in str(p):
                            issues.append(self._make_finding(
                                "iam_cross_account_no_external_id", "medium",
                                f"Role '{role_name}' allows cross-account access without ExternalId.",
                                "Add sts:ExternalId condition to prevent confused deputy attacks.",
                                role_arn,
                            ))
                            break

            # Check max session duration
            max_session = role.get("max_session_duration", 3600)
            if max_session > 43200:  # 12 hours
                issues.append(self._make_finding(
                    "iam_long_session", "low",
                    f"Role '{role_name}' allows sessions up to {max_session // 3600}h.",
                    "Reduce max session duration to 1-4 hours.",
                    role_arn,
                ))

        # Emit intelligence for critical IAM findings
        packets: List[IntelligencePacket] = []
        critical_findings = [i for i in issues if i["severity"] == "critical"]
        if critical_findings:
            packets.append(
                IntelligencePacket(
                    packet_id=f"PKT-IAM-{uuid.uuid4().hex[:8]}",
                    source_agent=self.agent_id,
                    target_agents=["all"],
                    intelligence_type=IntelligenceType.VULNERABILITY,
                    priority=Priority.CRITICAL,
                    confidence=90.0,
                    timestamp=datetime.now(timezone.utc),
                    data={
                        "finding_type": "iam_critical_misconfiguration",
                        "critical_count": len(critical_findings),
                        "examples": [f["title"] for f in critical_findings[:3]],
                    },
                    correlation_keys=["iam_audit", "privilege_escalation"],
                )
            )

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "policies_analysed": len(policies),
                "roles_analysed": len(roles),
                "total_analysed": analysed_count,
                "issues_found": len(issues),
                "critical_count": len(critical_findings),
                "issues": issues,
            },
            intelligence_packets=packets,
        )

    # =====================================================================
    # check_s3_exposure
    # =====================================================================

    async def _check_s3_exposure(self, params: Dict[str, Any]) -> SkillResult:
        """Check S3 buckets for public exposure, encryption, and logging."""
        buckets = params.get("buckets", [])

        if not buckets:
            return SkillResult(
                success=False,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                errors=["'buckets' list is required and must not be empty."],
            )

        issues: List[Dict[str, Any]] = []
        secure_buckets: List[str] = []

        for bucket in buckets:
            bucket_name = bucket.get("name", "unknown")
            bucket_arn = f"arn:aws:s3:::{bucket_name}"
            bucket_issues = []

            # Public access block
            pab = bucket.get("public_access_block", {})
            if not all([
                pab.get("block_public_acls", False),
                pab.get("block_public_policy", False),
                pab.get("ignore_public_acls", False),
                pab.get("restrict_public_buckets", False),
            ]):
                bucket_issues.append(self._make_finding(
                    "s3_public_access_not_blocked", "critical",
                    f"Bucket '{bucket_name}' does not have full public access block enabled.",
                    "Enable all four public access block settings.",
                    bucket_arn,
                ))

            # Encryption
            encryption = bucket.get("encryption", {})
            sse_algorithm = encryption.get("sse_algorithm")
            if not sse_algorithm:
                bucket_issues.append(self._make_finding(
                    "s3_no_encryption", "high",
                    f"Bucket '{bucket_name}' does not have default encryption enabled.",
                    "Enable SSE-S3 (AES-256) or SSE-KMS encryption.",
                    bucket_arn,
                ))
            elif sse_algorithm == "AES256" and bucket.get("contains_sensitive_data", False):
                bucket_issues.append(self._make_finding(
                    "s3_weak_encryption", "medium",
                    f"Bucket '{bucket_name}' uses SSE-S3 for sensitive data; SSE-KMS preferred.",
                    "Upgrade to SSE-KMS with a customer-managed key for sensitive data.",
                    bucket_arn,
                ))

            # Versioning
            if not bucket.get("versioning_enabled", False):
                bucket_issues.append(self._make_finding(
                    "s3_no_versioning", "medium",
                    f"Bucket '{bucket_name}' does not have versioning enabled.",
                    "Enable versioning for data protection and recovery.",
                    bucket_arn,
                ))

            # Logging
            if not bucket.get("logging_enabled", False):
                bucket_issues.append(self._make_finding(
                    "s3_no_access_logging", "medium",
                    f"Bucket '{bucket_name}' does not have access logging enabled.",
                    "Enable server access logging or use CloudTrail data events.",
                    bucket_arn,
                ))

            # Lifecycle rules
            if not bucket.get("lifecycle_rules", []):
                bucket_issues.append(self._make_finding(
                    "s3_no_lifecycle", "low",
                    f"Bucket '{bucket_name}' has no lifecycle rules configured.",
                    "Add lifecycle rules for cost optimisation and data retention.",
                    bucket_arn,
                ))

            # Bucket policy checks
            policy = bucket.get("policy", {})
            if policy:
                for stmt in policy.get("Statement", []):
                    principal = stmt.get("Principal", "")
                    if principal == "*" and stmt.get("Effect") == "Allow":
                        condition = stmt.get("Condition", {})
                        if not condition:
                            bucket_issues.append(self._make_finding(
                                "s3_public_policy", "critical",
                                f"Bucket '{bucket_name}' has a policy granting public access.",
                                "Remove or restrict the wildcard principal in the bucket policy.",
                                bucket_arn,
                            ))

            if bucket_issues:
                issues.extend(bucket_issues)
            else:
                secure_buckets.append(bucket_name)

            self.assessed_resources[bucket_arn] = {
                "type": "s3_bucket", "assessed_at": datetime.now(timezone.utc).isoformat(),
            }

        # Intelligence for public buckets
        packets: List[IntelligencePacket] = []
        public_issues = [i for i in issues if "public" in i.get("finding_type", "")]
        if public_issues:
            packets.append(
                IntelligencePacket(
                    packet_id=f"PKT-S3-{uuid.uuid4().hex[:8]}",
                    source_agent=self.agent_id,
                    target_agents=["all"],
                    intelligence_type=IntelligenceType.VULNERABILITY,
                    priority=Priority.CRITICAL,
                    confidence=95.0,
                    timestamp=datetime.now(timezone.utc),
                    data={
                        "finding_type": "s3_public_exposure",
                        "affected_buckets": len(public_issues),
                    },
                    correlation_keys=["s3_exposure", "data_leak_risk"],
                )
            )

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "buckets_assessed": len(buckets),
                "secure_buckets": secure_buckets,
                "issues_found": len(issues),
                "issues": issues,
            },
            intelligence_packets=packets,
        )

    # =====================================================================
    # scan_security_groups
    # =====================================================================

    async def _scan_security_groups(self, params: Dict[str, Any]) -> SkillResult:
        """Validate security group rules for overly permissive access."""
        security_groups = params.get("security_groups", [])

        if not security_groups:
            return SkillResult(
                success=False,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                errors=["'security_groups' list is required and must not be empty."],
            )

        issues: List[Dict[str, Any]] = []
        clean_groups: List[str] = []

        for sg in security_groups:
            sg_id = sg.get("group_id", "unknown")
            sg_name = sg.get("group_name", sg_id)
            sg_issues = []

            # Check ingress rules
            for rule in sg.get("ingress_rules", []):
                cidr = rule.get("cidr", "")
                from_port = rule.get("from_port", 0)
                to_port = rule.get("to_port", 65535)
                protocol = rule.get("protocol", "tcp")

                # Open to the world
                if cidr in ("0.0.0.0/0", "::/0"):
                    if from_port == 0 and to_port == 65535:
                        sg_issues.append(self._make_finding(
                            "sg_all_ports_open", "critical",
                            f"Security group '{sg_name}' ({sg_id}) allows all {protocol} "
                            f"ports from {cidr}.",
                            "Restrict to specific ports and source CIDR ranges.",
                            sg_id,
                        ))
                    else:
                        # Check specific dangerous ports
                        exposed_dangerous = set()
                        for port in range(from_port, min(to_port + 1, from_port + 100)):
                            if port in DANGEROUS_PORTS:
                                exposed_dangerous.add(port)

                        if exposed_dangerous:
                            sg_issues.append(self._make_finding(
                                "sg_dangerous_port_exposed", "high",
                                f"Security group '{sg_name}' ({sg_id}) exposes "
                                f"port(s) {sorted(exposed_dangerous)} to {cidr}.",
                                f"Restrict access to ports {sorted(exposed_dangerous)} "
                                f"to known source IPs or VPN CIDR.",
                                sg_id,
                            ))

                # Overly broad CIDR
                if cidr and cidr not in ("0.0.0.0/0", "::/0"):
                    try:
                        net = ipaddress.ip_network(cidr, strict=False)
                        if net.prefixlen < 16:
                            sg_issues.append(self._make_finding(
                                "sg_broad_cidr", "medium",
                                f"Security group '{sg_name}' ({sg_id}) allows ingress from "
                                f"broad CIDR {cidr} (/{net.prefixlen}).",
                                "Narrow the CIDR range to the minimum required.",
                                sg_id,
                            ))
                    except ValueError:
                        pass

            # Check egress rules
            for rule in sg.get("egress_rules", []):
                cidr = rule.get("cidr", "")
                from_port = rule.get("from_port", 0)
                to_port = rule.get("to_port", 65535)
                if cidr in ("0.0.0.0/0", "::/0") and from_port == 0 and to_port == 65535:
                    sg_issues.append(self._make_finding(
                        "sg_unrestricted_egress", "medium",
                        f"Security group '{sg_name}' ({sg_id}) allows unrestricted outbound traffic.",
                        "Restrict egress to required destinations and ports for defence-in-depth.",
                        sg_id,
                    ))

            # Check for description
            if not sg.get("description"):
                sg_issues.append(self._make_finding(
                    "sg_no_description", "low",
                    f"Security group '{sg_name}' ({sg_id}) has no description.",
                    "Add a description documenting the security group's purpose.",
                    sg_id,
                ))

            if sg_issues:
                issues.extend(sg_issues)
            else:
                clean_groups.append(sg_id)

            self.assessed_resources[sg_id] = {
                "type": "security_group",
                "assessed_at": datetime.now(timezone.utc).isoformat(),
            }

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "groups_assessed": len(security_groups),
                "clean_groups": clean_groups,
                "issues_found": len(issues),
                "issues": issues,
            },
        )

    # =====================================================================
    # evaluate_encryption
    # =====================================================================

    async def _evaluate_encryption(self, params: Dict[str, Any]) -> SkillResult:
        """Assess encryption at rest and in transit for AWS resources."""
        resources = params.get("resources", [])

        if not resources:
            return SkillResult(
                success=False,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                errors=["'resources' list is required and must not be empty."],
            )

        issues: List[Dict[str, Any]] = []
        compliant: List[str] = []

        for res in resources:
            res_id = res.get("resource_id", "unknown")
            res_type = res.get("resource_type", "unknown")
            res_issues = []

            # Encryption at rest
            at_rest = res.get("encryption_at_rest", {})
            if not at_rest.get("enabled", False):
                res_issues.append(self._make_finding(
                    "encryption_at_rest_disabled", "high",
                    f"{res_type} '{res_id}' does not have encryption at rest enabled.",
                    "Enable encryption at rest using KMS (preferably customer-managed key).",
                    res_id,
                ))
            else:
                kms_type = at_rest.get("kms_type", "aws_managed")
                if kms_type == "aws_managed" and res.get("contains_sensitive_data", False):
                    res_issues.append(self._make_finding(
                        "encryption_aws_managed_key", "medium",
                        f"{res_type} '{res_id}' uses AWS-managed keys for sensitive data.",
                        "Switch to a customer-managed KMS key for granular access control.",
                        res_id,
                    ))
                key_rotation = at_rest.get("key_rotation_enabled", False)
                if not key_rotation:
                    res_issues.append(self._make_finding(
                        "encryption_no_key_rotation", "medium",
                        f"{res_type} '{res_id}' does not have KMS key rotation enabled.",
                        "Enable automatic key rotation for the KMS key.",
                        res_id,
                    ))

            # Encryption in transit
            in_transit = res.get("encryption_in_transit", {})
            if not in_transit.get("enforced", False):
                res_issues.append(self._make_finding(
                    "encryption_in_transit_not_enforced", "high",
                    f"{res_type} '{res_id}' does not enforce encryption in transit.",
                    "Enforce TLS for all connections (e.g., S3 bucket policy with aws:SecureTransport).",
                    res_id,
                ))
            else:
                tls_version = in_transit.get("minimum_tls_version", "")
                if tls_version and tls_version < "1.2":
                    res_issues.append(self._make_finding(
                        "encryption_weak_tls", "high",
                        f"{res_type} '{res_id}' allows TLS versions below 1.2.",
                        "Set minimum TLS version to 1.2.",
                        res_id,
                    ))

            if res_issues:
                issues.extend(res_issues)
            else:
                compliant.append(res_id)

            self.assessed_resources[res_id] = {
                "type": res_type,
                "assessed_at": datetime.now(timezone.utc).isoformat(),
            }

        encryption_score = (
            round(len(compliant) / len(resources) * 100, 1) if resources else 0.0
        )

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "resources_assessed": len(resources),
                "compliant_resources": compliant,
                "encryption_compliance_score": encryption_score,
                "issues_found": len(issues),
                "issues": issues,
            },
        )

    # =====================================================================
    # generate_findings
    # =====================================================================

    async def _generate_findings(self, params: Dict[str, Any]) -> SkillResult:
        """Generate a consolidated findings report from all assessments."""
        severity_filter = params.get("severity")
        resource_filter = params.get("resource_type")
        limit = params.get("limit", 100)

        findings = list(self.findings)

        if severity_filter:
            findings = [f for f in findings if f.get("severity") == severity_filter]
        if resource_filter:
            findings = [
                f for f in findings
                if resource_filter in f.get("resource_id", "")
                or resource_filter in f.get("finding_type", "")
            ]

        # Severity distribution
        severity_dist: Dict[str, int] = defaultdict(int)
        for f in findings:
            severity_dist[f.get("severity", "medium")] += 1

        # Category distribution
        category_dist: Dict[str, int] = defaultdict(int)
        for f in findings:
            ftype = f.get("finding_type", "unknown")
            category = ftype.split("_")[0] if "_" in ftype else ftype
            category_dist[category] += 1

        # Risk score: weighted sum
        weights = {"critical": 10, "high": 5, "medium": 2, "low": 1}
        risk_score = sum(
            weights.get(f.get("severity", "medium"), 2) for f in findings
        )
        max_risk = len(findings) * 10 if findings else 1
        normalised_risk = min(round((risk_score / max_risk) * 100, 1), 100.0)

        overall_posture = "critical" if normalised_risk >= 70 else (
            "poor" if normalised_risk >= 40 else (
                "fair" if normalised_risk >= 15 else "good"
            )
        )

        # Top recommendations
        recommendations = []
        if severity_dist.get("critical", 0) > 0:
            recommendations.append(
                f"Address {severity_dist['critical']} critical finding(s) immediately."
            )
        if severity_dist.get("high", 0) > 0:
            recommendations.append(
                f"Remediate {severity_dist['high']} high-severity finding(s) within 24 hours."
            )
        if not self.findings:
            recommendations.append(
                "No findings recorded. Run individual assessments first "
                "(assess_vpc, audit_iam, check_s3_exposure, scan_security_groups, evaluate_encryption)."
            )

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "total_findings": len(findings),
                "returned": min(limit, len(findings)),
                "findings": findings[-limit:],
                "severity_distribution": dict(severity_dist),
                "category_distribution": dict(category_dist),
                "risk_score": normalised_risk,
                "overall_posture": overall_posture,
                "resources_assessed": len(self.assessed_resources),
                "recommendations": recommendations,
            },
        )

    # =====================================================================
    # Internal helpers
    # =====================================================================

    def _make_finding(
        self,
        finding_type: str,
        severity: str,
        title: str,
        remediation: str,
        resource_id: str,
    ) -> Dict[str, Any]:
        """Create a standardised finding and store it."""
        self.finding_counter += 1
        finding = {
            "finding_id": f"AWS-{self.finding_counter:04d}",
            "finding_type": finding_type,
            "severity": severity,
            "title": title,
            "remediation": remediation,
            "resource_id": resource_id,
            "detected_at": datetime.now(timezone.utc).isoformat(),
            "status": "open",
        }
        self.findings.append(finding)

        # Keep bounded
        if len(self.findings) > 5000:
            self.findings = self.findings[-5000:]

        return finding
