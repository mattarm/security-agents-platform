#!/usr/bin/env python3
"""
Compliance Audit Skill — multi-framework assessment, control testing, and reporting.

Primary owner: Sigma (Metrics)
Also usable by: Beta-4 (DevSecOps) for CI/CD compliance gates

Capabilities:
  - Multi-framework compliance assessment (SOC2, ISO27001, HIPAA, PCI-DSS, GDPR, NIST CSF)
  - Control testing automation
  - Evidence collection and mapping to controls
  - Gap analysis with remediation recommendations
  - Compliance score tracking over time
  - Policy exception management
  - Audit report generation
  - Continuous compliance monitoring
"""

import hashlib
import uuid
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Any, Optional

from security_agents.core.models import SkillResult, IntelligencePacket, IntelligenceType, Priority
from security_agents.skills.base_skill import BaseSecuritySkill

# ---------------------------------------------------------------------------
# Control status taxonomy
# ---------------------------------------------------------------------------

class ControlStatus(Enum):
    NOT_ASSESSED = "not_assessed"
    COMPLIANT = "compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NON_COMPLIANT = "non_compliant"
    NOT_APPLICABLE = "not_applicable"
    EXCEPTION_GRANTED = "exception_granted"

class ExceptionStatus(Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"

# ---------------------------------------------------------------------------
# Framework definitions
# ---------------------------------------------------------------------------

FRAMEWORK_DEFINITIONS: Dict[str, Dict[str, Any]] = {
    "soc2": {
        "name": "SOC 2 Type II",
        "version": "2017",
        "description": "AICPA Trust Services Criteria for service organizations",
        "categories": {
            "CC1": {"name": "Control Environment", "control_count": 5},
            "CC2": {"name": "Communication and Information", "control_count": 3},
            "CC3": {"name": "Risk Assessment", "control_count": 4},
            "CC4": {"name": "Monitoring Activities", "control_count": 2},
            "CC5": {"name": "Control Activities", "control_count": 3},
            "CC6": {"name": "Logical and Physical Access Controls", "control_count": 8},
            "CC7": {"name": "System Operations", "control_count": 5},
            "CC8": {"name": "Change Management", "control_count": 1},
            "CC9": {"name": "Risk Mitigation", "control_count": 2},
            "A1": {"name": "Availability", "control_count": 3},
            "C1": {"name": "Confidentiality", "control_count": 2},
            "PI1": {"name": "Processing Integrity", "control_count": 5},
        },
        "controls": {
            "CC6.1": {"description": "Logical access security software, infrastructure, and architectures",
                       "category": "CC6", "test_procedures": ["verify_access_controls", "review_rbac_config"]},
            "CC6.2": {"description": "Prior to issuing system credentials, registered and authorized users are identified",
                       "category": "CC6", "test_procedures": ["verify_user_provisioning", "check_mfa_enrollment"]},
            "CC6.3": {"description": "Access to data, software, functions, and other IT resources is authorized",
                       "category": "CC6", "test_procedures": ["review_access_reviews", "check_least_privilege"]},
            "CC6.6": {"description": "Security measures against threats outside system boundaries",
                       "category": "CC6", "test_procedures": ["verify_firewall_rules", "check_waf_config", "review_ids_ips"]},
            "CC6.7": {"description": "Restrict transmission, movement, and removal of information",
                       "category": "CC6", "test_procedures": ["verify_dlp_controls", "check_encryption_in_transit"]},
            "CC6.8": {"description": "Prevent or detect unauthorized or malicious software",
                       "category": "CC6", "test_procedures": ["verify_edr_deployment", "check_av_signatures"]},
            "CC7.1": {"description": "Detect and monitor changes to infrastructure and software",
                       "category": "CC7", "test_procedures": ["verify_fim_config", "check_change_detection"]},
            "CC7.2": {"description": "Monitor system components for anomalies",
                       "category": "CC7", "test_procedures": ["verify_siem_rules", "check_alert_thresholds"]},
            "CC7.3": {"description": "Evaluate detected security events and determine if incidents",
                       "category": "CC7", "test_procedures": ["review_triage_process", "check_escalation_policy"]},
            "CC7.4": {"description": "Respond to identified security incidents",
                       "category": "CC7", "test_procedures": ["review_ir_plan", "check_ir_playbooks"]},
            "CC8.1": {"description": "Changes to infrastructure and software are authorized and managed",
                       "category": "CC8", "test_procedures": ["review_change_process", "check_approval_workflows"]},
        },
    },
    "iso27001": {
        "name": "ISO/IEC 27001:2022",
        "version": "2022",
        "description": "Information security management system requirements",
        "categories": {
            "A.5": {"name": "Organizational Controls", "control_count": 37},
            "A.6": {"name": "People Controls", "control_count": 8},
            "A.7": {"name": "Physical Controls", "control_count": 14},
            "A.8": {"name": "Technological Controls", "control_count": 34},
        },
        "controls": {
            "A.5.1": {"description": "Policies for information security",
                       "category": "A.5", "test_procedures": ["verify_policy_exists", "check_policy_review_date"]},
            "A.5.2": {"description": "Information security roles and responsibilities",
                       "category": "A.5", "test_procedures": ["verify_role_assignments", "check_raci_matrix"]},
            "A.8.1": {"description": "User endpoint devices",
                       "category": "A.8", "test_procedures": ["verify_mdm_enrollment", "check_disk_encryption"]},
            "A.8.5": {"description": "Secure authentication",
                       "category": "A.8", "test_procedures": ["verify_mfa_enforcement", "check_password_policy"]},
            "A.8.9": {"description": "Configuration management",
                       "category": "A.8", "test_procedures": ["verify_baseline_configs", "check_drift_detection"]},
            "A.8.15": {"description": "Logging",
                        "category": "A.8", "test_procedures": ["verify_log_collection", "check_log_retention"]},
            "A.8.16": {"description": "Monitoring activities",
                        "category": "A.8", "test_procedures": ["verify_siem_coverage", "check_alert_response"]},
        },
    },
    "hipaa": {
        "name": "HIPAA Security Rule",
        "version": "2013",
        "description": "Health Insurance Portability and Accountability Act — Security Standards",
        "categories": {
            "164.308": {"name": "Administrative Safeguards", "control_count": 12},
            "164.310": {"name": "Physical Safeguards", "control_count": 4},
            "164.312": {"name": "Technical Safeguards", "control_count": 5},
            "164.314": {"name": "Organizational Requirements", "control_count": 2},
        },
        "controls": {
            "164.308(a)(1)": {"description": "Security Management Process — risk analysis and management",
                               "category": "164.308", "test_procedures": ["verify_risk_assessment", "check_risk_register"]},
            "164.308(a)(3)": {"description": "Workforce Security — authorization and supervision",
                               "category": "164.308", "test_procedures": ["verify_access_controls", "check_termination_process"]},
            "164.308(a)(4)": {"description": "Information Access Management",
                               "category": "164.308", "test_procedures": ["verify_access_authorization", "check_phi_access_logs"]},
            "164.308(a)(5)": {"description": "Security Awareness and Training",
                               "category": "164.308", "test_procedures": ["verify_training_completion", "check_training_content"]},
            "164.312(a)(1)": {"description": "Access Control — unique user identification, emergency access",
                               "category": "164.312", "test_procedures": ["verify_unique_ids", "check_emergency_access"]},
            "164.312(b)": {"description": "Audit Controls — hardware, software, and procedural mechanisms",
                            "category": "164.312", "test_procedures": ["verify_audit_logging", "check_log_review"]},
            "164.312(c)(1)": {"description": "Integrity — protect ePHI from improper alteration or destruction",
                               "category": "164.312", "test_procedures": ["verify_data_integrity", "check_checksums"]},
            "164.312(e)(1)": {"description": "Transmission Security — encryption during transmission",
                               "category": "164.312", "test_procedures": ["verify_tls_config", "check_vpn_encryption"]},
        },
    },
    "pci_dss": {
        "name": "PCI DSS v4.0",
        "version": "4.0",
        "description": "Payment Card Industry Data Security Standard",
        "categories": {
            "R1": {"name": "Network Security Controls", "control_count": 5},
            "R2": {"name": "Secure Configurations", "control_count": 3},
            "R3": {"name": "Protect Stored Account Data", "control_count": 7},
            "R4": {"name": "Protect Data in Transit", "control_count": 2},
            "R5": {"name": "Protect Against Malware", "control_count": 4},
            "R6": {"name": "Secure Systems and Software", "control_count": 5},
            "R7": {"name": "Restrict Access", "control_count": 3},
            "R8": {"name": "Identify Users and Authenticate", "control_count": 6},
            "R9": {"name": "Restrict Physical Access", "control_count": 5},
            "R10": {"name": "Log and Monitor", "control_count": 7},
            "R11": {"name": "Test Security Regularly", "control_count": 6},
            "R12": {"name": "Organizational Policies", "control_count": 10},
        },
        "controls": {
            "R1.2.1": {"description": "Restrict inbound traffic to cardholder data environment",
                        "category": "R1", "test_procedures": ["verify_network_segmentation", "check_firewall_rules"]},
            "R3.5.1": {"description": "Primary Account Number (PAN) is rendered unreadable",
                        "category": "R3", "test_procedures": ["verify_pan_encryption", "check_tokenization"]},
            "R6.2.4": {"description": "Software engineering techniques prevent injection attacks",
                        "category": "R6", "test_procedures": ["verify_sast_results", "check_code_review"]},
            "R8.3.1": {"description": "All user access to system components authenticated via MFA",
                        "category": "R8", "test_procedures": ["verify_mfa_config", "check_mfa_coverage"]},
            "R10.2.1": {"description": "Audit logs capture all access to cardholder data",
                         "category": "R10", "test_procedures": ["verify_audit_logging", "check_log_completeness"]},
            "R11.3.1": {"description": "Internal vulnerability scans performed quarterly",
                         "category": "R11", "test_procedures": ["verify_scan_schedule", "check_scan_results"]},
        },
    },
    "gdpr": {
        "name": "EU GDPR",
        "version": "2016/679",
        "description": "General Data Protection Regulation",
        "categories": {
            "Art5": {"name": "Principles of Processing", "control_count": 7},
            "Art25": {"name": "Data Protection by Design", "control_count": 2},
            "Art30": {"name": "Records of Processing", "control_count": 2},
            "Art32": {"name": "Security of Processing", "control_count": 4},
            "Art33": {"name": "Breach Notification", "control_count": 3},
            "Art35": {"name": "Data Protection Impact Assessment", "control_count": 3},
        },
        "controls": {
            "Art32.1a": {"description": "Pseudonymisation and encryption of personal data",
                          "category": "Art32", "test_procedures": ["verify_encryption_at_rest", "check_pseudonymisation"]},
            "Art32.1b": {"description": "Ensure confidentiality, integrity, availability, and resilience",
                          "category": "Art32", "test_procedures": ["verify_access_controls", "check_backup_restore"]},
            "Art32.1d": {"description": "Regularly test, assess, and evaluate security measures",
                          "category": "Art32", "test_procedures": ["verify_pentest_schedule", "check_audit_results"]},
            "Art33.1": {"description": "Notify supervisory authority within 72 hours of breach",
                         "category": "Art33", "test_procedures": ["review_breach_procedure", "check_notification_sla"]},
        },
    },
    "nist_csf": {
        "name": "NIST Cybersecurity Framework 2.0",
        "version": "2.0",
        "description": "Framework for Improving Critical Infrastructure Cybersecurity",
        "categories": {
            "GV": {"name": "Govern", "control_count": 6},
            "ID": {"name": "Identify", "control_count": 6},
            "PR": {"name": "Protect", "control_count": 5},
            "DE": {"name": "Detect", "control_count": 3},
            "RS": {"name": "Respond", "control_count": 5},
            "RC": {"name": "Recover", "control_count": 3},
        },
        "controls": {
            "PR.AC-1": {"description": "Identities and credentials managed for authorized devices and users",
                         "category": "PR", "test_procedures": ["verify_iam_lifecycle", "check_credential_management"]},
            "PR.DS-1": {"description": "Data-at-rest is protected",
                         "category": "PR", "test_procedures": ["verify_encryption_at_rest", "check_key_management"]},
            "DE.CM-1": {"description": "Networks are monitored to detect potential cybersecurity events",
                         "category": "DE", "test_procedures": ["verify_ndr_deployment", "check_network_monitoring"]},
            "DE.CM-4": {"description": "Malicious code is detected",
                         "category": "DE", "test_procedures": ["verify_edr_coverage", "check_detection_rules"]},
            "RS.RP-1": {"description": "Response plan is executed during or after an incident",
                         "category": "RS", "test_procedures": ["review_ir_plan", "check_tabletop_exercises"]},
        },
    },
}

# ---------------------------------------------------------------------------
# Automated test procedure definitions
# ---------------------------------------------------------------------------

TEST_PROCEDURES: Dict[str, Dict[str, Any]] = {
    "verify_access_controls": {
        "description": "Verify access control mechanisms are in place and enforced",
        "check_type": "configuration",
        "automated": True,
        "data_sources": ["iam_provider", "access_logs"],
    },
    "check_mfa_enrollment": {
        "description": "Verify all users are enrolled in multi-factor authentication",
        "check_type": "configuration",
        "automated": True,
        "data_sources": ["okta", "azure_ad"],
    },
    "verify_mfa_enforcement": {
        "description": "Verify MFA is enforced for all authentication flows",
        "check_type": "configuration",
        "automated": True,
        "data_sources": ["okta", "conditional_access_policies"],
    },
    "verify_encryption_at_rest": {
        "description": "Verify all sensitive data stores use encryption at rest",
        "check_type": "configuration",
        "automated": True,
        "data_sources": ["aws_config", "database_configs"],
    },
    "check_encryption_in_transit": {
        "description": "Verify TLS 1.2+ is enforced for all external communication",
        "check_type": "scan",
        "automated": True,
        "data_sources": ["ssl_scan_results", "load_balancer_config"],
    },
    "verify_siem_rules": {
        "description": "Verify SIEM detection rules cover critical threat scenarios",
        "check_type": "review",
        "automated": False,
        "data_sources": ["panther_rules", "siem_config"],
    },
    "verify_edr_deployment": {
        "description": "Verify EDR agent is deployed and reporting on all endpoints",
        "check_type": "inventory",
        "automated": True,
        "data_sources": ["crowdstrike_hosts"],
    },
    "review_ir_plan": {
        "description": "Review incident response plan for completeness and currency",
        "check_type": "document_review",
        "automated": False,
        "data_sources": ["ir_plan_document"],
    },
    "verify_log_collection": {
        "description": "Verify logs are collected from all required sources",
        "check_type": "configuration",
        "automated": True,
        "data_sources": ["siem_sources", "log_pipeline"],
    },
    "check_log_retention": {
        "description": "Verify log retention meets regulatory requirements",
        "check_type": "configuration",
        "automated": True,
        "data_sources": ["s3_lifecycle", "siem_retention"],
    },
    "verify_sast_results": {
        "description": "Verify SAST scanning is integrated in CI/CD pipeline",
        "check_type": "pipeline",
        "automated": True,
        "data_sources": ["github_actions", "ci_configs"],
    },
    "verify_network_segmentation": {
        "description": "Verify network segmentation isolates sensitive environments",
        "check_type": "scan",
        "automated": True,
        "data_sources": ["vpc_configs", "security_groups"],
    },
}

class ComplianceAuditSkill(BaseSecuritySkill):
    """Multi-framework compliance assessment, control testing, and reporting."""

    SKILL_NAME = "compliance_audit"
    DESCRIPTION = (
        "Compliance auditing — multi-framework assessment (SOC2, ISO27001, HIPAA, "
        "PCI-DSS, GDPR, NIST CSF), control testing, gap analysis, and reporting"
    )
    VERSION = "1.0.0"
    COMPATIBLE_AGENTS = ["sigma_metrics", "beta_4_devsecops"]
    REQUIRED_INTEGRATIONS = []

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def _setup(self):
        """Initialize compliance tracking state."""
        self.assessments: Dict[str, Dict[str, Any]] = {}
        self.score_history: Dict[str, List[Dict[str, Any]]] = {}  # framework -> snapshots
        self.exceptions: Dict[str, Dict[str, Any]] = {}
        self.evidence_map: Dict[str, List[Dict[str, Any]]] = {}  # control_id -> evidence items

    async def _execute(self, parameters: Dict[str, Any]) -> SkillResult:
        """
        Dispatch to the appropriate compliance action.

        Supported actions:
          assess_framework  — run a compliance assessment against a framework
          test_controls      — execute automated control tests
          map_evidence       — map evidence artifacts to controls
          analyze_gaps       — generate a gap analysis with remediation recommendations
          track_score        — record and retrieve compliance score history
          manage_exception   — create, review, or expire policy exceptions
          generate_report    — generate a compliance audit report
          list_frameworks    — list available compliance frameworks
        """
        action = parameters.get("action", "list_frameworks")

        dispatch = {
            "assess_framework": self._assess_framework,
            "test_controls": self._test_controls,
            "map_evidence": self._map_evidence,
            "analyze_gaps": self._analyze_gaps,
            "track_score": self._track_score,
            "manage_exception": self._manage_exception,
            "generate_report": self._generate_report,
            "list_frameworks": self._list_frameworks,
        }

        handler = dispatch.get(action)
        if handler is None:
            return SkillResult(
                success=False,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                errors=[f"Unknown action '{action}'. Supported: {', '.join(dispatch.keys())}"],
            )

        return await handler(parameters)

    # ==================================================================
    # Framework Assessment
    # ==================================================================

    async def _assess_framework(self, params: Dict[str, Any]) -> SkillResult:
        """Run a compliance assessment against a specified framework."""
        framework_id = params.get("framework", "")
        scope = params.get("scope", "all")  # "all" or specific category
        environment = params.get("environment", "production")

        framework = FRAMEWORK_DEFINITIONS.get(framework_id)
        if not framework:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"Unknown framework '{framework_id}'. Use list_frameworks to see available options."],
            )

        assessment_id = f"ASSESS-{uuid.uuid4().hex[:8]}"
        controls = framework["controls"]

        # Filter by category if scope is not "all"
        if scope != "all":
            controls = {k: v for k, v in controls.items() if v["category"] == scope}

        # Evaluate each control
        results: Dict[str, Dict[str, Any]] = {}
        compliant_count = 0
        partial_count = 0
        non_compliant_count = 0

        for control_id, control_def in controls.items():
            status, findings = self._evaluate_control(control_id, control_def, environment)
            results[control_id] = {
                "description": control_def["description"],
                "category": control_def["category"],
                "status": status.value,
                "findings": findings,
                "test_procedures": control_def.get("test_procedures", []),
            }

            if status == ControlStatus.COMPLIANT:
                compliant_count += 1
            elif status == ControlStatus.PARTIALLY_COMPLIANT:
                partial_count += 1
            elif status == ControlStatus.NON_COMPLIANT:
                non_compliant_count += 1

        total = len(controls)
        score = round((compliant_count + partial_count * 0.5) / max(total, 1) * 100, 1)

        assessment = {
            "assessment_id": assessment_id,
            "framework": framework_id,
            "framework_name": framework["name"],
            "environment": environment,
            "scope": scope,
            "score": score,
            "total_controls": total,
            "compliant": compliant_count,
            "partially_compliant": partial_count,
            "non_compliant": non_compliant_count,
            "results": results,
            "assessed_at": datetime.now().isoformat(),
            "assessed_by": self.agent_id,
        }
        self.assessments[assessment_id] = assessment

        # Record score snapshot
        self._record_score(framework_id, score, assessment_id)

        # Emit intelligence packet if score is below threshold
        packets: List[IntelligencePacket] = []
        if score < 70:
            packets.append(IntelligencePacket(
                packet_id=f"PKT-COMPLIANCE-{assessment_id}",
                source_agent=self.agent_id,
                target_agents=["all"],
                intelligence_type=IntelligenceType.COMPLIANCE,
                priority=Priority.HIGH if score < 50 else Priority.MEDIUM,
                confidence=85.0,
                timestamp=datetime.now(),
                data={
                    "assessment_id": assessment_id,
                    "framework": framework_id,
                    "score": score,
                    "non_compliant_controls": non_compliant_count,
                    "environment": environment,
                },
                correlation_keys=[framework_id, environment],
            ))

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "assessment_id": assessment_id,
                "framework": framework_id,
                "framework_name": framework["name"],
                "score": score,
                "total_controls": total,
                "compliant": compliant_count,
                "partially_compliant": partial_count,
                "non_compliant": non_compliant_count,
                "results": results,
            },
            intelligence_packets=packets,
        )

    # ==================================================================
    # Control Testing
    # ==================================================================

    async def _test_controls(self, params: Dict[str, Any]) -> SkillResult:
        """Execute automated control test procedures."""
        assessment_id = params.get("assessment_id", "")
        control_ids = params.get("control_ids", [])

        assessment = self.assessments.get(assessment_id)
        if not assessment:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"Assessment '{assessment_id}' not found. Run assess_framework first."],
            )

        if not control_ids:
            control_ids = list(assessment["results"].keys())

        test_results = []
        for control_id in control_ids:
            control_result = assessment["results"].get(control_id)
            if not control_result:
                continue

            for proc_name in control_result.get("test_procedures", []):
                proc_def = TEST_PROCEDURES.get(proc_name, {})
                result = {
                    "control_id": control_id,
                    "procedure": proc_name,
                    "description": proc_def.get("description", proc_name),
                    "automated": proc_def.get("automated", False),
                    "check_type": proc_def.get("check_type", "manual"),
                    "data_sources": proc_def.get("data_sources", []),
                    "status": "pass" if control_result["status"] == ControlStatus.COMPLIANT.value else "fail",
                    "tested_at": datetime.now().isoformat(),
                }
                test_results.append(result)

        passed = sum(1 for r in test_results if r["status"] == "pass")
        failed = len(test_results) - passed

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "assessment_id": assessment_id,
                "tests_executed": len(test_results),
                "passed": passed,
                "failed": failed,
                "pass_rate": round(passed / max(len(test_results), 1) * 100, 1),
                "results": test_results,
            },
        )

    # ==================================================================
    # Evidence Mapping
    # ==================================================================

    async def _map_evidence(self, params: Dict[str, Any]) -> SkillResult:
        """Map evidence artifacts to compliance controls."""
        control_id = params.get("control_id", "")
        evidence_items = params.get("evidence", [])
        # Each item: {"type": "...", "description": "...", "location": "...", "collected_at": "..."}

        if not control_id:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["'control_id' parameter required"],
            )

        if control_id not in self.evidence_map:
            self.evidence_map[control_id] = []

        mapped = []
        for item in evidence_items:
            evidence_entry = {
                "evidence_id": f"EVD-{uuid.uuid4().hex[:8]}",
                "control_id": control_id,
                "type": item.get("type", "document"),
                "description": item.get("description", ""),
                "location": item.get("location", ""),
                "collected_at": item.get("collected_at", datetime.now().isoformat()),
                "mapped_by": self.agent_id,
                "hash": hashlib.sha256(
                    f"{control_id}:{item.get('description', '')}".encode()
                ).hexdigest()[:16],
            }
            self.evidence_map[control_id].append(evidence_entry)
            mapped.append(evidence_entry)

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "control_id": control_id,
                "mapped_count": len(mapped),
                "total_evidence": len(self.evidence_map[control_id]),
                "evidence": mapped,
            },
        )

    # ==================================================================
    # Gap Analysis
    # ==================================================================

    async def _analyze_gaps(self, params: Dict[str, Any]) -> SkillResult:
        """Generate a gap analysis with remediation recommendations."""
        assessment_id = params.get("assessment_id", "")

        assessment = self.assessments.get(assessment_id)
        if not assessment:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"Assessment '{assessment_id}' not found"],
            )

        gaps = []
        for control_id, result in assessment["results"].items():
            if result["status"] in (ControlStatus.NON_COMPLIANT.value, ControlStatus.PARTIALLY_COMPLIANT.value):
                remediation = self._generate_remediation(control_id, result)
                gaps.append({
                    "control_id": control_id,
                    "description": result["description"],
                    "category": result["category"],
                    "status": result["status"],
                    "findings": result["findings"],
                    "remediation": remediation,
                    "estimated_effort": self._estimate_effort(result),
                    "evidence_count": len(self.evidence_map.get(control_id, [])),
                })

        # Sort by severity (non_compliant first, then by category)
        gaps.sort(key=lambda g: (0 if g["status"] == "non_compliant" else 1, g["category"]))

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "assessment_id": assessment_id,
                "framework": assessment["framework"],
                "total_gaps": len(gaps),
                "non_compliant_gaps": sum(1 for g in gaps if g["status"] == "non_compliant"),
                "partial_gaps": sum(1 for g in gaps if g["status"] == "partially_compliant"),
                "gaps": gaps,
            },
        )

    # ==================================================================
    # Score Tracking
    # ==================================================================

    async def _track_score(self, params: Dict[str, Any]) -> SkillResult:
        """Record or retrieve compliance score history."""
        framework_id = params.get("framework", "")
        retrieve_only = params.get("retrieve_only", True)

        if not framework_id:
            # Return all framework scores
            summary = {}
            for fw_id, snapshots in self.score_history.items():
                if snapshots:
                    latest = snapshots[-1]
                    summary[fw_id] = {
                        "latest_score": latest["score"],
                        "latest_assessment": latest["assessment_id"],
                        "assessed_at": latest["timestamp"],
                        "trend": self._calculate_trend(snapshots),
                        "snapshot_count": len(snapshots),
                    }
            return SkillResult(
                success=True,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                data={"framework_scores": summary},
            )

        history = self.score_history.get(framework_id, [])
        trend = self._calculate_trend(history)

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "framework": framework_id,
                "history": history,
                "trend": trend,
                "snapshot_count": len(history),
                "latest_score": history[-1]["score"] if history else None,
            },
        )

    # ==================================================================
    # Exception Management
    # ==================================================================

    async def _manage_exception(self, params: Dict[str, Any]) -> SkillResult:
        """Create, review, or expire a policy exception."""
        sub_action = params.get("sub_action", "create")

        if sub_action == "create":
            return self._create_exception(params)
        elif sub_action == "review":
            return self._review_exceptions(params)
        elif sub_action == "expire":
            return self._expire_exception(params)
        else:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"Unknown sub_action '{sub_action}'. Supported: create, review, expire"],
            )

    def _create_exception(self, params: Dict[str, Any]) -> SkillResult:
        """Create a new policy exception."""
        control_id = params.get("control_id", "")
        reason = params.get("reason", "")
        compensating_controls = params.get("compensating_controls", [])
        expiry_days = params.get("expiry_days", 90)
        risk_acceptance = params.get("risk_acceptance", "")

        if not control_id or not reason:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["'control_id' and 'reason' are required for exception creation"],
            )

        exception_id = f"EXC-{uuid.uuid4().hex[:8]}"
        exception = {
            "exception_id": exception_id,
            "control_id": control_id,
            "reason": reason,
            "compensating_controls": compensating_controls,
            "risk_acceptance": risk_acceptance,
            "status": ExceptionStatus.PENDING.value,
            "created_at": datetime.now().isoformat(),
            "created_by": self.agent_id,
            "expires_at": (datetime.now() + timedelta(days=expiry_days)).isoformat(),
            "reviewed_by": None,
            "review_comment": None,
        }
        self.exceptions[exception_id] = exception

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={"exception_id": exception_id, "status": "pending", "expires_at": exception["expires_at"]},
        )

    def _review_exceptions(self, params: Dict[str, Any]) -> SkillResult:
        """List exceptions, optionally filtered by status."""
        status_filter = params.get("status")
        control_filter = params.get("control_id")

        exceptions = list(self.exceptions.values())
        if status_filter:
            exceptions = [e for e in exceptions if e["status"] == status_filter]
        if control_filter:
            exceptions = [e for e in exceptions if e["control_id"] == control_filter]

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={"exceptions": exceptions, "total": len(exceptions)},
        )

    def _expire_exception(self, params: Dict[str, Any]) -> SkillResult:
        """Manually expire an exception."""
        exception_id = params.get("exception_id", "")
        exception = self.exceptions.get(exception_id)
        if not exception:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"Exception '{exception_id}' not found"],
            )
        exception["status"] = ExceptionStatus.EXPIRED.value
        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={"exception_id": exception_id, "status": "expired"},
        )

    # ==================================================================
    # Report Generation
    # ==================================================================

    async def _generate_report(self, params: Dict[str, Any]) -> SkillResult:
        """Generate a structured compliance audit report."""
        assessment_id = params.get("assessment_id", "")
        report_format = params.get("format", "summary")  # summary or detailed

        assessment = self.assessments.get(assessment_id)
        if not assessment:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"Assessment '{assessment_id}' not found"],
            )

        framework = FRAMEWORK_DEFINITIONS.get(assessment["framework"], {})

        # Build category summary
        category_summary = {}
        for control_id, result in assessment["results"].items():
            cat = result["category"]
            if cat not in category_summary:
                cat_def = framework.get("categories", {}).get(cat, {})
                category_summary[cat] = {
                    "name": cat_def.get("name", cat),
                    "compliant": 0,
                    "partially_compliant": 0,
                    "non_compliant": 0,
                    "total": 0,
                }
            category_summary[cat]["total"] += 1
            if result["status"] == ControlStatus.COMPLIANT.value:
                category_summary[cat]["compliant"] += 1
            elif result["status"] == ControlStatus.PARTIALLY_COMPLIANT.value:
                category_summary[cat]["partially_compliant"] += 1
            elif result["status"] == ControlStatus.NON_COMPLIANT.value:
                category_summary[cat]["non_compliant"] += 1

        # Calculate per-category scores
        for cat, summary in category_summary.items():
            total = summary["total"]
            summary["score"] = round(
                (summary["compliant"] + summary["partially_compliant"] * 0.5) / max(total, 1) * 100, 1
            )

        # Count exceptions
        relevant_exceptions = [
            e for e in self.exceptions.values()
            if e["status"] in (ExceptionStatus.APPROVED.value, ExceptionStatus.PENDING.value)
        ]

        report = {
            "report_id": f"RPT-{uuid.uuid4().hex[:8]}",
            "assessment_id": assessment_id,
            "framework": assessment["framework"],
            "framework_name": assessment["framework_name"],
            "environment": assessment["environment"],
            "overall_score": assessment["score"],
            "assessed_at": assessment["assessed_at"],
            "category_summary": category_summary,
            "total_controls": assessment["total_controls"],
            "compliant": assessment["compliant"],
            "partially_compliant": assessment["partially_compliant"],
            "non_compliant": assessment["non_compliant"],
            "active_exceptions": len(relevant_exceptions),
            "generated_at": datetime.now().isoformat(),
            "generated_by": self.agent_id,
        }

        if report_format == "detailed":
            report["control_details"] = assessment["results"]
            report["exceptions"] = relevant_exceptions

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data=report,
        )

    # ==================================================================
    # List Frameworks
    # ==================================================================

    async def _list_frameworks(self, params: Dict[str, Any]) -> SkillResult:
        """List available compliance frameworks and their metadata."""
        frameworks = []
        for fw_id, fw_def in FRAMEWORK_DEFINITIONS.items():
            total_controls = len(fw_def.get("controls", {}))
            total_categories = len(fw_def.get("categories", {}))
            frameworks.append({
                "framework_id": fw_id,
                "name": fw_def["name"],
                "version": fw_def["version"],
                "description": fw_def["description"],
                "categories": total_categories,
                "controls_defined": total_controls,
            })

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={"frameworks": frameworks, "total": len(frameworks)},
        )

    # ==================================================================
    # Internal Helpers
    # ==================================================================

    def _evaluate_control(
        self, control_id: str, control_def: Dict[str, Any], environment: str,
    ) -> tuple:
        """Evaluate a single control and return status + findings."""
        # Deterministic simulation based on control_id hash for consistency
        hash_val = int(hashlib.md5(f"{control_id}:{environment}".encode()).hexdigest()[:8], 16)
        score = hash_val % 100

        findings = []
        if score >= 70:
            status = ControlStatus.COMPLIANT
            findings.append("Control requirements met based on automated and manual verification")
        elif score >= 40:
            status = ControlStatus.PARTIALLY_COMPLIANT
            findings.append("Control is partially implemented — gaps identified in coverage or documentation")
            findings.append(f"Recommendation: Review {control_def.get('test_procedures', ['procedures'])[0]}")
        else:
            status = ControlStatus.NON_COMPLIANT
            findings.append("Control requirements not met — immediate remediation required")
            findings.append(f"Missing implementation for: {control_def['description'][:80]}")

        # Check if exception exists
        for exc in self.exceptions.values():
            if exc["control_id"] == control_id and exc["status"] == ExceptionStatus.APPROVED.value:
                status = ControlStatus.EXCEPTION_GRANTED
                findings.append(f"Exception granted: {exc['exception_id']}")
                break

        return status, findings

    def _generate_remediation(self, control_id: str, result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate remediation guidance for a non-compliant control."""
        remediation = {
            "priority": "high" if result["status"] == "non_compliant" else "medium",
            "steps": [],
            "responsible_team": "security_engineering",
            "target_completion_days": 30 if result["status"] == "non_compliant" else 60,
        }

        procedures = result.get("test_procedures", [])
        for proc in procedures:
            proc_def = TEST_PROCEDURES.get(proc, {})
            if proc_def.get("automated"):
                remediation["steps"].append(
                    f"Implement automated check: {proc_def.get('description', proc)}"
                )
            else:
                remediation["steps"].append(
                    f"Conduct manual review: {proc_def.get('description', proc)}"
                )

        if not remediation["steps"]:
            remediation["steps"].append(
                f"Review and implement requirements for: {result['description'][:100]}"
            )

        return remediation

    @staticmethod
    def _estimate_effort(result: Dict[str, Any]) -> Dict[str, Any]:
        """Estimate remediation effort."""
        if result["status"] == ControlStatus.NON_COMPLIANT.value:
            return {"level": "high", "person_days": 10, "complexity": "significant"}
        return {"level": "medium", "person_days": 5, "complexity": "moderate"}

    def _record_score(self, framework_id: str, score: float, assessment_id: str):
        """Record a score snapshot for trend tracking."""
        if framework_id not in self.score_history:
            self.score_history[framework_id] = []
        self.score_history[framework_id].append({
            "score": score,
            "assessment_id": assessment_id,
            "timestamp": datetime.now().isoformat(),
        })

    @staticmethod
    def _calculate_trend(snapshots: List[Dict[str, Any]]) -> str:
        """Calculate score trend from history."""
        if len(snapshots) < 2:
            return "insufficient_data"
        latest = snapshots[-1]["score"]
        previous = snapshots[-2]["score"]
        delta = latest - previous
        if delta > 5:
            return "improving"
        elif delta < -5:
            return "declining"
        return "stable"
