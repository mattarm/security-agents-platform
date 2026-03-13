#!/usr/bin/env python3
"""
SIEM Rule Management Skill — Detection rule lifecycle and coverage analysis.

Primary owner: Gamma (Blue Team)

Capabilities:
  - Sigma rule format creation and validation
  - Rule syntax and logic validation
  - Detection coverage mapping to MITRE ATT&CK
  - False positive tuning with threshold adjustment
  - Rule lifecycle management (draft -> testing -> active -> deprecated)
  - Performance impact estimation
  - Coverage gap analysis and reporting
"""

import uuid
import re
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from enum import Enum

from security_agents.core.models import SkillResult, IntelligencePacket, IntelligenceType, Priority, Severity
from security_agents.skills.base_skill import BaseSecuritySkill

class RuleStatus(Enum):
    DRAFT = "draft"
    TESTING = "testing"
    ACTIVE = "active"
    DISABLED = "disabled"
    DEPRECATED = "deprecated"

class RuleLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

class LogSource(Enum):
    WINDOWS_SECURITY = "windows_security"
    WINDOWS_SYSMON = "windows_sysmon"
    WINDOWS_POWERSHELL = "windows_powershell"
    LINUX_AUDIT = "linux_audit"
    LINUX_SYSLOG = "linux_syslog"
    FIREWALL = "firewall"
    PROXY = "proxy"
    DNS = "dns"
    AWS_CLOUDTRAIL = "aws_cloudtrail"
    AZURE_ACTIVITY = "azure_activity"
    GCP_AUDIT = "gcp_audit"
    OKTA = "okta"
    NETWORK_FLOW = "network_flow"
    EDR = "edr"
    EMAIL_GATEWAY = "email_gateway"
    CUSTOM = "custom"

# ---------------------------------------------------------------------------
# MITRE ATT&CK technique-to-data-source mapping (representative subset)
# ---------------------------------------------------------------------------
MITRE_TECHNIQUE_MAP = {
    "T1059.001": {"name": "PowerShell", "tactic": "execution", "log_sources": ["windows_powershell", "windows_sysmon", "edr"]},
    "T1059.003": {"name": "Windows Command Shell", "tactic": "execution", "log_sources": ["windows_sysmon", "edr"]},
    "T1053.005": {"name": "Scheduled Task", "tactic": "persistence", "log_sources": ["windows_security", "windows_sysmon"]},
    "T1543.003": {"name": "Windows Service", "tactic": "persistence", "log_sources": ["windows_security", "windows_sysmon"]},
    "T1078": {"name": "Valid Accounts", "tactic": "initial_access", "log_sources": ["windows_security", "okta", "aws_cloudtrail"]},
    "T1110": {"name": "Brute Force", "tactic": "credential_access", "log_sources": ["windows_security", "okta", "linux_audit"]},
    "T1003": {"name": "OS Credential Dumping", "tactic": "credential_access", "log_sources": ["windows_sysmon", "edr"]},
    "T1021.001": {"name": "Remote Desktop Protocol", "tactic": "lateral_movement", "log_sources": ["windows_security", "network_flow"]},
    "T1021.002": {"name": "SMB/Windows Admin Shares", "tactic": "lateral_movement", "log_sources": ["windows_security", "network_flow"]},
    "T1071.001": {"name": "Web Protocols", "tactic": "command_and_control", "log_sources": ["proxy", "firewall", "network_flow"]},
    "T1071.004": {"name": "DNS", "tactic": "command_and_control", "log_sources": ["dns", "network_flow"]},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "exfiltration", "log_sources": ["firewall", "network_flow", "proxy"]},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "impact", "log_sources": ["edr", "windows_sysmon"]},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "initial_access", "log_sources": ["firewall", "proxy", "aws_cloudtrail"]},
    "T1566.001": {"name": "Spearphishing Attachment", "tactic": "initial_access", "log_sources": ["email_gateway", "edr"]},
    "T1566.002": {"name": "Spearphishing Link", "tactic": "initial_access", "log_sources": ["email_gateway", "proxy"]},
    "T1547.001": {"name": "Registry Run Keys", "tactic": "persistence", "log_sources": ["windows_sysmon", "edr"]},
    "T1055": {"name": "Process Injection", "tactic": "defense_evasion", "log_sources": ["windows_sysmon", "edr"]},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "defense_evasion", "log_sources": ["windows_sysmon", "edr"]},
    "T1087": {"name": "Account Discovery", "tactic": "discovery", "log_sources": ["windows_security", "windows_sysmon", "linux_audit"]},
    "T1082": {"name": "System Information Discovery", "tactic": "discovery", "log_sources": ["windows_sysmon", "edr"]},
    "T1560": {"name": "Archive Collected Data", "tactic": "collection", "log_sources": ["edr", "windows_sysmon"]},
    "T1098": {"name": "Account Manipulation", "tactic": "persistence", "log_sources": ["windows_security", "okta", "aws_cloudtrail", "azure_activity"]},
    "T1136": {"name": "Create Account", "tactic": "persistence", "log_sources": ["windows_security", "okta", "aws_cloudtrail"]},
}

# Required fields for a valid Sigma rule
SIGMA_REQUIRED_FIELDS = {"title", "logsource", "detection"}
SIGMA_OPTIONAL_FIELDS = {
    "id", "status", "description", "references", "author", "date",
    "modified", "tags", "level", "falsepositives", "fields",
}

class SIEMRuleManagementSkill(BaseSecuritySkill):
    """SIEM detection rule lifecycle management with MITRE ATT&CK coverage analysis."""

    SKILL_NAME = "siem_rule_management"
    DESCRIPTION = (
        "SIEM detection rule creation, validation, deployment, tuning, "
        "and MITRE ATT&CK coverage analysis with Sigma rule support"
    )
    VERSION = "1.0.0"
    COMPATIBLE_AGENTS = ["gamma_blue_team"]
    REQUIRED_INTEGRATIONS = []

    # Performance weight heuristics (events/sec cost estimate per condition type)
    PERFORMANCE_WEIGHTS = {
        "regex": 3.0,
        "wildcard": 2.0,
        "keyword": 1.5,
        "exact": 1.0,
        "numeric_comparison": 0.5,
        "list_lookup": 1.2,
        "aggregation": 4.0,
        "correlation": 5.0,
    }

    async def _setup(self):
        self.rules: Dict[str, Dict[str, Any]] = {}
        self.rule_metrics: Dict[str, Dict[str, Any]] = {}  # rule_id -> stats
        self.test_results: Dict[str, List[Dict[str, Any]]] = {}

    async def _execute(self, parameters: Dict[str, Any]) -> SkillResult:
        action = parameters.get("action", "list_rules")
        dispatch = {
            "create_rule": self._create_rule,
            "validate_rule": self._validate_rule,
            "test_rule": self._test_rule,
            "deploy_rule": self._deploy_rule,
            "list_rules": self._list_rules,
            "disable_rule": self._disable_rule,
            "tune_rule": self._tune_rule,
            "get_coverage": self._get_coverage,
            "generate_report": self._generate_report,
        }
        handler = dispatch.get(action)
        if not handler:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"Unknown action '{action}'. Supported: {list(dispatch.keys())}"],
            )
        return await handler(parameters)

    # =========================================================================
    # Rule Creation
    # =========================================================================

    async def _create_rule(self, params: Dict[str, Any]) -> SkillResult:
        """Create a new SIEM detection rule in Sigma format."""
        rule_id = params.get("rule_id") or f"rule-{uuid.uuid4().hex[:8]}"

        title = params.get("title")
        if not title:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["Parameter 'title' is required"],
            )

        logsource = params.get("logsource", {})
        detection = params.get("detection", {})
        mitre_techniques = params.get("mitre_techniques", [])
        level = params.get("level", "medium")

        # Build Sigma-format rule structure
        now = datetime.now()
        rule = {
            "rule_id": rule_id,
            "title": title,
            "description": params.get("description", ""),
            "status": RuleStatus.DRAFT.value,
            "level": level,
            "author": params.get("author", self.agent_id),
            "date": now.strftime("%Y/%m/%d"),
            "modified": now.strftime("%Y/%m/%d"),
            "logsource": logsource,
            "detection": detection,
            "falsepositives": params.get("falsepositives", []),
            "tags": [f"attack.{MITRE_TECHNIQUE_MAP[t]['tactic']}" for t in mitre_techniques if t in MITRE_TECHNIQUE_MAP]
                   + [f"attack.{t.lower()}" for t in mitre_techniques],
            "mitre_techniques": mitre_techniques,
            "fields": params.get("fields", []),
            "references": params.get("references", []),
            "created_at": now.isoformat(),
            "updated_at": now.isoformat(),
            "created_by": params.get("author", self.agent_id),
            "tune_history": [],
            "version": 1,
        }

        # Validate immediately
        validation = self._validate_rule_structure(rule)

        if validation["errors"]:
            rule["status"] = RuleStatus.DRAFT.value
        self.rules[rule_id] = rule

        # Estimate performance impact
        perf = self._estimate_performance(rule)

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "rule_id": rule_id,
                "rule": rule,
                "validation": validation,
                "performance_estimate": perf,
            },
            warnings=validation.get("warnings", []),
        )

    # =========================================================================
    # Rule Validation
    # =========================================================================

    def _validate_rule_structure(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        """Validate a Sigma-format rule for syntax and logic issues."""
        errors: List[str] = []
        warnings: List[str] = []

        # Required field checks
        if not rule.get("title"):
            errors.append("Missing required field: title")
        elif len(rule["title"]) > 256:
            warnings.append("Title exceeds 256 characters; may be truncated in SIEM UI")

        if not rule.get("logsource"):
            errors.append("Missing required field: logsource")
        else:
            ls = rule["logsource"]
            if not ls.get("category") and not ls.get("product") and not ls.get("service"):
                errors.append("logsource must specify at least one of: category, product, service")

        if not rule.get("detection"):
            errors.append("Missing required field: detection")
        else:
            det = rule["detection"]
            if "condition" not in det and "selection" not in det:
                errors.append("detection must contain 'condition' or 'selection' key")
            if "condition" in det:
                cond = det["condition"]
                # Validate condition references existing selection names
                selection_keys = {k for k in det.keys() if k != "condition"}
                referenced = set(re.findall(r'\b([a-zA-Z_]\w*)\b', cond))
                keywords = {"and", "or", "not", "all", "of", "them", "1"}
                unresolved = referenced - selection_keys - keywords
                if unresolved:
                    errors.append(f"Condition references undefined selections: {unresolved}")
            # Check for overly broad detection
            for key, value in det.items():
                if key == "condition":
                    continue
                if isinstance(value, dict):
                    if len(value) == 0:
                        errors.append(f"Empty selection '{key}' will match nothing")
                    for field_name, field_val in value.items():
                        if isinstance(field_val, str) and field_val == "*":
                            warnings.append(f"Wildcard-only value in '{key}.{field_name}' — may generate excessive alerts")

        # Level validation
        valid_levels = [e.value for e in RuleLevel]
        if rule.get("level") and rule["level"] not in valid_levels:
            warnings.append(f"Non-standard level '{rule['level']}'; expected one of {valid_levels}")

        # MITRE technique validation
        for tech in rule.get("mitre_techniques", []):
            if tech not in MITRE_TECHNIQUE_MAP:
                warnings.append(f"MITRE technique '{tech}' not in known mapping — verify ID")

        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings,
            "checks_passed": {
                "has_title": bool(rule.get("title")),
                "has_logsource": bool(rule.get("logsource")),
                "has_detection": bool(rule.get("detection")),
                "has_level": bool(rule.get("level")),
                "has_description": bool(rule.get("description")),
                "has_mitre_mapping": len(rule.get("mitre_techniques", [])) > 0,
                "has_falsepositives": len(rule.get("falsepositives", [])) > 0,
            },
        }

    async def _validate_rule(self, params: Dict[str, Any]) -> SkillResult:
        """Validate an existing or provided rule."""
        rule_id = params.get("rule_id")
        if rule_id and rule_id in self.rules:
            rule = self.rules[rule_id]
        elif params.get("rule"):
            rule = params["rule"]
        else:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["Provide 'rule_id' of existing rule or 'rule' dict to validate"],
            )

        validation = self._validate_rule_structure(rule)
        perf = self._estimate_performance(rule)

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={"rule_id": rule_id, "validation": validation, "performance_estimate": perf},
            warnings=validation.get("warnings", []),
        )

    # =========================================================================
    # Rule Testing
    # =========================================================================

    async def _test_rule(self, params: Dict[str, Any]) -> SkillResult:
        """Simulate rule testing against sample events."""
        rule_id = params.get("rule_id")
        if not rule_id or rule_id not in self.rules:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"Rule '{rule_id}' not found"],
            )

        rule = self.rules[rule_id]
        test_events = params.get("test_events", [])
        time_range_hours = params.get("time_range_hours", 24)

        # Validate before testing
        validation = self._validate_rule_structure(rule)
        if not validation["valid"]:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["Rule has validation errors — fix before testing"] + validation["errors"],
            )

        # Simulated test results (in production, this would run against SIEM)
        detection = rule.get("detection", {})
        selection_count = len([k for k in detection if k != "condition"])
        estimated_matches = max(1, len(test_events)) if test_events else 0

        # Heuristic: estimate false positive rate from rule complexity
        fp_factors = []
        for key, value in detection.items():
            if key == "condition":
                continue
            if isinstance(value, dict):
                for fv in value.values():
                    if isinstance(fv, str) and "*" in fv:
                        fp_factors.append("wildcard_usage")
                    if isinstance(fv, list) and len(fv) > 10:
                        fp_factors.append("large_value_list")

        estimated_fp_rate = min(0.5, 0.02 * len(fp_factors) + 0.01)

        test_result = {
            "rule_id": rule_id,
            "test_id": f"test-{uuid.uuid4().hex[:8]}",
            "timestamp": datetime.now().isoformat(),
            "time_range_hours": time_range_hours,
            "events_tested": len(test_events) if test_events else 0,
            "matches": estimated_matches,
            "estimated_daily_alerts": max(0, int(estimated_matches * (24 / max(1, time_range_hours)))),
            "estimated_fp_rate": round(estimated_fp_rate, 3),
            "selection_count": selection_count,
            "fp_factors": fp_factors,
            "recommendation": "ready_for_deployment" if estimated_fp_rate < 0.1 else "needs_tuning",
        }

        self.test_results.setdefault(rule_id, []).append(test_result)

        # Move to testing status
        if rule["status"] == RuleStatus.DRAFT.value:
            rule["status"] = RuleStatus.TESTING.value
            rule["updated_at"] = datetime.now().isoformat()

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={"test_result": test_result},
            warnings=["High estimated false positive rate — consider tuning"] if estimated_fp_rate >= 0.1 else [],
        )

    # =========================================================================
    # Rule Deployment
    # =========================================================================

    async def _deploy_rule(self, params: Dict[str, Any]) -> SkillResult:
        """Deploy a tested rule to active detection."""
        rule_id = params.get("rule_id")
        if not rule_id or rule_id not in self.rules:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"Rule '{rule_id}' not found"],
            )

        rule = self.rules[rule_id]
        force = params.get("force", False)

        # Enforce lifecycle: must be tested before deployment unless forced
        if rule["status"] not in (RuleStatus.TESTING.value, RuleStatus.DISABLED.value) and not force:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[
                    f"Rule is in '{rule['status']}' status. Only 'testing' or 'disabled' rules "
                    f"can be deployed. Use force=True to override."
                ],
            )

        # Validation gate
        validation = self._validate_rule_structure(rule)
        if not validation["valid"]:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["Rule has validation errors — cannot deploy"] + validation["errors"],
            )

        now = datetime.now()
        rule["status"] = RuleStatus.ACTIVE.value
        rule["deployed_at"] = now.isoformat()
        rule["updated_at"] = now.isoformat()

        # Initialize metrics tracking
        self.rule_metrics[rule_id] = {
            "deployed_at": now.isoformat(),
            "total_alerts": 0,
            "true_positives": 0,
            "false_positives": 0,
            "last_triggered": None,
        }

        # Emit intelligence packet for new active detection
        packet = IntelligencePacket(
            packet_id=f"PKT-RULE-{rule_id}",
            source_agent=self.agent_id,
            target_agents=["all"],
            intelligence_type=IntelligenceType.CORRELATION,
            priority=Priority.MEDIUM,
            confidence=85.0,
            timestamp=now,
            data={
                "event": "rule_deployed",
                "rule_id": rule_id,
                "title": rule["title"],
                "mitre_techniques": rule.get("mitre_techniques", []),
                "level": rule.get("level"),
            },
            correlation_keys=rule.get("mitre_techniques", []),
        )

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "rule_id": rule_id,
                "status": rule["status"],
                "deployed_at": rule["deployed_at"],
                "title": rule["title"],
                "mitre_techniques": rule.get("mitre_techniques", []),
            },
            intelligence_packets=[packet],
        )

    # =========================================================================
    # List / Disable
    # =========================================================================

    async def _list_rules(self, params: Dict[str, Any]) -> SkillResult:
        """List all rules with optional status filter."""
        status_filter = params.get("status")
        level_filter = params.get("level")

        rules = []
        for rid, rule in self.rules.items():
            if status_filter and rule["status"] != status_filter:
                continue
            if level_filter and rule.get("level") != level_filter:
                continue
            rules.append({
                "rule_id": rid,
                "title": rule["title"],
                "status": rule["status"],
                "level": rule.get("level", "medium"),
                "mitre_techniques": rule.get("mitre_techniques", []),
                "version": rule.get("version", 1),
                "updated_at": rule.get("updated_at"),
            })

        summary = {
            status.value: sum(1 for r in self.rules.values() if r["status"] == status.value)
            for status in RuleStatus
        }

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={"rules": rules, "total": len(rules), "status_summary": summary},
        )

    async def _disable_rule(self, params: Dict[str, Any]) -> SkillResult:
        """Disable an active rule."""
        rule_id = params.get("rule_id")
        if not rule_id or rule_id not in self.rules:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"Rule '{rule_id}' not found"],
            )

        rule = self.rules[rule_id]
        reason = params.get("reason", "No reason provided")
        previous_status = rule["status"]
        rule["status"] = RuleStatus.DISABLED.value
        rule["disabled_at"] = datetime.now().isoformat()
        rule["disable_reason"] = reason
        rule["updated_at"] = datetime.now().isoformat()

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "rule_id": rule_id,
                "previous_status": previous_status,
                "status": rule["status"],
                "reason": reason,
            },
        )

    # =========================================================================
    # Rule Tuning
    # =========================================================================

    async def _tune_rule(self, params: Dict[str, Any]) -> SkillResult:
        """Tune a rule to reduce false positives or adjust thresholds."""
        rule_id = params.get("rule_id")
        if not rule_id or rule_id not in self.rules:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"Rule '{rule_id}' not found"],
            )

        rule = self.rules[rule_id]
        changes: List[str] = []

        # Add exclusions
        exclusions = params.get("exclusions", [])
        if exclusions:
            detection = rule.get("detection", {})
            existing_filter = detection.get("filter", {})
            for exc in exclusions:
                field_name = exc.get("field")
                value = exc.get("value")
                if field_name and value:
                    existing_filter.setdefault(field_name, [])
                    if isinstance(existing_filter[field_name], list):
                        existing_filter[field_name].append(value)
                    else:
                        existing_filter[field_name] = [existing_filter[field_name], value]
                    changes.append(f"Added exclusion: {field_name}={value}")
            detection["filter"] = existing_filter
            # Ensure condition references filter
            if "condition" in detection and "not filter" not in detection["condition"]:
                detection["condition"] += " and not filter"
            rule["detection"] = detection

        # Adjust threshold
        threshold = params.get("threshold")
        if threshold:
            rule.setdefault("detection", {})["threshold"] = threshold
            changes.append(f"Set threshold: count={threshold.get('count')}, timeframe={threshold.get('timeframe')}")

        # Adjust level
        new_level = params.get("level")
        if new_level:
            old_level = rule.get("level")
            rule["level"] = new_level
            changes.append(f"Level changed: {old_level} -> {new_level}")

        # Add false positive notes
        fp_notes = params.get("falsepositives", [])
        if fp_notes:
            rule.setdefault("falsepositives", []).extend(fp_notes)
            changes.append(f"Added {len(fp_notes)} false positive note(s)")

        # Version bump
        rule["version"] = rule.get("version", 1) + 1
        rule["updated_at"] = datetime.now().isoformat()
        rule["tune_history"].append({
            "timestamp": datetime.now().isoformat(),
            "version": rule["version"],
            "changes": changes,
            "tuned_by": params.get("analyst", self.agent_id),
        })

        # Move back to testing after significant changes
        if exclusions or threshold:
            rule["status"] = RuleStatus.TESTING.value
            changes.append("Status reverted to 'testing' for re-validation")

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "rule_id": rule_id,
                "version": rule["version"],
                "status": rule["status"],
                "changes": changes,
                "tune_history": rule["tune_history"],
            },
        )

    # =========================================================================
    # MITRE ATT&CK Coverage
    # =========================================================================

    async def _get_coverage(self, params: Dict[str, Any]) -> SkillResult:
        """Analyze detection coverage mapped to MITRE ATT&CK framework."""
        # Collect all techniques covered by active and testing rules
        covered_techniques: Dict[str, List[str]] = {}
        for rid, rule in self.rules.items():
            if rule["status"] in (RuleStatus.ACTIVE.value, RuleStatus.TESTING.value):
                for tech in rule.get("mitre_techniques", []):
                    covered_techniques.setdefault(tech, []).append(rid)

        # Build tactic-level summary
        tactic_coverage: Dict[str, Dict[str, Any]] = {}
        for tech_id, info in MITRE_TECHNIQUE_MAP.items():
            tactic = info["tactic"]
            tactic_coverage.setdefault(tactic, {"total_techniques": 0, "covered": 0, "techniques": []})
            tactic_coverage[tactic]["total_techniques"] += 1
            if tech_id in covered_techniques:
                tactic_coverage[tactic]["covered"] += 1
                tactic_coverage[tactic]["techniques"].append({
                    "technique_id": tech_id,
                    "name": info["name"],
                    "rules": covered_techniques[tech_id],
                })

        for tactic, data in tactic_coverage.items():
            total = data["total_techniques"]
            data["coverage_pct"] = round((data["covered"] / total * 100) if total else 0, 1)

        # Identify gaps
        gaps = []
        for tech_id, info in MITRE_TECHNIQUE_MAP.items():
            if tech_id not in covered_techniques:
                gaps.append({
                    "technique_id": tech_id,
                    "name": info["name"],
                    "tactic": info["tactic"],
                    "recommended_log_sources": info["log_sources"],
                })

        overall_total = len(MITRE_TECHNIQUE_MAP)
        overall_covered = len(covered_techniques)

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "overall_coverage_pct": round((overall_covered / overall_total * 100) if overall_total else 0, 1),
                "techniques_covered": overall_covered,
                "techniques_total": overall_total,
                "tactic_coverage": tactic_coverage,
                "coverage_gaps": gaps,
                "gap_count": len(gaps),
            },
        )

    # =========================================================================
    # Performance Estimation
    # =========================================================================

    def _estimate_performance(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        """Estimate the SIEM performance cost of a rule."""
        detection = rule.get("detection", {})
        cost = 0.0
        factors: List[str] = []

        for key, value in detection.items():
            if key == "condition":
                if "near" in str(value) or "count" in str(value):
                    cost += self.PERFORMANCE_WEIGHTS["aggregation"]
                    factors.append("aggregation_in_condition")
                continue
            if key == "threshold":
                cost += self.PERFORMANCE_WEIGHTS["aggregation"]
                factors.append("threshold_evaluation")
                continue
            if isinstance(value, dict):
                for fv in value.values():
                    if isinstance(fv, str):
                        if re.search(r'[*?]', fv):
                            cost += self.PERFORMANCE_WEIGHTS["wildcard"]
                            factors.append("wildcard_match")
                        elif fv.startswith("re:") or "|re" in fv:
                            cost += self.PERFORMANCE_WEIGHTS["regex"]
                            factors.append("regex_match")
                        else:
                            cost += self.PERFORMANCE_WEIGHTS["exact"]
                    elif isinstance(fv, list):
                        cost += self.PERFORMANCE_WEIGHTS["list_lookup"] * (1 + len(fv) / 100)
                        factors.append(f"list_lookup({len(fv)} values)")

        # Normalize to a 1-10 impact scale
        impact_score = min(10.0, round(cost, 1))
        if impact_score <= 3:
            impact_label = "low"
        elif impact_score <= 6:
            impact_label = "medium"
        else:
            impact_label = "high"

        return {
            "impact_score": impact_score,
            "impact_label": impact_label,
            "cost_factors": factors,
            "recommendation": (
                "Rule is efficient and suitable for high-volume log sources"
                if impact_label == "low"
                else "Consider optimizing regex/wildcard usage"
                if impact_label == "medium"
                else "High-cost rule — deploy with rate limiting or on filtered log subset"
            ),
        }

    # =========================================================================
    # Reporting
    # =========================================================================

    async def _generate_report(self, params: Dict[str, Any]) -> SkillResult:
        """Generate a comprehensive SIEM rule management report."""
        report_type = params.get("report_type", "summary")

        status_counts = {s.value: 0 for s in RuleStatus}
        level_counts = {l.value: 0 for l in RuleLevel}
        all_techniques: set = set()

        for rule in self.rules.values():
            status_counts[rule.get("status", "draft")] = status_counts.get(rule.get("status", "draft"), 0) + 1
            level_counts[rule.get("level", "medium")] = level_counts.get(rule.get("level", "medium"), 0) + 1
            all_techniques.update(rule.get("mitre_techniques", []))

        # Coverage summary
        technique_total = len(MITRE_TECHNIQUE_MAP)
        technique_covered = len(all_techniques & set(MITRE_TECHNIQUE_MAP.keys()))

        report = {
            "generated_at": datetime.now().isoformat(),
            "report_type": report_type,
            "total_rules": len(self.rules),
            "status_distribution": status_counts,
            "level_distribution": level_counts,
            "mitre_coverage": {
                "techniques_covered": technique_covered,
                "techniques_total": technique_total,
                "coverage_pct": round((technique_covered / technique_total * 100) if technique_total else 0, 1),
            },
            "rules_with_tests": len(self.test_results),
            "total_test_runs": sum(len(v) for v in self.test_results.values()),
            "recommendations": [],
        }

        # Generate recommendations
        if status_counts.get("draft", 0) > 5:
            report["recommendations"].append(
                f"{status_counts['draft']} rules still in draft — review and advance to testing"
            )
        if report["mitre_coverage"]["coverage_pct"] < 50:
            report["recommendations"].append(
                "MITRE ATT&CK coverage below 50% — prioritize gap analysis"
            )
        if status_counts.get("disabled", 0) > status_counts.get("active", 0):
            report["recommendations"].append(
                "More disabled rules than active — review disabled rules for re-enablement or deprecation"
            )

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={"report": report},
        )
