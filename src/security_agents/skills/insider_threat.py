#!/usr/bin/env python3
"""
Insider Threat Detection Skill — Behavioral analytics for insider risk identification.

Primary owners: Gamma (Blue Team), Alpha-4 (Threat Intel)

Capabilities:
  - UEBA indicators (unusual access, data exfiltration patterns, privilege escalation)
  - Behavioral baseline comparison with statistical deviation detection
  - Risk scoring with time-based decay
  - Watchlist management with configurable thresholds
  - Privacy-preserving design (aggregated signals, no raw content capture)
  - Resignation and HR event correlation
  - Structured investigation workflow
"""

import hashlib
import math
import uuid
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Any, Optional

from security_agents.core.models import SkillResult, IntelligencePacket, IntelligenceType, Priority
from security_agents.skills.base_skill import BaseSecuritySkill

# =============================================================================
# Enumerations
# =============================================================================

class IndicatorCategory(Enum):
    ACCESS_ANOMALY = "access_anomaly"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ABUSE = "privilege_abuse"
    POLICY_VIOLATION = "policy_violation"
    BEHAVIORAL_CHANGE = "behavioral_change"
    HR_CORRELATION = "hr_correlation"
    TECHNICAL_INDICATOR = "technical_indicator"

class RiskLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    BASELINE = "baseline"

class WatchlistReason(Enum):
    HIGH_RISK_SCORE = "high_risk_score"
    HR_FLAG = "hr_flag"
    REPEATED_VIOLATIONS = "repeated_violations"
    INVESTIGATION = "investigation"
    DEPARTING_EMPLOYEE = "departing_employee"
    PRIVILEGED_USER = "privileged_user"
    MANUAL_ADDITION = "manual_addition"

class InvestigationStatus(Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    ESCALATED = "escalated"
    CLOSED_CONFIRMED = "closed_confirmed"
    CLOSED_FALSE_POSITIVE = "closed_false_positive"
    CLOSED_INCONCLUSIVE = "closed_inconclusive"

# =============================================================================
# UEBA Indicator Definitions
# =============================================================================

INDICATOR_DEFINITIONS: Dict[str, Dict[str, Any]] = {
    # Access anomalies
    "unusual_login_time": {
        "category": IndicatorCategory.ACCESS_ANOMALY.value,
        "description": "Login outside normal working hours pattern",
        "base_weight": 3,
        "privacy_level": "low",
        "mitre_technique": "T1078 - Valid Accounts",
    },
    "unusual_login_location": {
        "category": IndicatorCategory.ACCESS_ANOMALY.value,
        "description": "Login from geographic location not in user's baseline",
        "base_weight": 5,
        "privacy_level": "low",
        "mitre_technique": "T1078 - Valid Accounts",
    },
    "impossible_travel": {
        "category": IndicatorCategory.ACCESS_ANOMALY.value,
        "description": "Logins from geographically distant locations in impossibly short time",
        "base_weight": 8,
        "privacy_level": "low",
        "mitre_technique": "T1078 - Valid Accounts",
    },
    "failed_login_spike": {
        "category": IndicatorCategory.ACCESS_ANOMALY.value,
        "description": "Abnormal increase in failed authentication attempts",
        "base_weight": 4,
        "privacy_level": "low",
        "mitre_technique": "T1110 - Brute Force",
    },
    "dormant_account_activation": {
        "category": IndicatorCategory.ACCESS_ANOMALY.value,
        "description": "Previously dormant account suddenly becomes active",
        "base_weight": 6,
        "privacy_level": "low",
        "mitre_technique": "T1078 - Valid Accounts",
    },
    "unusual_system_access": {
        "category": IndicatorCategory.ACCESS_ANOMALY.value,
        "description": "Access to systems outside normal job function scope",
        "base_weight": 5,
        "privacy_level": "medium",
        "mitre_technique": "T1083 - File and Directory Discovery",
    },

    # Data exfiltration signals
    "large_download": {
        "category": IndicatorCategory.DATA_EXFILTRATION.value,
        "description": "Download volume significantly above user's baseline",
        "base_weight": 6,
        "privacy_level": "medium",
        "mitre_technique": "T1567 - Exfiltration Over Web Service",
    },
    "large_email_attachment": {
        "category": IndicatorCategory.DATA_EXFILTRATION.value,
        "description": "Email with unusually large or numerous attachments",
        "base_weight": 5,
        "privacy_level": "medium",
        "mitre_technique": "T1048 - Exfiltration Over Alternative Protocol",
    },
    "cloud_upload_spike": {
        "category": IndicatorCategory.DATA_EXFILTRATION.value,
        "description": "Unusual volume of uploads to cloud storage services",
        "base_weight": 6,
        "privacy_level": "medium",
        "mitre_technique": "T1567 - Exfiltration Over Web Service",
    },
    "usb_large_transfer": {
        "category": IndicatorCategory.DATA_EXFILTRATION.value,
        "description": "Large data transfer to removable media",
        "base_weight": 7,
        "privacy_level": "medium",
        "mitre_technique": "T1052 - Exfiltration Over Physical Medium",
    },
    "print_spike": {
        "category": IndicatorCategory.DATA_EXFILTRATION.value,
        "description": "Unusual volume of printing, especially sensitive documents",
        "base_weight": 4,
        "privacy_level": "medium",
        "mitre_technique": "T1052 - Exfiltration Over Physical Medium",
    },
    "sensitive_data_access_spike": {
        "category": IndicatorCategory.DATA_EXFILTRATION.value,
        "description": "Accessing significantly more sensitive files than baseline",
        "base_weight": 7,
        "privacy_level": "medium",
        "mitre_technique": "T1005 - Data from Local System",
    },

    # Privilege abuse
    "privilege_escalation_attempt": {
        "category": IndicatorCategory.PRIVILEGE_ABUSE.value,
        "description": "Attempted elevation beyond assigned role permissions",
        "base_weight": 8,
        "privacy_level": "low",
        "mitre_technique": "T1068 - Exploitation for Privilege Escalation",
    },
    "admin_action_outside_role": {
        "category": IndicatorCategory.PRIVILEGE_ABUSE.value,
        "description": "Administrative actions performed outside normal job duties",
        "base_weight": 7,
        "privacy_level": "low",
        "mitre_technique": "T1078.004 - Cloud Accounts",
    },
    "service_account_interactive": {
        "category": IndicatorCategory.PRIVILEGE_ABUSE.value,
        "description": "Service account used for interactive login",
        "base_weight": 8,
        "privacy_level": "low",
        "mitre_technique": "T1078.001 - Default Accounts",
    },
    "permission_change_self": {
        "category": IndicatorCategory.PRIVILEGE_ABUSE.value,
        "description": "User modifying their own permissions or group memberships",
        "base_weight": 9,
        "privacy_level": "low",
        "mitre_technique": "T1098 - Account Manipulation",
    },

    # Policy violations
    "unauthorized_tool_usage": {
        "category": IndicatorCategory.POLICY_VIOLATION.value,
        "description": "Use of unauthorized software, VPN, or proxy tools",
        "base_weight": 5,
        "privacy_level": "medium",
        "mitre_technique": "T1090 - Proxy",
    },
    "security_control_bypass": {
        "category": IndicatorCategory.POLICY_VIOLATION.value,
        "description": "Attempt to bypass or disable security controls (DLP, EDR, etc.)",
        "base_weight": 9,
        "privacy_level": "low",
        "mitre_technique": "T1562 - Impair Defenses",
    },
    "credential_sharing": {
        "category": IndicatorCategory.POLICY_VIOLATION.value,
        "description": "Evidence of account sharing or credential lending",
        "base_weight": 6,
        "privacy_level": "low",
        "mitre_technique": "T1078 - Valid Accounts",
    },

    # Behavioral change
    "work_hour_change": {
        "category": IndicatorCategory.BEHAVIORAL_CHANGE.value,
        "description": "Significant shift in working hours pattern",
        "base_weight": 2,
        "privacy_level": "high",
        "mitre_technique": None,
    },
    "productivity_pattern_change": {
        "category": IndicatorCategory.BEHAVIORAL_CHANGE.value,
        "description": "Marked change in system usage patterns",
        "base_weight": 2,
        "privacy_level": "high",
        "mitre_technique": None,
    },

    # HR correlation
    "resignation_notice": {
        "category": IndicatorCategory.HR_CORRELATION.value,
        "description": "Employee has submitted resignation or notice of departure",
        "base_weight": 5,
        "privacy_level": "high",
        "mitre_technique": None,
    },
    "performance_improvement_plan": {
        "category": IndicatorCategory.HR_CORRELATION.value,
        "description": "Employee is on a performance improvement plan",
        "base_weight": 4,
        "privacy_level": "high",
        "mitre_technique": None,
    },
    "denied_promotion_transfer": {
        "category": IndicatorCategory.HR_CORRELATION.value,
        "description": "Employee was denied a promotion or transfer request",
        "base_weight": 3,
        "privacy_level": "high",
        "mitre_technique": None,
    },
}

# Risk score decay: how fast old indicators lose weight
RISK_DECAY_HALF_LIFE_DAYS = 30  # Score halves every 30 days

class InsiderThreatSkill(BaseSecuritySkill):
    """Detect and assess insider threat risk through behavioral analytics."""

    SKILL_NAME = "insider_threat"
    DESCRIPTION = (
        "Detect insider threat risks through UEBA indicators, behavioral baseline "
        "comparison, risk scoring with temporal decay, and privacy-preserving analytics"
    )
    VERSION = "1.0.0"
    COMPATIBLE_AGENTS = ["gamma_blue_team", "alpha_4_threat_intel"]
    REQUIRED_INTEGRATIONS = []

    async def _setup(self):
        self.user_profiles: Dict[str, Dict[str, Any]] = {}  # user_id -> profile
        self.indicators: List[Dict[str, Any]] = []
        self.watchlist: Dict[str, Dict[str, Any]] = {}  # user_id -> watchlist entry
        self.alerts: List[Dict[str, Any]] = []
        self.investigations: Dict[str, Dict[str, Any]] = {}  # investigation_id -> data

    async def _execute(self, parameters: Dict[str, Any]) -> SkillResult:
        action = parameters.get("action", "analyze_behavior")

        dispatch = {
            "analyze_behavior": self._analyze_behavior,
            "detect_anomalies": self._detect_anomalies,
            "assess_risk": self._assess_risk,
            "create_watchlist": self._create_watchlist,
            "get_alerts": self._get_alerts,
            "investigate_user": self._investigate_user,
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
    # Analyze Behavior
    # =========================================================================

    async def _analyze_behavior(self, params: Dict[str, Any]) -> SkillResult:
        """Analyze user behavior events against baseline to detect anomalies."""
        user_id = params.get("user_id", "")
        events = params.get("events", [])  # [{type, timestamp, details}]
        baseline = params.get("baseline", {})  # optional: existing baseline metrics
        hr_flags = params.get("hr_flags", [])  # optional: HR-sourced indicators

        if not user_id:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["'user_id' is required"],
            )

        # Get or create user profile
        profile = self.user_profiles.get(user_id, {
            "user_id": user_id,
            "first_seen": datetime.now().isoformat(),
            "baseline": baseline or self._default_baseline(),
            "risk_score": 0,
            "risk_level": RiskLevel.BASELINE.value,
            "indicator_history": [],
            "total_events_analyzed": 0,
        })

        user_baseline = profile.get("baseline", self._default_baseline())
        detected_indicators = []

        # Analyze each event against baseline
        for event in events:
            event_type = event.get("type", "")
            event_ts = event.get("timestamp", datetime.now().isoformat())
            event_details = event.get("details", {})

            indicators = self._evaluate_event(event_type, event_details, user_baseline)
            for indicator in indicators:
                indicator["user_id"] = user_id
                indicator["event_timestamp"] = event_ts
                indicator["detected_at"] = datetime.now().isoformat()
                detected_indicators.append(indicator)

        # Process HR flags as indicators
        for flag in hr_flags:
            flag_type = flag.get("type", "")
            indicator_def = INDICATOR_DEFINITIONS.get(flag_type)
            if indicator_def:
                detected_indicators.append({
                    "indicator_id": f"IND-{uuid.uuid4().hex[:8]}",
                    "user_id": user_id,
                    "indicator_type": flag_type,
                    "category": indicator_def["category"],
                    "description": indicator_def["description"],
                    "weight": indicator_def["base_weight"],
                    "confidence": flag.get("confidence", 90.0),
                    "privacy_level": indicator_def["privacy_level"],
                    "mitre_technique": indicator_def.get("mitre_technique"),
                    "event_timestamp": flag.get("timestamp", datetime.now().isoformat()),
                    "detected_at": datetime.now().isoformat(),
                    "source": "hr_correlation",
                    "details": {k: v for k, v in flag.items() if k not in ("type", "confidence", "timestamp")},
                })

        # Store indicators and update profile
        self.indicators.extend(detected_indicators)
        profile["indicator_history"].extend(detected_indicators)
        profile["total_events_analyzed"] += len(events)
        profile["last_analyzed"] = datetime.now().isoformat()

        # Recalculate risk score with decay
        risk_score = self._calculate_user_risk(profile)
        profile["risk_score"] = risk_score
        profile["risk_level"] = self._score_to_risk_level(risk_score)

        self.user_profiles[user_id] = profile

        # Generate alert if risk threshold exceeded
        if risk_score >= 70:
            alert = {
                "alert_id": f"ALT-{uuid.uuid4().hex[:8]}",
                "user_id": user_id,
                "risk_score": risk_score,
                "risk_level": profile["risk_level"],
                "indicator_count": len(detected_indicators),
                "top_indicators": sorted(detected_indicators, key=lambda i: i.get("weight", 0), reverse=True)[:5],
                "timestamp": datetime.now().isoformat(),
                "recommended_action": self._recommend_response(risk_score, detected_indicators),
            }
            self.alerts.append(alert)

        # Category breakdown
        category_counts: Dict[str, int] = {}
        for ind in detected_indicators:
            cat = ind.get("category", "unknown")
            category_counts[cat] = category_counts.get(cat, 0) + 1

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "user_id": user_id,
                "events_analyzed": len(events),
                "indicators_detected": len(detected_indicators),
                "indicators": detected_indicators,
                "category_breakdown": category_counts,
                "risk_score": risk_score,
                "risk_level": profile["risk_level"],
                "on_watchlist": user_id in self.watchlist,
            },
            warnings=[
                f"User '{user_id}' risk score is {risk_score} ({profile['risk_level']}) — investigation recommended"
            ] if risk_score >= 70 else [],
        )

    # =========================================================================
    # Detect Anomalies
    # =========================================================================

    async def _detect_anomalies(self, params: Dict[str, Any]) -> SkillResult:
        """Batch anomaly detection across multiple users."""
        user_activities = params.get("user_activities", {})  # {user_id: {metrics}}
        detection_threshold = params.get("threshold", 2.0)  # standard deviations

        if not user_activities:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["'user_activities' required — dict of user_id -> activity metrics"],
            )

        anomalies = []
        for user_id, metrics in user_activities.items():
            profile = self.user_profiles.get(user_id, {"baseline": self._default_baseline()})
            baseline = profile.get("baseline", self._default_baseline())

            user_anomalies = self._compare_to_baseline(user_id, metrics, baseline, detection_threshold)
            anomalies.extend(user_anomalies)

        # Group by user
        user_anomaly_counts: Dict[str, int] = {}
        for a in anomalies:
            uid = a.get("user_id", "")
            user_anomaly_counts[uid] = user_anomaly_counts.get(uid, 0) + 1

        # Sort by anomaly count
        top_users = sorted(user_anomaly_counts.items(), key=lambda x: x[1], reverse=True)

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "total_anomalies": len(anomalies),
                "users_with_anomalies": len(user_anomaly_counts),
                "users_analyzed": len(user_activities),
                "anomalies": anomalies,
                "top_anomalous_users": top_users[:10],
                "detection_threshold": detection_threshold,
            },
        )

    # =========================================================================
    # Assess Risk
    # =========================================================================

    async def _assess_risk(self, params: Dict[str, Any]) -> SkillResult:
        """Calculate or retrieve risk scores for users."""
        user_id = params.get("user_id")
        recalculate = params.get("recalculate", True)

        if user_id:
            profile = self.user_profiles.get(user_id)
            if not profile:
                return SkillResult(
                    success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                    errors=[f"No profile found for user '{user_id}'. Analyze behavior first."],
                )

            if recalculate:
                risk_score = self._calculate_user_risk(profile)
                profile["risk_score"] = risk_score
                profile["risk_level"] = self._score_to_risk_level(risk_score)

            # Build risk breakdown
            recent_indicators = [
                i for i in profile.get("indicator_history", [])
                if self._days_since(i.get("detected_at", "")) < 90
            ]

            category_risk: Dict[str, float] = {}
            for ind in recent_indicators:
                cat = ind.get("category", "unknown")
                weight = ind.get("weight", 0) * ind.get("confidence", 50) / 100
                decay = self._decay_factor(ind.get("detected_at", ""))
                category_risk[cat] = category_risk.get(cat, 0) + weight * decay

            return SkillResult(
                success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                data={
                    "user_id": user_id,
                    "risk_score": profile["risk_score"],
                    "risk_level": profile["risk_level"],
                    "category_risk_breakdown": {k: round(v, 1) for k, v in sorted(category_risk.items(), key=lambda x: x[1], reverse=True)},
                    "total_indicators": len(profile.get("indicator_history", [])),
                    "recent_indicators_90d": len(recent_indicators),
                    "on_watchlist": user_id in self.watchlist,
                    "risk_trend": self._calculate_trend(profile),
                },
            )

        # Organization-wide risk assessment
        if not self.user_profiles:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["No user profiles. Analyze behavior for at least one user first."],
            )

        user_risks = []
        for uid, prof in self.user_profiles.items():
            if recalculate:
                score = self._calculate_user_risk(prof)
                prof["risk_score"] = score
                prof["risk_level"] = self._score_to_risk_level(score)
            user_risks.append({
                "user_id": uid,
                "risk_score": prof["risk_score"],
                "risk_level": prof["risk_level"],
                "indicator_count": len(prof.get("indicator_history", [])),
            })

        user_risks.sort(key=lambda u: u["risk_score"], reverse=True)

        risk_distribution = {}
        for level in ["critical", "high", "medium", "low", "baseline"]:
            risk_distribution[level] = sum(1 for u in user_risks if u["risk_level"] == level)

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "total_users": len(user_risks),
                "risk_distribution": risk_distribution,
                "top_risk_users": user_risks[:10],
                "average_risk_score": round(sum(u["risk_score"] for u in user_risks) / len(user_risks), 1),
                "watchlist_count": len(self.watchlist),
                "active_alerts": len([a for a in self.alerts if not a.get("resolved")]),
            },
        )

    # =========================================================================
    # Watchlist Management
    # =========================================================================

    async def _create_watchlist(self, params: Dict[str, Any]) -> SkillResult:
        """Add, remove, or list watchlist entries."""
        watchlist_action = params.get("watchlist_action", "add")  # add, remove, list
        user_id = params.get("user_id", "")
        reason = params.get("reason", "")
        enhanced_monitoring = params.get("enhanced_monitoring", True)

        if watchlist_action == "list":
            entries = list(self.watchlist.values())
            return SkillResult(
                success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                data={
                    "watchlist": entries,
                    "total_entries": len(entries),
                    "reason_breakdown": {
                        r.value: sum(1 for e in entries if e.get("reason") == r.value)
                        for r in WatchlistReason
                    },
                },
            )

        if not user_id:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["'user_id' required for watchlist add/remove"],
            )

        if watchlist_action == "add":
            if not reason:
                return SkillResult(
                    success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                    errors=["'reason' required when adding to watchlist (for audit trail)"],
                )

            entry = {
                "user_id": user_id,
                "reason": reason,
                "added_at": datetime.now().isoformat(),
                "added_by": self.agent_id,
                "enhanced_monitoring": enhanced_monitoring,
                "risk_score_at_addition": self.user_profiles.get(user_id, {}).get("risk_score", 0),
                "notes": params.get("notes", ""),
            }
            self.watchlist[user_id] = entry

            return SkillResult(
                success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                data={
                    "watchlist_entry": entry,
                    "total_watchlist": len(self.watchlist),
                    "note": "Privacy notice: Enhanced monitoring must comply with organizational policy and applicable privacy regulations.",
                },
            )

        elif watchlist_action == "remove":
            if user_id not in self.watchlist:
                return SkillResult(
                    success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                    errors=[f"User '{user_id}' is not on the watchlist"],
                )

            removed = self.watchlist.pop(user_id)
            return SkillResult(
                success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                data={
                    "removed_entry": removed,
                    "total_watchlist": len(self.watchlist),
                },
            )

        return SkillResult(
            success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            errors=[f"Unknown watchlist_action '{watchlist_action}'. Use: add, remove, list"],
        )

    # =========================================================================
    # Get Alerts
    # =========================================================================

    async def _get_alerts(self, params: Dict[str, Any]) -> SkillResult:
        """Retrieve insider threat alerts with optional filtering."""
        user_id_filter = params.get("user_id")
        risk_level_filter = params.get("risk_level")
        limit = params.get("limit", 50)
        include_resolved = params.get("include_resolved", False)

        alerts = self.alerts
        if user_id_filter:
            alerts = [a for a in alerts if a.get("user_id") == user_id_filter]
        if risk_level_filter:
            alerts = [a for a in alerts if a.get("risk_level") == risk_level_filter]
        if not include_resolved:
            alerts = [a for a in alerts if not a.get("resolved")]

        # Sort by risk score descending
        alerts.sort(key=lambda a: a.get("risk_score", 0), reverse=True)

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "alerts": alerts[:limit],
                "total_alerts": len(alerts),
                "returned": min(limit, len(alerts)),
                "risk_level_breakdown": {
                    level: sum(1 for a in alerts if a.get("risk_level") == level)
                    for level in ["critical", "high", "medium", "low"]
                },
            },
        )

    # =========================================================================
    # Investigate User
    # =========================================================================

    async def _investigate_user(self, params: Dict[str, Any]) -> SkillResult:
        """Open or update an investigation for a user."""
        user_id = params.get("user_id", "")
        investigation_action = params.get("investigation_action", "open")  # open, update, close
        investigation_id = params.get("investigation_id")
        notes = params.get("notes", "")
        status = params.get("status")

        if not user_id and not investigation_id:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["'user_id' or 'investigation_id' required"],
            )

        if investigation_action == "open":
            if not user_id:
                return SkillResult(
                    success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                    errors=["'user_id' required to open investigation"],
                )

            profile = self.user_profiles.get(user_id, {})
            inv_id = f"INV-{uuid.uuid4().hex[:8]}"

            # Collect evidence summary (aggregated, privacy-preserving)
            recent_indicators = [
                i for i in profile.get("indicator_history", [])
                if self._days_since(i.get("detected_at", "")) < 90
            ]

            investigation = {
                "investigation_id": inv_id,
                "user_id": user_id,
                "status": InvestigationStatus.OPEN.value,
                "opened_at": datetime.now().isoformat(),
                "opened_by": self.agent_id,
                "risk_score_at_open": profile.get("risk_score", 0),
                "risk_level_at_open": profile.get("risk_level", "unknown"),
                "indicator_summary": {
                    "total_indicators_90d": len(recent_indicators),
                    "category_breakdown": self._category_breakdown(recent_indicators),
                    "highest_weight_indicators": sorted(
                        recent_indicators, key=lambda i: i.get("weight", 0), reverse=True
                    )[:5],
                },
                "timeline": [
                    {
                        "timestamp": datetime.now().isoformat(),
                        "action": "investigation_opened",
                        "actor": self.agent_id,
                        "notes": notes or "Investigation opened based on risk score threshold",
                    }
                ],
                "privacy_notice": (
                    "This investigation is subject to organizational privacy policy. "
                    "Only aggregated behavioral signals are collected — no content of "
                    "communications or documents is captured."
                ),
            }

            self.investigations[inv_id] = investigation

            return SkillResult(
                success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                data={"investigation": investigation},
            )

        elif investigation_action == "update":
            inv = self.investigations.get(investigation_id)
            if not inv:
                return SkillResult(
                    success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                    errors=[f"Investigation '{investigation_id}' not found"],
                )

            if status:
                inv["status"] = status
            if notes:
                inv["timeline"].append({
                    "timestamp": datetime.now().isoformat(),
                    "action": "note_added",
                    "actor": self.agent_id,
                    "notes": notes,
                })
            inv["updated_at"] = datetime.now().isoformat()

            return SkillResult(
                success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                data={"investigation": inv},
            )

        elif investigation_action == "close":
            inv = self.investigations.get(investigation_id)
            if not inv:
                return SkillResult(
                    success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                    errors=[f"Investigation '{investigation_id}' not found"],
                )

            close_status = status or InvestigationStatus.CLOSED_INCONCLUSIVE.value
            inv["status"] = close_status
            inv["closed_at"] = datetime.now().isoformat()
            inv["timeline"].append({
                "timestamp": datetime.now().isoformat(),
                "action": "investigation_closed",
                "actor": self.agent_id,
                "notes": notes or f"Closed as {close_status}",
                "status": close_status,
            })

            return SkillResult(
                success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                data={"investigation": inv},
            )

        return SkillResult(
            success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            errors=[f"Unknown investigation_action '{investigation_action}'. Use: open, update, close"],
        )

    # =========================================================================
    # Generate Report
    # =========================================================================

    async def _generate_report(self, params: Dict[str, Any]) -> SkillResult:
        """Generate insider threat assessment report."""
        user_id = params.get("user_id")
        include_indicators = params.get("include_indicators", True)

        if user_id:
            profile = self.user_profiles.get(user_id)
            if not profile:
                return SkillResult(
                    success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                    errors=[f"No profile for user '{user_id}'"],
                )

            recent = [
                i for i in profile.get("indicator_history", [])
                if self._days_since(i.get("detected_at", "")) < 90
            ]

            report = {
                "report_id": f"RPT-{uuid.uuid4().hex[:8]}",
                "report_type": "individual",
                "generated_at": datetime.now().isoformat(),
                "user_id": user_id,
                "risk_score": profile["risk_score"],
                "risk_level": profile["risk_level"],
                "risk_trend": self._calculate_trend(profile),
                "on_watchlist": user_id in self.watchlist,
                "active_investigation": any(
                    inv.get("user_id") == user_id and inv.get("status") in ("open", "in_progress", "escalated")
                    for inv in self.investigations.values()
                ),
                "indicator_summary": {
                    "total_indicators_90d": len(recent),
                    "category_breakdown": self._category_breakdown(recent),
                },
                "recommendations": self._user_recommendations(profile, recent),
                "privacy_notice": "Report contains aggregated behavioral signals only.",
            }

            if include_indicators:
                report["indicators"] = recent

        else:
            # Organization-wide report
            profiles = list(self.user_profiles.values())
            risk_distribution = {}
            for level in ["critical", "high", "medium", "low", "baseline"]:
                risk_distribution[level] = sum(1 for p in profiles if p.get("risk_level") == level)

            report = {
                "report_id": f"RPT-{uuid.uuid4().hex[:8]}",
                "report_type": "organization",
                "generated_at": datetime.now().isoformat(),
                "summary": {
                    "total_users_monitored": len(profiles),
                    "risk_distribution": risk_distribution,
                    "average_risk_score": round(
                        sum(p.get("risk_score", 0) for p in profiles) / len(profiles), 1
                    ) if profiles else 0,
                    "watchlist_size": len(self.watchlist),
                    "active_alerts": len([a for a in self.alerts if not a.get("resolved")]),
                    "open_investigations": sum(
                        1 for inv in self.investigations.values()
                        if inv.get("status") in ("open", "in_progress", "escalated")
                    ),
                    "total_indicators_30d": sum(
                        1 for i in self.indicators
                        if self._days_since(i.get("detected_at", "")) < 30
                    ),
                },
                "top_risk_users": sorted(
                    [{"user_id": p["user_id"], "risk_score": p["risk_score"], "risk_level": p["risk_level"]} for p in profiles],
                    key=lambda x: x["risk_score"], reverse=True
                )[:10],
                "most_common_indicators": self._most_common_indicators(),
                "recommendations": self._org_recommendations(profiles),
                "privacy_notice": "Report contains aggregated organizational risk metrics only.",
            }

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={"report": report},
        )

    # =========================================================================
    # Internal Helpers
    # =========================================================================

    def _default_baseline(self) -> Dict[str, Any]:
        """Return a default behavioral baseline."""
        return {
            "avg_login_hour": 9,
            "login_hour_stddev": 2,
            "avg_daily_logins": 3,
            "daily_logins_stddev": 1.5,
            "avg_daily_file_access": 50,
            "file_access_stddev": 20,
            "avg_daily_download_mb": 100,
            "download_stddev": 50,
            "avg_daily_email_attachments": 5,
            "email_attachment_stddev": 3,
            "normal_locations": [],
            "normal_systems": [],
            "work_hours_start": 8,
            "work_hours_end": 18,
        }

    def _evaluate_event(self, event_type: str, details: Dict[str, Any], baseline: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Evaluate a single event against the baseline."""
        indicators = []

        if event_type == "login":
            hour = details.get("hour", 12)
            location = details.get("location", "")
            avg_hour = baseline.get("avg_login_hour", 9)
            hour_stddev = baseline.get("login_hour_stddev", 2)

            # Unusual time check
            if hour_stddev > 0:
                z_score = abs(hour - avg_hour) / hour_stddev
                if z_score > 2.5:
                    ind_def = INDICATOR_DEFINITIONS["unusual_login_time"]
                    indicators.append(self._build_indicator("unusual_login_time", ind_def, {
                        "login_hour": hour, "baseline_avg": avg_hour, "z_score": round(z_score, 2),
                    }, confidence=min(95, 50 + z_score * 15)))

            # Unusual location check
            normal_locs = baseline.get("normal_locations", [])
            if location and normal_locs and location not in normal_locs:
                ind_def = INDICATOR_DEFINITIONS["unusual_login_location"]
                indicators.append(self._build_indicator("unusual_login_location", ind_def, {
                    "location": location, "normal_locations": normal_locs,
                }, confidence=75))

        elif event_type == "file_access":
            count = details.get("count", 0)
            avg = baseline.get("avg_daily_file_access", 50)
            stddev = baseline.get("file_access_stddev", 20)
            if stddev > 0 and count > 0:
                z_score = (count - avg) / stddev
                if z_score > 2.0:
                    ind_def = INDICATOR_DEFINITIONS["sensitive_data_access_spike"]
                    indicators.append(self._build_indicator("sensitive_data_access_spike", ind_def, {
                        "access_count": count, "baseline_avg": avg, "z_score": round(z_score, 2),
                    }, confidence=min(95, 50 + z_score * 12)))

        elif event_type == "download":
            volume_mb = details.get("volume_mb", 0)
            avg = baseline.get("avg_daily_download_mb", 100)
            stddev = baseline.get("download_stddev", 50)
            if stddev > 0 and volume_mb > 0:
                z_score = (volume_mb - avg) / stddev
                if z_score > 2.0:
                    ind_def = INDICATOR_DEFINITIONS["large_download"]
                    indicators.append(self._build_indicator("large_download", ind_def, {
                        "volume_mb": volume_mb, "baseline_avg": avg, "z_score": round(z_score, 2),
                    }, confidence=min(95, 50 + z_score * 12)))

        elif event_type == "privilege_change":
            ind_def = INDICATOR_DEFINITIONS.get(details.get("indicator_type", "privilege_escalation_attempt"),
                                                 INDICATOR_DEFINITIONS["privilege_escalation_attempt"])
            indicators.append(self._build_indicator(
                details.get("indicator_type", "privilege_escalation_attempt"),
                ind_def, details, confidence=details.get("confidence", 80)))

        elif event_type == "policy_violation":
            violation_type = details.get("violation_type", "unauthorized_tool_usage")
            ind_def = INDICATOR_DEFINITIONS.get(violation_type, INDICATOR_DEFINITIONS.get("unauthorized_tool_usage"))
            if ind_def:
                indicators.append(self._build_indicator(violation_type, ind_def, details, confidence=85))

        elif event_type == "usb_transfer":
            ind_def = INDICATOR_DEFINITIONS["usb_large_transfer"]
            indicators.append(self._build_indicator("usb_large_transfer", ind_def, details, confidence=90))

        elif event_type == "cloud_upload":
            ind_def = INDICATOR_DEFINITIONS["cloud_upload_spike"]
            indicators.append(self._build_indicator("cloud_upload_spike", ind_def, details, confidence=75))

        # Check for matched indicator definitions by event type directly
        if event_type in INDICATOR_DEFINITIONS and not indicators:
            ind_def = INDICATOR_DEFINITIONS[event_type]
            indicators.append(self._build_indicator(event_type, ind_def, details, confidence=70))

        return indicators

    def _build_indicator(self, indicator_type: str, definition: Dict[str, Any],
                         details: Dict[str, Any], confidence: float = 70.0) -> Dict[str, Any]:
        """Build a standardized indicator dict."""
        return {
            "indicator_id": f"IND-{uuid.uuid4().hex[:8]}",
            "indicator_type": indicator_type,
            "category": definition["category"],
            "description": definition["description"],
            "weight": definition["base_weight"],
            "confidence": round(min(100, max(0, confidence)), 1),
            "privacy_level": definition["privacy_level"],
            "mitre_technique": definition.get("mitre_technique"),
            "source": "behavioral_analysis",
            "details": details,
        }

    def _compare_to_baseline(self, user_id: str, metrics: Dict[str, Any],
                             baseline: Dict[str, Any], threshold: float) -> List[Dict[str, Any]]:
        """Compare user metrics to baseline, flagging deviations beyond threshold standard deviations."""
        anomalies = []

        metric_mappings = [
            ("daily_logins", "avg_daily_logins", "daily_logins_stddev", "failed_login_spike"),
            ("daily_file_access", "avg_daily_file_access", "file_access_stddev", "sensitive_data_access_spike"),
            ("daily_download_mb", "avg_daily_download_mb", "download_stddev", "large_download"),
            ("daily_email_attachments", "avg_daily_email_attachments", "email_attachment_stddev", "large_email_attachment"),
        ]

        for metric_key, avg_key, stddev_key, indicator_type in metric_mappings:
            value = metrics.get(metric_key)
            if value is None:
                continue

            avg = baseline.get(avg_key, 0)
            stddev = baseline.get(stddev_key, 1)
            if stddev <= 0:
                stddev = 1

            z_score = (value - avg) / stddev
            if z_score > threshold:
                ind_def = INDICATOR_DEFINITIONS.get(indicator_type, {
                    "category": IndicatorCategory.BEHAVIORAL_CHANGE.value,
                    "description": f"Anomalous {metric_key}",
                    "base_weight": 4,
                    "privacy_level": "medium",
                    "mitre_technique": None,
                })
                anomalies.append({
                    "user_id": user_id,
                    "metric": metric_key,
                    "value": value,
                    "baseline_avg": avg,
                    "baseline_stddev": stddev,
                    "z_score": round(z_score, 2),
                    "indicator_type": indicator_type,
                    "category": ind_def.get("category", IndicatorCategory.BEHAVIORAL_CHANGE.value),
                    "detected_at": datetime.now().isoformat(),
                })

        return anomalies

    def _calculate_user_risk(self, profile: Dict[str, Any]) -> float:
        """Calculate risk score with time-based decay."""
        score = 0.0
        for indicator in profile.get("indicator_history", []):
            weight = indicator.get("weight", 0)
            confidence = indicator.get("confidence", 50) / 100
            decay = self._decay_factor(indicator.get("detected_at", ""))
            score += weight * confidence * decay

        # Watchlist bonus: being on watchlist doesn't increase score, but we cap
        # Normalize to 0-100
        return min(100.0, round(score, 1))

    def _decay_factor(self, timestamp_str: str) -> float:
        """Calculate exponential decay factor based on age of indicator."""
        days = self._days_since(timestamp_str)
        if days <= 0:
            return 1.0
        # Exponential decay with configurable half-life
        return math.pow(0.5, days / RISK_DECAY_HALF_LIFE_DAYS)

    def _days_since(self, timestamp_str: str) -> float:
        """Calculate days since a timestamp."""
        if not timestamp_str:
            return 0
        try:
            ts = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
            now = datetime.now(ts.tzinfo) if ts.tzinfo else datetime.now()
            return max(0, (now - ts).total_seconds() / 86400)
        except (ValueError, TypeError):
            return 0

    def _score_to_risk_level(self, score: float) -> str:
        """Convert numeric risk score to risk level."""
        if score >= 80:
            return RiskLevel.CRITICAL.value
        elif score >= 60:
            return RiskLevel.HIGH.value
        elif score >= 35:
            return RiskLevel.MEDIUM.value
        elif score >= 15:
            return RiskLevel.LOW.value
        return RiskLevel.BASELINE.value

    def _calculate_trend(self, profile: Dict[str, Any]) -> str:
        """Calculate risk trend (increasing, stable, decreasing)."""
        history = profile.get("indicator_history", [])
        if len(history) < 2:
            return "insufficient_data"

        # Compare indicators in last 30 days vs 30-60 days ago
        recent = sum(1 for i in history if self._days_since(i.get("detected_at", "")) < 30)
        older = sum(1 for i in history if 30 <= self._days_since(i.get("detected_at", "")) < 60)

        if recent > older * 1.5:
            return "increasing"
        elif recent < older * 0.5:
            return "decreasing"
        return "stable"

    def _recommend_response(self, risk_score: float, indicators: List[Dict[str, Any]]) -> str:
        """Generate a recommended response based on risk score and indicators."""
        if risk_score >= 80:
            return "IMMEDIATE: Escalate to security management. Consider temporary access restriction. Open formal investigation."
        elif risk_score >= 60:
            return "HIGH: Open investigation. Increase monitoring. Review recent access patterns and data movements."
        elif risk_score >= 35:
            return "MEDIUM: Add to watchlist with enhanced monitoring. Review indicators at next triage cycle."
        return "LOW: Continue standard monitoring. No action required."

    def _category_breakdown(self, indicators: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count indicators by category."""
        counts: Dict[str, int] = {}
        for ind in indicators:
            cat = ind.get("category", "unknown")
            counts[cat] = counts.get(cat, 0) + 1
        return counts

    def _most_common_indicators(self) -> List[Dict[str, Any]]:
        """Find most common indicator types across all users."""
        type_counts: Dict[str, int] = {}
        for ind in self.indicators:
            it = ind.get("indicator_type", "unknown")
            type_counts[it] = type_counts.get(it, 0) + 1
        return [
            {"indicator_type": k, "count": v}
            for k, v in sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        ]

    def _user_recommendations(self, profile: Dict[str, Any], recent_indicators: List[Dict[str, Any]]) -> List[str]:
        """Generate user-specific recommendations."""
        recs = []
        risk_score = profile.get("risk_score", 0)

        if risk_score >= 60:
            recs.append("Initiate formal investigation with appropriate privacy safeguards.")
        if any(i.get("category") == IndicatorCategory.DATA_EXFILTRATION.value for i in recent_indicators):
            recs.append("Review DLP alerts and data transfer logs for potential data exfiltration.")
        if any(i.get("category") == IndicatorCategory.PRIVILEGE_ABUSE.value for i in recent_indicators):
            recs.append("Audit user permissions and recent privilege changes. Apply least-privilege.")
        if any(i.get("category") == IndicatorCategory.HR_CORRELATION.value for i in recent_indicators):
            recs.append("Coordinate with HR for context. Departing employee protocols may apply.")
        if not recs:
            recs.append("Continue standard monitoring. Review at next assessment cycle.")
        return recs

    def _org_recommendations(self, profiles: List[Dict[str, Any]]) -> List[str]:
        """Generate organization-level recommendations."""
        recs = []
        high_risk = sum(1 for p in profiles if p.get("risk_score", 0) >= 60)
        if high_risk:
            recs.append(f"{high_risk} user(s) at high/critical risk — ensure active investigation or enhanced monitoring.")

        recs.extend([
            "Review and update behavioral baselines quarterly as work patterns evolve.",
            "Coordinate insider threat indicators with HR departure and performance processes.",
            "Ensure DLP and endpoint monitoring controls are active for all high-risk users.",
            "Conduct insider threat awareness training for managers to recognize behavioral indicators.",
            "All monitoring activities must comply with organizational privacy policy and applicable regulations.",
        ])
        return recs
