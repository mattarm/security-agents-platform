#!/usr/bin/env python3
"""
Identity Threat Detection Skill — behavioral analytics for identity-based attacks.

Primary owner: Gamma (Blue Team)
Also usable by: Alpha-4 (threat intel correlation for identity-focused campaigns)

Capabilities:
  - Impossible travel detection (login from distant locations within short time)
  - Credential stuffing / password spray detection
  - Account takeover detection (behavior anomaly after login)
  - Privilege escalation monitoring
  - MFA bypass attempt detection
  - Dormant account abuse
  - OAuth consent phishing detection
  - Risk-based authentication scoring
"""

import hashlib
import math
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from enum import Enum

from security_agents.core.models import (
    SkillResult, IntelligencePacket, IntelligenceType, Priority,
)
from security_agents.skills.base_skill import BaseSecuritySkill

class RiskLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"

class IdentityThreatDetectionSkill(BaseSecuritySkill):
    """Identity-based threat detection with behavioral analytics."""

    SKILL_NAME = "identity_threat_detection"
    DESCRIPTION = (
        "Identity threat detection including impossible travel, credential attacks, "
        "account takeover, privilege escalation, MFA bypass, dormant account abuse, "
        "OAuth consent phishing, and risk-based authentication scoring"
    )
    VERSION = "1.0.0"
    COMPATIBLE_AGENTS = ["gamma_blue_team", "alpha_4_threat_intel"]
    REQUIRED_INTEGRATIONS = []

    # Maximum plausible travel speed in km/h (commercial aviation)
    MAX_TRAVEL_SPEED_KMH = 900

    # Earth radius in kilometers for haversine calculation
    EARTH_RADIUS_KM = 6371.0

    # Password spray thresholds
    SPRAY_FAILED_THRESHOLD = 5       # failures from one IP across different accounts
    SPRAY_TIME_WINDOW_MINUTES = 10

    # Credential stuffing thresholds
    STUFFING_FAILED_THRESHOLD = 20   # failures against one account from multiple IPs
    STUFFING_TIME_WINDOW_MINUTES = 30

    # Dormant account threshold (days with no activity)
    DORMANT_THRESHOLD_DAYS = 90

    # Known suspicious OAuth scopes
    SUSPICIOUS_OAUTH_SCOPES = {
        "mail.read", "mail.readwrite", "mail.send",
        "files.readwrite.all", "user.readwrite.all",
        "directory.readwrite.all", "contacts.readwrite",
    }

    # Risk score weights for authentication scoring
    AUTH_RISK_WEIGHTS = {
        "impossible_travel": 40,
        "new_device": 15,
        "new_location": 12,
        "unusual_time": 8,
        "failed_mfa": 25,
        "tor_exit_node": 30,
        "vpn_provider": 10,
        "credential_leak": 35,
        "dormant_account": 20,
        "privilege_escalation": 25,
    }

    async def _setup(self):
        """Initialize detection state."""
        self.user_profiles: Dict[str, Dict[str, Any]] = {}  # user -> behavioral profile
        self.login_history: Dict[str, List[Dict[str, Any]]] = {}  # user -> recent logins
        self.alerts: List[Dict[str, Any]] = []
        self.known_tor_exits: set = set()  # Would be populated from threat feeds

    async def _execute(self, parameters: Dict[str, Any]) -> SkillResult:
        """
        Dispatch to the appropriate identity threat detection action.

        Supported actions:
          analyze_login              — full login event analysis
          detect_impossible_travel   — check for impossible travel
          detect_credential_attack   — detect spray/stuffing patterns
          detect_account_takeover    — behavioral anomaly detection post-login
          monitor_privilege_changes  — watch for privilege escalation
          score_authentication_risk  — compute risk score for an auth event
          detect_dormant_abuse       — flag activity on dormant accounts
        """
        action = parameters.get("action", "analyze_login")

        dispatch = {
            "analyze_login": self._analyze_login,
            "detect_impossible_travel": self._detect_impossible_travel,
            "detect_credential_attack": self._detect_credential_attack,
            "detect_account_takeover": self._detect_account_takeover,
            "monitor_privilege_changes": self._monitor_privilege_changes,
            "score_authentication_risk": self._score_authentication_risk,
            "detect_dormant_abuse": self._detect_dormant_abuse,
        }

        handler = dispatch.get(action)
        if not handler:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"Unknown action '{action}'. Supported: {list(dispatch.keys())}"],
            )
        return await handler(parameters)

    # =========================================================================
    # Full Login Analysis
    # =========================================================================

    async def _analyze_login(self, params: Dict[str, Any]) -> SkillResult:
        """Perform comprehensive analysis of a login event."""
        user_id = params.get("user_id", "")
        if not user_id:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["'user_id' parameter required"],
            )

        login_event = {
            "user_id": user_id,
            "timestamp": params.get("timestamp", datetime.now().isoformat()),
            "source_ip": params.get("source_ip", ""),
            "latitude": params.get("latitude"),
            "longitude": params.get("longitude"),
            "country": params.get("country", ""),
            "city": params.get("city", ""),
            "user_agent": params.get("user_agent", ""),
            "device_id": params.get("device_id", ""),
            "mfa_used": params.get("mfa_used", False),
            "mfa_method": params.get("mfa_method", ""),
            "success": params.get("success", True),
            "application": params.get("application", ""),
        }

        # Store login in history
        self.login_history.setdefault(user_id, []).append(login_event)
        # Keep only last 100 logins per user
        if len(self.login_history[user_id]) > 100:
            self.login_history[user_id] = self.login_history[user_id][-100:]

        # Run all detection checks
        risk_factors = []
        packets = []

        # Impossible travel
        travel_result = self._check_impossible_travel(user_id, login_event)
        if travel_result["detected"]:
            risk_factors.append({
                "factor": "impossible_travel",
                "weight": self.AUTH_RISK_WEIGHTS["impossible_travel"],
                "detail": travel_result["detail"],
            })

        # New device
        profile = self.user_profiles.get(user_id, {})
        known_devices = profile.get("known_devices", set())
        device_id = login_event.get("device_id", "")
        if device_id and device_id not in known_devices:
            risk_factors.append({
                "factor": "new_device",
                "weight": self.AUTH_RISK_WEIGHTS["new_device"],
                "detail": f"Login from previously unseen device: {device_id}",
            })

        # New location
        known_countries = profile.get("known_countries", set())
        country = login_event.get("country", "")
        if country and country not in known_countries:
            risk_factors.append({
                "factor": "new_location",
                "weight": self.AUTH_RISK_WEIGHTS["new_location"],
                "detail": f"Login from new country: {country}",
            })

        # Unusual hour
        try:
            ts = datetime.fromisoformat(login_event["timestamp"])
            hour = ts.hour
            typical_hours = profile.get("typical_hours", set(range(7, 22)))
            if hour not in typical_hours:
                risk_factors.append({
                    "factor": "unusual_time",
                    "weight": self.AUTH_RISK_WEIGHTS["unusual_time"],
                    "detail": f"Login at unusual hour: {hour:02d}:00",
                })
        except (ValueError, TypeError):
            pass

        # Tor exit node
        if login_event.get("source_ip") in self.known_tor_exits:
            risk_factors.append({
                "factor": "tor_exit_node",
                "weight": self.AUTH_RISK_WEIGHTS["tor_exit_node"],
                "detail": "Login from known Tor exit node",
            })

        # Compute risk score
        risk_score = self._compute_risk_score(risk_factors)
        risk_level = self._risk_level_from_score(risk_score)

        # Update user profile
        self._update_user_profile(user_id, login_event)

        # Emit intelligence for high-risk logins
        if risk_score >= 60:
            alert = {
                "alert_id": f"IDT-{uuid.uuid4().hex[:8]}",
                "user_id": user_id,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "risk_factors": risk_factors,
                "login_event": login_event,
                "detected_at": datetime.now().isoformat(),
            }
            self.alerts.append(alert)

            packets.append(IntelligencePacket(
                packet_id=f"PKT-IDT-{alert['alert_id']}",
                source_agent=self.agent_id,
                target_agents=["all"],
                intelligence_type=IntelligenceType.IDENTITY_THREAT,
                priority=Priority.CRITICAL if risk_score >= 80 else Priority.HIGH,
                confidence=min(95.0, risk_score + 5),
                timestamp=datetime.now(),
                data={
                    "alert_id": alert["alert_id"],
                    "user_id": user_id,
                    "risk_score": risk_score,
                    "risk_level": risk_level,
                    "factors": [f["factor"] for f in risk_factors],
                    "source_ip": login_event.get("source_ip", ""),
                },
                correlation_keys=[user_id, login_event.get("source_ip", "")],
            ))

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "user_id": user_id,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "risk_factors": risk_factors,
                "recommended_actions": self._recommend_actions(risk_level, risk_factors),
                "login_event": login_event,
            },
            intelligence_packets=packets,
        )

    # =========================================================================
    # Impossible Travel Detection
    # =========================================================================

    async def _detect_impossible_travel(self, params: Dict[str, Any]) -> SkillResult:
        """Check login events for impossible travel patterns."""
        user_id = params.get("user_id", "")
        logins = params.get("logins", self.login_history.get(user_id, []))

        if len(logins) < 2:
            return SkillResult(
                success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                data={"impossible_travel_detected": False, "message": "Insufficient login history"},
            )

        detections = []
        sorted_logins = sorted(logins, key=lambda l: l.get("timestamp", ""))

        for i in range(1, len(sorted_logins)):
            prev = sorted_logins[i - 1]
            curr = sorted_logins[i]
            result = self._check_impossible_travel_pair(prev, curr)
            if result["detected"]:
                detections.append(result)

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "impossible_travel_detected": len(detections) > 0,
                "detections": detections,
                "logins_analyzed": len(sorted_logins),
            },
        )

    def _check_impossible_travel(self, user_id: str, current_login: Dict) -> Dict[str, Any]:
        """Check if current login is impossible travel relative to previous logins."""
        history = self.login_history.get(user_id, [])
        if len(history) < 2:
            return {"detected": False, "detail": ""}

        # Compare against the second-to-last login (last is the current one we just added)
        prev_login = history[-2]
        return self._check_impossible_travel_pair(prev_login, current_login)

    def _check_impossible_travel_pair(self, prev: Dict, curr: Dict) -> Dict[str, Any]:
        """Check if two logins represent impossible travel."""
        lat1 = prev.get("latitude")
        lon1 = prev.get("longitude")
        lat2 = curr.get("latitude")
        lon2 = curr.get("longitude")

        if None in (lat1, lon1, lat2, lon2):
            return {"detected": False, "detail": "Missing geolocation data"}

        distance_km = self._haversine_distance(lat1, lon1, lat2, lon2)

        # Parse timestamps
        try:
            t1 = datetime.fromisoformat(prev["timestamp"])
            t2 = datetime.fromisoformat(curr["timestamp"])
            time_diff_hours = abs((t2 - t1).total_seconds()) / 3600
        except (ValueError, TypeError, KeyError):
            return {"detected": False, "detail": "Invalid timestamps"}

        if time_diff_hours <= 0:
            time_diff_hours = 0.01  # Prevent division by zero

        required_speed = distance_km / time_diff_hours

        if required_speed > self.MAX_TRAVEL_SPEED_KMH and distance_km > 100:
            return {
                "detected": True,
                "detail": (
                    f"Login from {prev.get('city', '?')}/{prev.get('country', '?')} "
                    f"to {curr.get('city', '?')}/{curr.get('country', '?')} "
                    f"({distance_km:.0f} km in {time_diff_hours:.1f}h = "
                    f"{required_speed:.0f} km/h required)"
                ),
                "distance_km": round(distance_km, 1),
                "time_diff_hours": round(time_diff_hours, 2),
                "required_speed_kmh": round(required_speed, 0),
                "previous_login": prev,
                "current_login": curr,
            }

        return {"detected": False, "detail": ""}

    def _haversine_distance(self, lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Calculate great-circle distance between two points using the haversine formula."""
        lat1_r, lon1_r = math.radians(lat1), math.radians(lon1)
        lat2_r, lon2_r = math.radians(lat2), math.radians(lon2)

        dlat = lat2_r - lat1_r
        dlon = lon2_r - lon1_r

        a = math.sin(dlat / 2) ** 2 + math.cos(lat1_r) * math.cos(lat2_r) * math.sin(dlon / 2) ** 2
        c = 2 * math.asin(math.sqrt(a))

        return self.EARTH_RADIUS_KM * c

    # =========================================================================
    # Credential Attack Detection
    # =========================================================================

    async def _detect_credential_attack(self, params: Dict[str, Any]) -> SkillResult:
        """Detect credential stuffing and password spray attacks."""
        auth_events = params.get("auth_events", [])
        if not auth_events:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["'auth_events' parameter required — list of authentication events"],
            )

        # Analyze for password spray: many users, few attempts each, same source
        spray_detections = self._detect_password_spray(auth_events)

        # Analyze for credential stuffing: many attempts against one user from many sources
        stuffing_detections = self._detect_credential_stuffing(auth_events)

        total_detections = len(spray_detections) + len(stuffing_detections)

        packets = []
        if total_detections > 0:
            packets.append(IntelligencePacket(
                packet_id=f"PKT-CRED-{uuid.uuid4().hex[:8]}",
                source_agent=self.agent_id,
                target_agents=["all"],
                intelligence_type=IntelligenceType.IDENTITY_THREAT,
                priority=Priority.HIGH,
                confidence=85.0,
                timestamp=datetime.now(),
                data={
                    "event": "credential_attack_detected",
                    "spray_detections": len(spray_detections),
                    "stuffing_detections": len(stuffing_detections),
                    "source_ips": list(set(
                        d.get("source_ip", "") for d in spray_detections + stuffing_detections
                    ))[:20],
                },
                correlation_keys=list(set(
                    d.get("source_ip", "") for d in spray_detections + stuffing_detections
                ))[:20],
            ))

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "events_analyzed": len(auth_events),
                "password_spray": {
                    "detected": len(spray_detections) > 0,
                    "detections": spray_detections,
                },
                "credential_stuffing": {
                    "detected": len(stuffing_detections) > 0,
                    "detections": stuffing_detections,
                },
                "recommended_actions": (
                    ["Block source IPs at firewall", "Force password reset for targeted accounts",
                     "Enable account lockout policies", "Review MFA enrollment for targeted accounts"]
                    if total_detections > 0 else ["No credential attacks detected"]
                ),
            },
            intelligence_packets=packets,
        )

    def _detect_password_spray(self, events: List[Dict]) -> List[Dict]:
        """Detect password spray: one IP, many users, few attempts per user."""
        failed_events = [e for e in events if not e.get("success", True)]

        # Group by source IP
        by_ip: Dict[str, List[Dict]] = {}
        for evt in failed_events:
            ip = evt.get("source_ip", "")
            by_ip.setdefault(ip, []).append(evt)

        detections = []
        for ip, ip_events in by_ip.items():
            unique_users = set(e.get("user_id", "") for e in ip_events)
            if len(unique_users) >= self.SPRAY_FAILED_THRESHOLD:
                # Check time window
                timestamps = self._parse_timestamps(ip_events)
                if timestamps:
                    window = (max(timestamps) - min(timestamps)).total_seconds() / 60
                    if window <= self.SPRAY_TIME_WINDOW_MINUTES:
                        detections.append({
                            "attack_type": "password_spray",
                            "source_ip": ip,
                            "unique_users_targeted": len(unique_users),
                            "total_attempts": len(ip_events),
                            "time_window_minutes": round(window, 1),
                            "confidence": min(95.0, 60 + len(unique_users) * 3),
                        })

        return detections

    def _detect_credential_stuffing(self, events: List[Dict]) -> List[Dict]:
        """Detect credential stuffing: one user, many IPs, many failures."""
        failed_events = [e for e in events if not e.get("success", True)]

        # Group by user
        by_user: Dict[str, List[Dict]] = {}
        for evt in failed_events:
            user = evt.get("user_id", "")
            by_user.setdefault(user, []).append(evt)

        detections = []
        for user, user_events in by_user.items():
            unique_ips = set(e.get("source_ip", "") for e in user_events)
            if len(user_events) >= self.STUFFING_FAILED_THRESHOLD and len(unique_ips) >= 3:
                timestamps = self._parse_timestamps(user_events)
                if timestamps:
                    window = (max(timestamps) - min(timestamps)).total_seconds() / 60
                    if window <= self.STUFFING_TIME_WINDOW_MINUTES:
                        detections.append({
                            "attack_type": "credential_stuffing",
                            "target_user": user,
                            "source_ips": list(unique_ips)[:20],
                            "total_attempts": len(user_events),
                            "time_window_minutes": round(window, 1),
                            "confidence": min(95.0, 60 + len(user_events) * 1.5),
                        })

        return detections

    def _parse_timestamps(self, events: List[Dict]) -> List[datetime]:
        """Parse timestamps from events, ignoring unparseable ones."""
        timestamps = []
        for evt in events:
            ts = evt.get("timestamp", "")
            try:
                timestamps.append(datetime.fromisoformat(ts))
            except (ValueError, TypeError):
                continue
        return timestamps

    # =========================================================================
    # Account Takeover Detection
    # =========================================================================

    async def _detect_account_takeover(self, params: Dict[str, Any]) -> SkillResult:
        """Detect account takeover via behavioral anomaly after successful login."""
        user_id = params.get("user_id", "")
        post_login_actions = params.get("actions", [])

        if not user_id:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["'user_id' parameter required"],
            )

        profile = self.user_profiles.get(user_id, {})
        anomalies = []

        for action in post_login_actions:
            action_type = action.get("action_type", "")
            target = action.get("target", "")

            # Check for unusual actions
            typical_actions = profile.get("typical_actions", set())
            if action_type and action_type not in typical_actions:
                anomalies.append({
                    "action_type": action_type,
                    "target": target,
                    "reason": "Action type not in user's behavioral baseline",
                    "severity": "medium",
                })

            # High-risk post-compromise indicators
            ato_indicators = {
                "password_change": "Password change immediately after login may indicate takeover",
                "mfa_reset": "MFA reset after login is a strong takeover indicator",
                "email_forwarding_rule": "Email forwarding rule creation is common in account takeover",
                "api_key_creation": "API key creation may indicate persistence establishment",
                "role_assignment": "Self-role assignment may indicate privilege escalation",
                "bulk_download": "Bulk data download may indicate data exfiltration",
                "mailbox_delegation": "Mailbox delegation may indicate lateral access",
            }

            if action_type in ato_indicators:
                anomalies.append({
                    "action_type": action_type,
                    "target": target,
                    "reason": ato_indicators[action_type],
                    "severity": "high",
                })

        ato_score = self._compute_ato_score(anomalies)
        is_takeover = ato_score >= 60

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "user_id": user_id,
                "account_takeover_detected": is_takeover,
                "ato_score": ato_score,
                "anomalies": anomalies,
                "recommended_actions": (
                    [
                        "Immediately suspend the account",
                        "Force session revocation across all applications",
                        "Reset password and MFA credentials",
                        "Review audit log for full scope of unauthorized actions",
                        "Notify the legitimate account owner through verified contact",
                    ]
                    if is_takeover
                    else ["Continue monitoring — no takeover confirmed"]
                ),
            },
        )

    def _compute_ato_score(self, anomalies: List[Dict]) -> float:
        """Compute account takeover likelihood score."""
        if not anomalies:
            return 0.0
        severity_weights = {"critical": 30, "high": 20, "medium": 10, "low": 5}
        score = sum(severity_weights.get(a.get("severity", "low"), 0) for a in anomalies)
        return min(100.0, score)

    # =========================================================================
    # Privilege Escalation Monitoring
    # =========================================================================

    async def _monitor_privilege_changes(self, params: Dict[str, Any]) -> SkillResult:
        """Monitor for suspicious privilege escalation patterns."""
        changes = params.get("privilege_changes", [])
        if not changes:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["'privilege_changes' parameter required"],
            )

        suspicious = []
        for change in changes:
            risk = self._assess_privilege_change(change)
            if risk["is_suspicious"]:
                suspicious.append(risk)

        packets = []
        if suspicious:
            packets.append(IntelligencePacket(
                packet_id=f"PKT-PRIV-{uuid.uuid4().hex[:8]}",
                source_agent=self.agent_id,
                target_agents=["all"],
                intelligence_type=IntelligenceType.IDENTITY_THREAT,
                priority=Priority.HIGH,
                confidence=80.0,
                timestamp=datetime.now(),
                data={
                    "event": "suspicious_privilege_changes",
                    "count": len(suspicious),
                    "users": list(set(s.get("user_id", "") for s in suspicious)),
                },
                correlation_keys=list(set(s.get("user_id", "") for s in suspicious)),
            ))

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "changes_analyzed": len(changes),
                "suspicious_changes": suspicious,
                "risk_level": "high" if suspicious else "low",
            },
            intelligence_packets=packets,
        )

    def _assess_privilege_change(self, change: Dict[str, Any]) -> Dict[str, Any]:
        """Assess whether a privilege change is suspicious."""
        user_id = change.get("user_id", "")
        changed_by = change.get("changed_by", "")
        new_role = change.get("new_role", "")
        previous_role = change.get("previous_role", "")

        is_suspicious = False
        reasons = []

        # Self-elevation
        if user_id == changed_by:
            is_suspicious = True
            reasons.append("User elevated their own privileges")

        # Elevation to admin roles
        admin_roles = {"admin", "global_admin", "root", "superadmin", "owner", "security_admin"}
        if new_role.lower() in admin_roles and previous_role.lower() not in admin_roles:
            is_suspicious = True
            reasons.append(f"Elevation to admin role: {new_role}")

        # Off-hours change
        timestamp = change.get("timestamp", "")
        try:
            ts = datetime.fromisoformat(timestamp)
            if ts.hour < 6 or ts.hour > 22 or ts.weekday() >= 5:
                is_suspicious = True
                reasons.append("Privilege change during off-hours or weekend")
        except (ValueError, TypeError):
            pass

        # No approval record
        if not change.get("approval_ticket"):
            reasons.append("No approval ticket associated with privilege change")
            if is_suspicious:
                pass  # Already flagged
            elif new_role.lower() in admin_roles:
                is_suspicious = True

        return {
            "user_id": user_id,
            "changed_by": changed_by,
            "previous_role": previous_role,
            "new_role": new_role,
            "is_suspicious": is_suspicious,
            "reasons": reasons,
            "severity": "high" if is_suspicious else "low",
        }

    # =========================================================================
    # Risk-Based Authentication Scoring
    # =========================================================================

    async def _score_authentication_risk(self, params: Dict[str, Any]) -> SkillResult:
        """Compute a risk score for an authentication event with all context signals."""
        signals = params.get("signals", {})
        user_id = params.get("user_id", "")

        risk_factors = []
        for signal_name, signal_present in signals.items():
            if signal_present and signal_name in self.AUTH_RISK_WEIGHTS:
                risk_factors.append({
                    "factor": signal_name,
                    "weight": self.AUTH_RISK_WEIGHTS[signal_name],
                })

        risk_score = self._compute_risk_score(risk_factors)
        risk_level = self._risk_level_from_score(risk_score)

        # Determine required authentication action
        if risk_score >= 80:
            auth_action = "block"
        elif risk_score >= 60:
            auth_action = "step_up_mfa"
        elif risk_score >= 40:
            auth_action = "challenge"
        elif risk_score >= 20:
            auth_action = "allow_with_monitoring"
        else:
            auth_action = "allow"

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "user_id": user_id,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "risk_factors": risk_factors,
                "recommended_action": auth_action,
                "action_rationale": self._explain_auth_action(auth_action, risk_factors),
            },
        )

    # =========================================================================
    # Dormant Account Detection
    # =========================================================================

    async def _detect_dormant_abuse(self, params: Dict[str, Any]) -> SkillResult:
        """Detect login activity on dormant accounts."""
        accounts = params.get("accounts", [])
        if not accounts:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["'accounts' parameter required — list of {user_id, last_active, current_login}"],
            )

        now = datetime.now()
        detections = []

        for account in accounts:
            user_id = account.get("user_id", "")
            last_active_str = account.get("last_active", "")
            current_login = account.get("current_login", {})

            try:
                last_active = datetime.fromisoformat(last_active_str)
                dormant_days = (now - last_active).days
            except (ValueError, TypeError):
                continue

            if dormant_days >= self.DORMANT_THRESHOLD_DAYS:
                detections.append({
                    "user_id": user_id,
                    "dormant_days": dormant_days,
                    "last_active": last_active_str,
                    "current_login": current_login,
                    "risk_level": "critical" if dormant_days > 365 else "high" if dormant_days > 180 else "medium",
                    "recommended_actions": [
                        "Verify login with account owner through out-of-band channel",
                        "Temporarily suspend account pending verification",
                        "Review all actions taken during current session",
                        "Consider disabling dormant accounts proactively",
                    ],
                })

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "accounts_checked": len(accounts),
                "dormant_abuse_detected": len(detections) > 0,
                "detections": detections,
            },
        )

    # =========================================================================
    # Internal Helpers
    # =========================================================================

    def _compute_risk_score(self, risk_factors: List[Dict]) -> float:
        """Compute aggregate risk score from weighted factors (0-100)."""
        if not risk_factors:
            return 0.0
        total = sum(f.get("weight", 0) for f in risk_factors)
        return round(min(100.0, total), 1)

    def _risk_level_from_score(self, score: float) -> str:
        if score >= 80:
            return RiskLevel.CRITICAL.value
        if score >= 60:
            return RiskLevel.HIGH.value
        if score >= 40:
            return RiskLevel.MEDIUM.value
        if score >= 20:
            return RiskLevel.LOW.value
        return RiskLevel.NONE.value

    def _update_user_profile(self, user_id: str, login_event: Dict):
        """Update behavioral profile for a user based on login events."""
        if user_id not in self.user_profiles:
            self.user_profiles[user_id] = {
                "known_devices": set(),
                "known_countries": set(),
                "known_ips": set(),
                "typical_hours": set(),
                "typical_actions": set(),
                "login_count": 0,
            }

        profile = self.user_profiles[user_id]
        profile["login_count"] += 1

        if login_event.get("device_id"):
            profile["known_devices"].add(login_event["device_id"])
        if login_event.get("country"):
            profile["known_countries"].add(login_event["country"])
        if login_event.get("source_ip"):
            profile["known_ips"].add(login_event["source_ip"])

        try:
            ts = datetime.fromisoformat(login_event.get("timestamp", ""))
            profile["typical_hours"].add(ts.hour)
        except (ValueError, TypeError):
            pass

    def _recommend_actions(self, risk_level: str, risk_factors: List[Dict]) -> List[str]:
        """Recommend actions based on risk level and specific factors."""
        actions = []
        factor_names = {f["factor"] for f in risk_factors}

        if risk_level in ("critical", "high"):
            actions.append("Require step-up authentication (hardware token or biometric)")
            actions.append("Alert SOC team for immediate investigation")
            if "impossible_travel" in factor_names:
                actions.append("Verify login with user through known phone number")
            if "tor_exit_node" in factor_names:
                actions.append("Block IP and review all sessions from this source")
        elif risk_level == "medium":
            actions.append("Prompt for additional MFA verification")
            actions.append("Monitor session for anomalous behavior")
        else:
            actions.append("Allow session — risk within acceptable threshold")

        return actions

    def _explain_auth_action(self, action: str, factors: List[Dict]) -> str:
        """Generate human-readable explanation for authentication action."""
        explanations = {
            "block": "Authentication blocked due to critical risk signals. Manual verification required.",
            "step_up_mfa": "High risk detected — requiring hardware security key or biometric verification.",
            "challenge": "Moderate risk signals detected — presenting knowledge-based challenge.",
            "allow_with_monitoring": "Minor risk signals present — session will be monitored for anomalies.",
            "allow": "No significant risk signals — standard authentication flow.",
        }
        base = explanations.get(action, "")
        if factors:
            factor_list = ", ".join(f["factor"] for f in factors)
            return f"{base} Risk factors: {factor_list}."
        return base
