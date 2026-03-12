#!/usr/bin/env python3
"""
Incident Response Playbook Skill — Structured, automated incident response.

Primary owner: Gamma (Blue Team)
Also usable by: Sigma (metrics tracking)

Capabilities:
  - Playbook definition and management (YAML-based)
  - Incident classification to playbook mapping
  - Automated step execution with conditional logic
  - Evidence preservation during response
  - Containment orchestration
  - Post-incident analysis and reporting
  - SLA tracking and escalation
"""

import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from enum import Enum

from security_agents.core.models import (
    SkillResult, IntelligencePacket, IntelligenceType, Priority,
    Severity, IncidentCase,
)
from security_agents.skills.base_skill import BaseSecuritySkill

class PlaybookStepType(Enum):
    AUTOMATED = "automated"
    MANUAL = "manual"
    CONDITIONAL = "conditional"
    APPROVAL = "approval"
    NOTIFICATION = "notification"
    EVIDENCE = "evidence_collection"

class IncidentSeverity(Enum):
    P1_CRITICAL = "P1"
    P2_HIGH = "P2"
    P3_MEDIUM = "P3"
    P4_LOW = "P4"

class IncidentPhase(Enum):
    DETECTION = "detection"
    TRIAGE = "triage"
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    LESSONS_LEARNED = "lessons_learned"

class IncidentResponseSkill(BaseSecuritySkill):
    """Structured incident response with playbook automation."""

    SKILL_NAME = "incident_response"
    DESCRIPTION = "Playbook-driven incident response with automated containment, evidence collection, and SLA tracking"
    VERSION = "1.0.0"
    COMPATIBLE_AGENTS = ["gamma_blue_team", "sigma_metrics"]
    REQUIRED_INTEGRATIONS = []

    # SLA definitions by severity
    SLAS = {
        "P1": {"response_minutes": 15, "containment_minutes": 60, "resolution_hours": 4},
        "P2": {"response_minutes": 30, "containment_minutes": 120, "resolution_hours": 8},
        "P3": {"response_minutes": 120, "containment_minutes": 480, "resolution_hours": 24},
        "P4": {"response_minutes": 480, "containment_minutes": 1440, "resolution_hours": 72},
    }

    # Built-in playbooks
    PLAYBOOKS = {
        "malware_infection": {
            "name": "Malware Infection Response",
            "description": "Respond to confirmed or suspected malware infection",
            "classification": "malware",
            "severity_default": "P2",
            "phases": {
                "detection": [
                    {"step": "Validate alert and confirm malware indicators", "type": "automated", "tool": "edr"},
                    {"step": "Identify affected host(s) and user(s)", "type": "automated", "tool": "siem"},
                    {"step": "Determine malware family and capabilities", "type": "automated", "tool": "threat_intel"},
                ],
                "triage": [
                    {"step": "Assess blast radius — other hosts with same IOCs", "type": "automated", "tool": "edr"},
                    {"step": "Classify severity based on system criticality", "type": "automated"},
                    {"step": "Notify SOC lead and assign analyst", "type": "notification", "target": "soc_lead"},
                ],
                "containment": [
                    {"step": "Isolate affected host(s) from network", "type": "automated", "tool": "edr", "action": "network_isolate"},
                    {"step": "Block malware C2 domains/IPs at firewall", "type": "automated", "tool": "firewall", "action": "block_iocs"},
                    {"step": "Disable compromised user account(s)", "type": "approval", "approver": "soc_lead", "action": "disable_account"},
                    {"step": "Block malware hash in EDR", "type": "automated", "tool": "edr", "action": "block_hash"},
                ],
                "eradication": [
                    {"step": "Run full malware scan on isolated host", "type": "automated", "tool": "edr"},
                    {"step": "Remove persistence mechanisms", "type": "manual"},
                    {"step": "Verify no lateral movement occurred", "type": "automated", "tool": "siem"},
                    {"step": "Reset credentials for affected users", "type": "automated", "tool": "iam", "action": "reset_password"},
                ],
                "recovery": [
                    {"step": "Restore host from clean image or remove isolation", "type": "approval", "approver": "soc_lead"},
                    {"step": "Monitor for reinfection (48-hour watch)", "type": "automated", "tool": "siem"},
                    {"step": "Confirm host is clean and operational", "type": "manual"},
                ],
                "lessons_learned": [
                    {"step": "Document timeline and root cause", "type": "manual"},
                    {"step": "Update detection rules based on findings", "type": "manual"},
                    {"step": "Generate incident report", "type": "automated"},
                ],
            },
        },
        "phishing_compromise": {
            "name": "Phishing Compromise Response",
            "description": "Respond to successful phishing attack with credential or system compromise",
            "classification": "phishing",
            "severity_default": "P2",
            "phases": {
                "detection": [
                    {"step": "Identify phishing email and extract IOCs", "type": "automated", "tool": "email_gateway"},
                    {"step": "Determine who received and who clicked", "type": "automated", "tool": "email_gateway"},
                    {"step": "Classify attack type (credential harvest, malware, BEC)", "type": "automated"},
                ],
                "triage": [
                    {"step": "Assess number of compromised users", "type": "automated", "tool": "siem"},
                    {"step": "Check for credential use from unusual locations", "type": "automated", "tool": "iam"},
                    {"step": "Assign severity based on compromise scope", "type": "automated"},
                ],
                "containment": [
                    {"step": "Block sender domain in email gateway", "type": "automated", "tool": "email_gateway", "action": "block_domain"},
                    {"step": "Quarantine phishing email from all mailboxes", "type": "automated", "tool": "email_gateway", "action": "quarantine"},
                    {"step": "Force password reset for compromised users", "type": "automated", "tool": "iam", "action": "reset_password"},
                    {"step": "Revoke active sessions for compromised users", "type": "automated", "tool": "iam", "action": "revoke_sessions"},
                    {"step": "Block harvesting URLs at proxy/firewall", "type": "automated", "tool": "firewall", "action": "block_urls"},
                ],
                "eradication": [
                    {"step": "Check for unauthorized inbox rules or forwarding", "type": "automated", "tool": "email_gateway"},
                    {"step": "Review OAuth app consents for compromised accounts", "type": "automated", "tool": "iam"},
                    {"step": "Scan endpoints of users who clicked for malware", "type": "automated", "tool": "edr"},
                ],
                "recovery": [
                    {"step": "Re-enable accounts with new credentials and MFA", "type": "automated", "tool": "iam"},
                    {"step": "Monitor for additional phishing from same campaign", "type": "automated", "tool": "email_gateway"},
                    {"step": "Notify affected users with guidance", "type": "notification", "target": "affected_users"},
                ],
                "lessons_learned": [
                    {"step": "Update phishing detection rules", "type": "manual"},
                    {"step": "Schedule targeted security awareness training", "type": "manual"},
                    {"step": "Generate incident report", "type": "automated"},
                ],
            },
        },
        "data_breach": {
            "name": "Data Breach Response",
            "description": "Respond to confirmed or suspected data exfiltration",
            "classification": "data_breach",
            "severity_default": "P1",
            "phases": {
                "detection": [
                    {"step": "Validate data exfiltration indicators", "type": "automated", "tool": "dlp"},
                    {"step": "Identify affected data classifications", "type": "automated", "tool": "dlp"},
                    {"step": "Determine exfiltration method and destination", "type": "automated", "tool": "siem"},
                ],
                "triage": [
                    {"step": "Classify data sensitivity (PII, PHI, financial, IP)", "type": "manual"},
                    {"step": "Estimate volume of data exfiltrated", "type": "automated", "tool": "siem"},
                    {"step": "Identify regulatory notification requirements", "type": "manual"},
                    {"step": "Escalate to CISO and legal", "type": "notification", "target": "executive"},
                ],
                "containment": [
                    {"step": "Block exfiltration destination at network boundary", "type": "automated", "tool": "firewall", "action": "block_iocs"},
                    {"step": "Isolate source system(s)", "type": "automated", "tool": "edr", "action": "network_isolate"},
                    {"step": "Revoke access for compromised accounts", "type": "automated", "tool": "iam", "action": "disable_account"},
                    {"step": "Preserve forensic evidence", "type": "evidence_collection"},
                ],
                "eradication": [
                    {"step": "Identify and remediate root cause of access", "type": "manual"},
                    {"step": "Remove any data staging artifacts", "type": "manual"},
                    {"step": "Patch or close exploited vulnerability", "type": "manual"},
                ],
                "recovery": [
                    {"step": "Restore affected systems from clean state", "type": "manual"},
                    {"step": "Implement additional access controls", "type": "manual"},
                    {"step": "Begin regulatory notification process", "type": "manual"},
                ],
                "lessons_learned": [
                    {"step": "Complete forensic investigation report", "type": "manual"},
                    {"step": "Implement DLP rule improvements", "type": "manual"},
                    {"step": "Update incident response procedures", "type": "manual"},
                    {"step": "Generate board-level incident report", "type": "automated"},
                ],
            },
        },
        "unauthorized_access": {
            "name": "Unauthorized Access Response",
            "description": "Respond to unauthorized access to systems or data",
            "classification": "unauthorized_access",
            "severity_default": "P2",
            "phases": {
                "detection": [
                    {"step": "Validate unauthorized access indicators", "type": "automated", "tool": "siem"},
                    {"step": "Identify affected systems and accounts", "type": "automated", "tool": "iam"},
                ],
                "triage": [
                    {"step": "Determine access method (credential compromise, vulnerability, insider)", "type": "automated"},
                    {"step": "Assess what data/systems were accessed", "type": "automated", "tool": "siem"},
                ],
                "containment": [
                    {"step": "Disable compromised accounts", "type": "automated", "tool": "iam", "action": "disable_account"},
                    {"step": "Block source IPs at firewall", "type": "automated", "tool": "firewall", "action": "block_iocs"},
                    {"step": "Revoke VPN/remote access tokens", "type": "automated", "tool": "iam", "action": "revoke_sessions"},
                ],
                "eradication": [
                    {"step": "Reset all credentials for affected accounts", "type": "automated", "tool": "iam", "action": "reset_password"},
                    {"step": "Check for persistence mechanisms", "type": "automated", "tool": "edr"},
                    {"step": "Review and revoke unauthorized permissions", "type": "manual"},
                ],
                "recovery": [
                    {"step": "Re-enable accounts with MFA enforcement", "type": "automated", "tool": "iam"},
                    {"step": "Monitor for repeat unauthorized access", "type": "automated", "tool": "siem"},
                ],
                "lessons_learned": [
                    {"step": "Review access control policies", "type": "manual"},
                    {"step": "Generate incident report", "type": "automated"},
                ],
            },
        },
    }

    async def _setup(self):
        self.active_incidents: Dict[str, Dict[str, Any]] = {}
        self.incident_history: List[Dict[str, Any]] = []
        self.evidence_log: List[Dict[str, Any]] = []

    async def _execute(self, parameters: Dict[str, Any]) -> SkillResult:
        action = parameters.get("action", "classify_incident")

        dispatch = {
            "classify_incident": self._classify_incident,
            "get_playbook": self._get_playbook,
            "start_incident": self._start_incident,
            "execute_step": self._execute_step,
            "advance_phase": self._advance_phase,
            "record_evidence": self._record_evidence,
            "check_sla": self._check_sla,
            "close_incident": self._close_incident,
            "list_incidents": self._list_incidents,
            "list_playbooks": self._list_playbooks,
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
    # Incident Classification
    # =========================================================================

    async def _classify_incident(self, params: Dict[str, Any]) -> SkillResult:
        """Classify an incident and recommend a playbook."""
        alert_title = params.get("title", "").lower()
        alert_description = params.get("description", "").lower()
        iocs = params.get("iocs", [])
        affected_systems = params.get("affected_systems", [])
        source = params.get("source", "")
        combined = f"{alert_title} {alert_description}"

        classification = "unauthorized_access"  # default
        confidence = 50.0

        # Classification rules
        if any(kw in combined for kw in ["malware", "ransomware", "trojan", "virus", "worm", "backdoor"]):
            classification = "malware_infection"
            confidence = 85.0
        elif any(kw in combined for kw in ["phish", "credential harvest", "spear phish", "bec"]):
            classification = "phishing_compromise"
            confidence = 85.0
        elif any(kw in combined for kw in ["exfiltrat", "data breach", "data theft", "data leak", "dlp"]):
            classification = "data_breach"
            confidence = 80.0
        elif any(kw in combined for kw in ["unauthorized", "brute force", "credential stuff", "account compromise"]):
            classification = "unauthorized_access"
            confidence = 75.0

        playbook = self.PLAYBOOKS.get(classification, {})
        severity = playbook.get("severity_default", "P3")

        # Adjust severity based on context
        if len(affected_systems) > 10:
            severity = "P1"
        elif len(affected_systems) > 3:
            severity = "P2" if severity != "P1" else "P1"

        sla = self.SLAS.get(severity, self.SLAS["P3"])

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "classification": classification,
                "confidence": confidence,
                "severity": severity,
                "recommended_playbook": classification,
                "playbook_name": playbook.get("name", "Unknown"),
                "sla": sla,
                "total_phases": len(playbook.get("phases", {})),
                "total_steps": sum(len(steps) for steps in playbook.get("phases", {}).values()),
            },
        )

    # =========================================================================
    # Playbook Management
    # =========================================================================

    async def _get_playbook(self, params: Dict[str, Any]) -> SkillResult:
        """Get a specific playbook definition."""
        playbook_id = params.get("playbook_id", "")
        if playbook_id not in self.PLAYBOOKS:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"Playbook '{playbook_id}' not found. Available: {list(self.PLAYBOOKS.keys())}"],
            )
        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={"playbook": self.PLAYBOOKS[playbook_id]},
        )

    async def _list_playbooks(self, params: Dict[str, Any]) -> SkillResult:
        playbooks = [
            {"id": k, "name": v["name"], "classification": v["classification"],
             "severity_default": v["severity_default"],
             "phases": len(v["phases"]),
             "steps": sum(len(s) for s in v["phases"].values())}
            for k, v in self.PLAYBOOKS.items()
        ]
        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={"playbooks": playbooks},
        )

    # =========================================================================
    # Incident Lifecycle
    # =========================================================================

    async def _start_incident(self, params: Dict[str, Any]) -> SkillResult:
        """Start a new incident and bind a playbook."""
        incident_id = f"INC-{uuid.uuid4().hex[:8]}"
        classification = params.get("classification", "unauthorized_access")
        severity = params.get("severity", self.PLAYBOOKS.get(classification, {}).get("severity_default", "P3"))
        playbook = self.PLAYBOOKS.get(classification, {})

        sla = self.SLAS.get(severity, self.SLAS["P3"])
        now = datetime.now()

        incident = {
            "incident_id": incident_id,
            "title": params.get("title", f"Incident {incident_id}"),
            "classification": classification,
            "severity": severity,
            "playbook": classification,
            "current_phase": "detection",
            "phase_index": 0,
            "step_index": 0,
            "status": "active",
            "created_at": now.isoformat(),
            "sla": {
                "response_deadline": (now + timedelta(minutes=sla["response_minutes"])).isoformat(),
                "containment_deadline": (now + timedelta(minutes=sla["containment_minutes"])).isoformat(),
                "resolution_deadline": (now + timedelta(hours=sla["resolution_hours"])).isoformat(),
            },
            "assigned_to": params.get("analyst", "unassigned"),
            "affected_systems": params.get("affected_systems", []),
            "iocs": params.get("iocs", []),
            "completed_steps": [],
            "evidence": [],
            "timeline": [{"timestamp": now.isoformat(), "event": "Incident created", "phase": "detection"}],
            "notes": [],
        }

        self.active_incidents[incident_id] = incident

        # Emit intelligence
        packet = IntelligencePacket(
            packet_id=f"PKT-INC-{incident_id}",
            source_agent=self.agent_id,
            target_agents=["all"],
            intelligence_type=IntelligenceType.INCIDENT,
            priority=Priority.CRITICAL if severity == "P1" else Priority.HIGH,
            confidence=90.0,
            timestamp=now,
            data={"incident_id": incident_id, "classification": classification, "severity": severity},
            correlation_keys=params.get("iocs", [])[:20],
        )

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={"incident": incident},
            intelligence_packets=[packet],
        )

    async def _execute_step(self, params: Dict[str, Any]) -> SkillResult:
        """Execute or complete the current step in the incident playbook."""
        incident_id = params.get("incident_id")
        if not incident_id or incident_id not in self.active_incidents:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"Incident '{incident_id}' not found"],
            )

        incident = self.active_incidents[incident_id]
        playbook = self.PLAYBOOKS.get(incident["playbook"], {})
        phase = incident["current_phase"]
        steps = playbook.get("phases", {}).get(phase, [])

        if incident["step_index"] >= len(steps):
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"All steps in phase '{phase}' completed. Use advance_phase."],
            )

        current_step = steps[incident["step_index"]]
        now = datetime.now()

        step_result = {
            "step": current_step["step"],
            "type": current_step["type"],
            "phase": phase,
            "executed_at": now.isoformat(),
            "result": params.get("result", "completed"),
            "notes": params.get("notes", ""),
            "automated": current_step["type"] == "automated",
        }

        incident["completed_steps"].append(step_result)
        incident["step_index"] += 1
        incident["timeline"].append({
            "timestamp": now.isoformat(),
            "event": f"Step completed: {current_step['step'][:60]}",
            "phase": phase,
        })

        # Check if phase is complete
        phase_complete = incident["step_index"] >= len(steps)
        next_step = None
        if not phase_complete:
            next_step = steps[incident["step_index"]]

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "completed_step": step_result,
                "phase_complete": phase_complete,
                "next_step": next_step,
                "steps_remaining_in_phase": len(steps) - incident["step_index"],
            },
        )

    async def _advance_phase(self, params: Dict[str, Any]) -> SkillResult:
        """Advance the incident to the next response phase."""
        incident_id = params.get("incident_id")
        if not incident_id or incident_id not in self.active_incidents:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"Incident '{incident_id}' not found"],
            )

        incident = self.active_incidents[incident_id]
        phases = list(IncidentPhase)
        phase_names = [p.value for p in phases]

        current_idx = phase_names.index(incident["current_phase"]) if incident["current_phase"] in phase_names else 0

        if current_idx >= len(phase_names) - 1:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["Already at final phase. Use close_incident."],
            )

        next_phase = phase_names[current_idx + 1]
        incident["current_phase"] = next_phase
        incident["step_index"] = 0
        incident["timeline"].append({
            "timestamp": datetime.now().isoformat(),
            "event": f"Advanced to phase: {next_phase}",
            "phase": next_phase,
        })

        playbook = self.PLAYBOOKS.get(incident["playbook"], {})
        next_steps = playbook.get("phases", {}).get(next_phase, [])

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "incident_id": incident_id,
                "previous_phase": phase_names[current_idx],
                "current_phase": next_phase,
                "steps_in_phase": len(next_steps),
                "first_step": next_steps[0] if next_steps else None,
            },
        )

    async def _record_evidence(self, params: Dict[str, Any]) -> SkillResult:
        """Record evidence collected during an incident."""
        incident_id = params.get("incident_id")
        if not incident_id or incident_id not in self.active_incidents:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"Incident '{incident_id}' not found"],
            )

        evidence = {
            "evidence_id": f"EV-{uuid.uuid4().hex[:8]}",
            "incident_id": incident_id,
            "type": params.get("type", "artifact"),
            "description": params.get("description", ""),
            "source": params.get("source", ""),
            "hash": params.get("hash", ""),
            "collected_at": datetime.now().isoformat(),
            "collected_by": params.get("analyst", self.agent_id),
            "chain_of_custody": [
                {"action": "collected", "by": self.agent_id, "at": datetime.now().isoformat()},
            ],
        }

        self.active_incidents[incident_id]["evidence"].append(evidence)
        self.evidence_log.append(evidence)

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={"evidence": evidence},
        )

    async def _check_sla(self, params: Dict[str, Any]) -> SkillResult:
        """Check SLA compliance for an incident."""
        incident_id = params.get("incident_id")
        if not incident_id or incident_id not in self.active_incidents:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"Incident '{incident_id}' not found"],
            )

        incident = self.active_incidents[incident_id]
        now = datetime.now()
        sla = incident["sla"]

        response_deadline = datetime.fromisoformat(sla["response_deadline"])
        containment_deadline = datetime.fromisoformat(sla["containment_deadline"])
        resolution_deadline = datetime.fromisoformat(sla["resolution_deadline"])

        phase_order = ["detection", "triage", "containment", "eradication", "recovery", "lessons_learned"]
        current_phase_idx = phase_order.index(incident["current_phase"]) if incident["current_phase"] in phase_order else 0

        sla_status = {
            "response": {
                "deadline": sla["response_deadline"],
                "met": current_phase_idx >= 1 or now <= response_deadline,
                "breached": now > response_deadline and current_phase_idx < 1,
                "remaining_minutes": max(0, (response_deadline - now).total_seconds() / 60) if now <= response_deadline else 0,
            },
            "containment": {
                "deadline": sla["containment_deadline"],
                "met": current_phase_idx >= 3,
                "breached": now > containment_deadline and current_phase_idx < 3,
                "remaining_minutes": max(0, (containment_deadline - now).total_seconds() / 60) if now <= containment_deadline else 0,
            },
            "resolution": {
                "deadline": sla["resolution_deadline"],
                "met": incident["status"] == "closed",
                "breached": now > resolution_deadline and incident["status"] != "closed",
                "remaining_minutes": max(0, (resolution_deadline - now).total_seconds() / 60) if now <= resolution_deadline else 0,
            },
        }

        any_breached = any(v["breached"] for v in sla_status.values())

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "incident_id": incident_id,
                "severity": incident["severity"],
                "sla_status": sla_status,
                "any_breached": any_breached,
                "current_phase": incident["current_phase"],
            },
            warnings=["SLA BREACH DETECTED"] if any_breached else [],
        )

    async def _close_incident(self, params: Dict[str, Any]) -> SkillResult:
        """Close an incident and generate summary."""
        incident_id = params.get("incident_id")
        if not incident_id or incident_id not in self.active_incidents:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"Incident '{incident_id}' not found"],
            )

        incident = self.active_incidents[incident_id]
        now = datetime.now()
        incident["status"] = "closed"
        incident["closed_at"] = now.isoformat()
        incident["root_cause"] = params.get("root_cause", "")
        incident["resolution"] = params.get("resolution", "")

        created = datetime.fromisoformat(incident["created_at"])
        duration = now - created

        summary = {
            "incident_id": incident_id,
            "title": incident["title"],
            "classification": incident["classification"],
            "severity": incident["severity"],
            "duration_hours": round(duration.total_seconds() / 3600, 2),
            "total_steps_completed": len(incident["completed_steps"]),
            "evidence_collected": len(incident["evidence"]),
            "affected_systems": len(incident["affected_systems"]),
            "root_cause": incident["root_cause"],
            "resolution": incident["resolution"],
            "timeline_events": len(incident["timeline"]),
        }

        self.incident_history.append(summary)
        del self.active_incidents[incident_id]

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={"summary": summary},
        )

    async def _list_incidents(self, params: Dict[str, Any]) -> SkillResult:
        incidents = [
            {
                "incident_id": i["incident_id"],
                "title": i["title"],
                "severity": i["severity"],
                "classification": i["classification"],
                "current_phase": i["current_phase"],
                "status": i["status"],
                "steps_completed": len(i["completed_steps"]),
            }
            for i in self.active_incidents.values()
        ]
        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={"active_incidents": incidents, "closed_count": len(self.incident_history)},
        )

    async def _generate_report(self, params: Dict[str, Any]) -> SkillResult:
        """Generate an incident report."""
        incident_id = params.get("incident_id")
        # Check active and history
        incident = self.active_incidents.get(incident_id)
        if not incident:
            hist = [h for h in self.incident_history if h.get("incident_id") == incident_id]
            if hist:
                return SkillResult(
                    success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                    data={"report": hist[0], "source": "history"},
                )
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"Incident '{incident_id}' not found"],
            )

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "report": {
                    "incident_id": incident["incident_id"],
                    "title": incident["title"],
                    "classification": incident["classification"],
                    "severity": incident["severity"],
                    "status": incident["status"],
                    "current_phase": incident["current_phase"],
                    "timeline": incident["timeline"],
                    "completed_steps": incident["completed_steps"],
                    "evidence_count": len(incident["evidence"]),
                    "iocs": incident["iocs"],
                    "affected_systems": incident["affected_systems"],
                },
                "source": "active",
            },
        )
