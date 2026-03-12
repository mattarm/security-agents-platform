#!/usr/bin/env python3
"""
Deception Technology Skill — Deploy and manage honeypots, honeytokens, and breadcrumbs.

Primary owners: Delta (Red Team), Gamma (Blue Team)

Capabilities:
  - Honeypot deployment (SSH, HTTP, SMB, database, file share)
  - Honeytoken management (credentials, documents, API keys, DNS canaries)
  - Interaction tracking with full session recording metadata
  - TTP mapping from attacker interactions to MITRE ATT&CK
  - Attacker profiling based on interaction patterns
  - Breadcrumb trail design for adversary path manipulation
  - Comprehensive deception campaign reporting
"""

import hashlib
import uuid
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Any, Optional

from security_agents.core.models import SkillResult, IntelligencePacket, IntelligenceType, Priority
from security_agents.skills.base_skill import BaseSecuritySkill

# =============================================================================
# Enumerations
# =============================================================================

class HoneypotType(Enum):
    SSH = "ssh"
    HTTP = "http"
    SMB = "smb"
    DATABASE = "database"
    FILE_SHARE = "file_share"
    RDP = "rdp"
    TELNET = "telnet"
    FTP = "ftp"
    SMTP = "smtp"
    CUSTOM = "custom"

class HoneytokenType(Enum):
    CREDENTIAL = "credential"
    DOCUMENT = "document"
    API_KEY = "api_key"
    DNS_CANARY = "dns_canary"
    AWS_KEY = "aws_key"
    DATABASE_RECORD = "database_record"
    URL_CANARY = "url_canary"
    EMAIL_CANARY = "email_canary"

class DecoyStatus(Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    TRIGGERED = "triggered"
    COMPROMISED = "compromised"
    DECOMMISSIONED = "decommissioned"

class InteractionSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

# =============================================================================
# Honeypot and Honeytoken Configuration Templates
# =============================================================================

HONEYPOT_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "ssh": {
        "default_port": 22,
        "emulated_service": "OpenSSH 8.9p1",
        "interaction_ttps": [
            {"technique": "T1110.001", "name": "Brute Force: Password Guessing", "phase": "credential_access"},
            {"technique": "T1021.004", "name": "Remote Services: SSH", "phase": "lateral_movement"},
            {"technique": "T1059.004", "name": "Command and Scripting: Unix Shell", "phase": "execution"},
        ],
        "telemetry": ["login_attempts", "commands_executed", "files_accessed", "source_ip"],
        "realism_features": ["banner_emulation", "fake_filesystem", "command_responses", "session_recording"],
    },
    "http": {
        "default_port": 80,
        "emulated_service": "Apache/2.4.54",
        "interaction_ttps": [
            {"technique": "T1190", "name": "Exploit Public-Facing Application", "phase": "initial_access"},
            {"technique": "T1595.002", "name": "Active Scanning: Vulnerability Scanning", "phase": "reconnaissance"},
            {"technique": "T1083", "name": "File and Directory Discovery", "phase": "discovery"},
        ],
        "telemetry": ["http_requests", "payloads", "user_agents", "source_ip", "paths_accessed"],
        "realism_features": ["fake_login_page", "directory_listing", "fake_admin_panel", "response_headers"],
    },
    "smb": {
        "default_port": 445,
        "emulated_service": "Samba 4.17",
        "interaction_ttps": [
            {"technique": "T1021.002", "name": "Remote Services: SMB/Windows Admin Shares", "phase": "lateral_movement"},
            {"technique": "T1135", "name": "Network Share Discovery", "phase": "discovery"},
            {"technique": "T1039", "name": "Data from Network Shared Drive", "phase": "collection"},
        ],
        "telemetry": ["share_access", "files_read", "files_written", "authentication_attempts"],
        "realism_features": ["fake_shares", "decoy_files", "ntlm_capture", "share_enumeration"],
    },
    "database": {
        "default_port": 3306,
        "emulated_service": "MySQL 8.0.32",
        "interaction_ttps": [
            {"technique": "T1190", "name": "Exploit Public-Facing Application", "phase": "initial_access"},
            {"technique": "T1505.001", "name": "SQL Stored Procedures", "phase": "persistence"},
            {"technique": "T1213", "name": "Data from Information Repositories", "phase": "collection"},
        ],
        "telemetry": ["queries_executed", "tables_accessed", "auth_attempts", "data_exfiltrated"],
        "realism_features": ["fake_schemas", "decoy_records", "query_logging", "slow_responses"],
    },
    "file_share": {
        "default_port": 2049,
        "emulated_service": "NFS v4",
        "interaction_ttps": [
            {"technique": "T1039", "name": "Data from Network Shared Drive", "phase": "collection"},
            {"technique": "T1083", "name": "File and Directory Discovery", "phase": "discovery"},
            {"technique": "T1005", "name": "Data from Local System", "phase": "collection"},
        ],
        "telemetry": ["files_accessed", "files_downloaded", "directory_listing", "mount_attempts"],
        "realism_features": ["decoy_documents", "fake_directory_structure", "access_logging"],
    },
    "rdp": {
        "default_port": 3389,
        "emulated_service": "Microsoft Terminal Services",
        "interaction_ttps": [
            {"technique": "T1021.001", "name": "Remote Services: Remote Desktop Protocol", "phase": "lateral_movement"},
            {"technique": "T1110", "name": "Brute Force", "phase": "credential_access"},
        ],
        "telemetry": ["login_attempts", "credentials_used", "source_ip", "session_duration"],
        "realism_features": ["nla_emulation", "fake_desktop", "credential_capture"],
    },
}

HONEYTOKEN_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "credential": {
        "description": "Fake credential planted in credential stores, config files, or memory",
        "detection_method": "Authentication attempt monitoring",
        "placement_locations": ["password_managers", "config_files", "environment_variables", "active_directory", "ldap"],
        "alert_on": "Any authentication attempt using the honeytoken credential",
        "ttps_detected": [
            {"technique": "T1078", "name": "Valid Accounts", "phase": "initial_access"},
            {"technique": "T1552.001", "name": "Credentials In Files", "phase": "credential_access"},
        ],
    },
    "document": {
        "description": "Decoy document with embedded tracking (beacon URL, metadata)",
        "detection_method": "HTTP callback when document is opened",
        "placement_locations": ["file_shares", "document_repositories", "email_attachments", "desktop"],
        "alert_on": "Document access or beacon callback",
        "ttps_detected": [
            {"technique": "T1005", "name": "Data from Local System", "phase": "collection"},
            {"technique": "T1039", "name": "Data from Network Shared Drive", "phase": "collection"},
        ],
    },
    "api_key": {
        "description": "Fake API key that triggers alert when used",
        "detection_method": "API gateway monitoring for honeytoken key usage",
        "placement_locations": ["source_code", "config_files", "environment_variables", "ci_cd_pipelines"],
        "alert_on": "Any API call using the honeytoken key",
        "ttps_detected": [
            {"technique": "T1552.001", "name": "Credentials In Files", "phase": "credential_access"},
            {"technique": "T1106", "name": "Native API", "phase": "execution"},
        ],
    },
    "dns_canary": {
        "description": "Unique DNS hostname that alerts when resolved",
        "detection_method": "DNS query monitoring for canary domain",
        "placement_locations": ["config_files", "hosts_files", "dns_records", "documentation"],
        "alert_on": "DNS resolution of the canary hostname",
        "ttps_detected": [
            {"technique": "T1071.004", "name": "Application Layer Protocol: DNS", "phase": "command_and_control"},
            {"technique": "T1016", "name": "System Network Configuration Discovery", "phase": "discovery"},
        ],
    },
    "aws_key": {
        "description": "Fake AWS access key that triggers CloudTrail alert on use",
        "detection_method": "CloudTrail monitoring for honeytoken key activity",
        "placement_locations": ["source_code", "environment_variables", "config_files", ".aws/credentials"],
        "alert_on": "Any AWS API call using the honeytoken key",
        "ttps_detected": [
            {"technique": "T1552.001", "name": "Credentials In Files", "phase": "credential_access"},
            {"technique": "T1078.004", "name": "Valid Accounts: Cloud Accounts", "phase": "initial_access"},
        ],
    },
    "url_canary": {
        "description": "Unique URL that alerts when accessed",
        "detection_method": "Web server monitoring for canary URL hits",
        "placement_locations": ["documents", "emails", "internal_wikis", "source_code_comments"],
        "alert_on": "HTTP request to the canary URL",
        "ttps_detected": [
            {"technique": "T1083", "name": "File and Directory Discovery", "phase": "discovery"},
        ],
    },
    "email_canary": {
        "description": "Fake email address that triggers alert on received mail",
        "detection_method": "Mail server monitoring for messages to canary address",
        "placement_locations": ["contact_lists", "directories", "org_charts", "email_groups"],
        "alert_on": "Email sent to the canary address",
        "ttps_detected": [
            {"technique": "T1589.002", "name": "Gather Victim Identity: Email Addresses", "phase": "reconnaissance"},
            {"technique": "T1566", "name": "Phishing", "phase": "initial_access"},
        ],
    },
}

class DeceptionTechnologySkill(BaseSecuritySkill):
    """Deploy and manage honeypots, honeytokens, and deception campaigns."""

    SKILL_NAME = "deception_technology"
    DESCRIPTION = (
        "Deploy and manage honeypots and honeytokens for intrusion detection, "
        "attacker profiling, and adversary engagement with TTP mapping"
    )
    VERSION = "1.0.0"
    COMPATIBLE_AGENTS = ["delta_red_team", "gamma_blue_team"]
    REQUIRED_INTEGRATIONS = []

    async def _setup(self):
        self.decoys: Dict[str, Dict[str, Any]] = {}  # decoy_id -> decoy config
        self.interactions: List[Dict[str, Any]] = []
        self.attacker_profiles: Dict[str, Dict[str, Any]] = {}  # profile_id -> profile

    async def _execute(self, parameters: Dict[str, Any]) -> SkillResult:
        action = parameters.get("action", "deploy_honeypot")

        dispatch = {
            "deploy_honeypot": self._deploy_honeypot,
            "deploy_honeytoken": self._deploy_honeytoken,
            "list_decoys": self._list_decoys,
            "get_interactions": self._get_interactions,
            "analyze_attacker": self._analyze_attacker,
            "remove_decoy": self._remove_decoy,
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
    # Deploy Honeypot
    # =========================================================================

    async def _deploy_honeypot(self, params: Dict[str, Any]) -> SkillResult:
        """Deploy a honeypot with specified configuration."""
        honeypot_type = params.get("honeypot_type", "ssh")
        name = params.get("name", "")
        network_segment = params.get("network_segment", "")
        ip_address = params.get("ip_address", "")
        port = params.get("port")
        interaction_level = params.get("interaction_level", "medium")  # low, medium, high
        breadcrumbs = params.get("breadcrumbs", [])  # paths that lead to this honeypot
        custom_config = params.get("config", {})

        if honeypot_type not in [ht.value for ht in HoneypotType]:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"Unknown honeypot_type '{honeypot_type}'. Valid: {[ht.value for ht in HoneypotType]}"],
            )

        template = HONEYPOT_TEMPLATES.get(honeypot_type, HONEYPOT_TEMPLATES.get("http"))
        decoy_id = f"HP-{uuid.uuid4().hex[:8]}"

        # Design breadcrumb trail
        breadcrumb_trail = self._design_breadcrumb_trail(decoy_id, honeypot_type, breadcrumbs, network_segment)

        decoy = {
            "decoy_id": decoy_id,
            "decoy_type": "honeypot",
            "honeypot_type": honeypot_type,
            "name": name or f"{honeypot_type}-honeypot-{decoy_id[-4:]}",
            "status": DecoyStatus.ACTIVE.value,
            "network_segment": network_segment,
            "ip_address": ip_address,
            "port": port or template["default_port"],
            "emulated_service": custom_config.get("emulated_service", template["emulated_service"]),
            "interaction_level": interaction_level,
            "telemetry_types": template["telemetry"],
            "realism_features": template["realism_features"],
            "detectable_ttps": template["interaction_ttps"],
            "breadcrumb_trail": breadcrumb_trail,
            "deployed_at": datetime.now().isoformat(),
            "deployed_by": self.agent_id,
            "interaction_count": 0,
            "last_interaction": None,
            "custom_config": custom_config,
        }

        self.decoys[decoy_id] = decoy

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "decoy": decoy,
                "breadcrumb_trail": breadcrumb_trail,
                "detection_capabilities": template["interaction_ttps"],
                "deployment_checklist": [
                    f"Configure firewall to allow inbound traffic to port {decoy['port']}",
                    f"Ensure network segment '{network_segment}' routing is configured",
                    "Deploy breadcrumbs to guide adversaries toward honeypot",
                    "Configure alerting for honeypot interactions",
                    "Verify honeypot is not accessible from legitimate user workflows",
                    "Document honeypot in security operations runbook",
                ],
            },
        )

    # =========================================================================
    # Deploy Honeytoken
    # =========================================================================

    async def _deploy_honeytoken(self, params: Dict[str, Any]) -> SkillResult:
        """Deploy a honeytoken (fake credential, document, API key, etc.)."""
        token_type = params.get("token_type", "credential")
        name = params.get("name", "")
        placement = params.get("placement", "")
        value = params.get("value", "")  # the actual fake credential/key/url
        description = params.get("description", "")
        custom_config = params.get("config", {})

        if token_type not in [ht.value for ht in HoneytokenType]:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"Unknown token_type '{token_type}'. Valid: {[ht.value for ht in HoneytokenType]}"],
            )

        template = HONEYTOKEN_TEMPLATES.get(token_type, HONEYTOKEN_TEMPLATES["credential"])
        decoy_id = f"HT-{uuid.uuid4().hex[:8]}"

        # Generate a unique token value if not provided
        if not value:
            value = self._generate_token_value(token_type, decoy_id)

        # Create canary fingerprint for detection
        fingerprint = hashlib.sha256(f"{decoy_id}:{value}".encode()).hexdigest()[:16]

        decoy = {
            "decoy_id": decoy_id,
            "decoy_type": "honeytoken",
            "token_type": token_type,
            "name": name or f"{token_type}-token-{decoy_id[-4:]}",
            "status": DecoyStatus.ACTIVE.value,
            "placement": placement or template["placement_locations"][0],
            "placement_options": template["placement_locations"],
            "value_preview": self._redact_value(value),
            "fingerprint": fingerprint,
            "description": description or template["description"],
            "detection_method": template["detection_method"],
            "alert_trigger": template["alert_on"],
            "detectable_ttps": template["ttps_detected"],
            "deployed_at": datetime.now().isoformat(),
            "deployed_by": self.agent_id,
            "interaction_count": 0,
            "last_interaction": None,
            "custom_config": custom_config,
        }

        self.decoys[decoy_id] = decoy

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "decoy": decoy,
                "token_value": value,  # returned once for deployment; should be stored securely
                "fingerprint": fingerprint,
                "detection_capabilities": template["ttps_detected"],
                "deployment_instructions": [
                    f"Place the {token_type} honeytoken at: {decoy['placement']}",
                    f"Configure monitoring for: {template['detection_method']}",
                    f"Alert trigger: {template['alert_on']}",
                    "Document the honeytoken in the deception inventory (not in shared docs)",
                    "Set up automated alerting to SOC on trigger",
                ],
            },
        )

    # =========================================================================
    # List Decoys
    # =========================================================================

    async def _list_decoys(self, params: Dict[str, Any]) -> SkillResult:
        """List all deployed decoys with optional filtering."""
        decoy_type_filter = params.get("decoy_type")  # honeypot or honeytoken
        status_filter = params.get("status")
        include_inactive = params.get("include_inactive", False)

        decoys = list(self.decoys.values())

        if decoy_type_filter:
            decoys = [d for d in decoys if d.get("decoy_type") == decoy_type_filter]
        if status_filter:
            decoys = [d for d in decoys if d.get("status") == status_filter]
        if not include_inactive:
            decoys = [d for d in decoys if d.get("status") not in (DecoyStatus.DECOMMISSIONED.value, DecoyStatus.INACTIVE.value)]

        # Summarize
        type_breakdown = {}
        for d in decoys:
            dt = d.get("decoy_type", "unknown")
            subtype = d.get("honeypot_type", d.get("token_type", "unknown"))
            key = f"{dt}:{subtype}"
            type_breakdown[key] = type_breakdown.get(key, 0) + 1

        triggered_decoys = [d for d in decoys if d.get("status") == DecoyStatus.TRIGGERED.value or d.get("interaction_count", 0) > 0]

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "decoys": decoys,
                "total_decoys": len(decoys),
                "type_breakdown": type_breakdown,
                "active_count": sum(1 for d in decoys if d.get("status") == DecoyStatus.ACTIVE.value),
                "triggered_count": len(triggered_decoys),
                "triggered_decoys": triggered_decoys,
            },
        )

    # =========================================================================
    # Record & Get Interactions
    # =========================================================================

    async def _get_interactions(self, params: Dict[str, Any]) -> SkillResult:
        """Record new interactions or retrieve interaction history."""
        decoy_id = params.get("decoy_id")
        new_interactions = params.get("interactions", [])  # [{source_ip, timestamp, action, details}]
        limit = params.get("limit", 100)

        # Record new interactions
        if new_interactions:
            decoy = self.decoys.get(decoy_id)
            if not decoy:
                return SkillResult(
                    success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                    errors=[f"Decoy '{decoy_id}' not found"],
                )

            recorded = []
            for interaction in new_interactions:
                source_ip = interaction.get("source_ip", "unknown")
                action = interaction.get("action", "unknown")
                details = interaction.get("details", {})

                # Map interaction to TTPs
                mapped_ttps = self._map_interaction_to_ttps(decoy, action, details)

                # Determine severity
                severity = self._assess_interaction_severity(action, details)

                record = {
                    "interaction_id": f"INT-{uuid.uuid4().hex[:8]}",
                    "decoy_id": decoy_id,
                    "decoy_type": decoy.get("decoy_type"),
                    "source_ip": source_ip,
                    "timestamp": interaction.get("timestamp", datetime.now().isoformat()),
                    "action": action,
                    "details": details,
                    "severity": severity,
                    "mapped_ttps": mapped_ttps,
                }
                recorded.append(record)
                self.interactions.append(record)

                # Update attacker profile
                self._update_attacker_profile(source_ip, record)

            # Update decoy status and stats
            decoy["interaction_count"] = decoy.get("interaction_count", 0) + len(recorded)
            decoy["last_interaction"] = datetime.now().isoformat()
            if decoy["status"] == DecoyStatus.ACTIVE.value:
                decoy["status"] = DecoyStatus.TRIGGERED.value

            # Generate intelligence packet
            packets = []
            if any(r["severity"] in ("critical", "high") for r in recorded):
                packets.append(IntelligencePacket(
                    packet_id=f"PKT-DEC-{uuid.uuid4().hex[:8]}",
                    source_agent=self.agent_id,
                    target_agents=["all"],
                    intelligence_type=IntelligenceType.INCIDENT,
                    priority=Priority.HIGH,
                    confidence=95.0,
                    timestamp=datetime.now(),
                    data={
                        "decoy_id": decoy_id,
                        "decoy_type": decoy.get("decoy_type"),
                        "source_ips": list(set(r["source_ip"] for r in recorded)),
                        "interactions": len(recorded),
                        "ttps_observed": list(set(
                            ttp["technique"] for r in recorded for ttp in r.get("mapped_ttps", [])
                        )),
                        "message": f"Deception decoy '{decoy.get('name')}' triggered — active adversary detected",
                    },
                    correlation_keys=[decoy_id, "deception_triggered"] + [r["source_ip"] for r in recorded],
                ))

            return SkillResult(
                success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                data={
                    "recorded_interactions": recorded,
                    "total_recorded": len(recorded),
                    "decoy_status": decoy["status"],
                    "decoy_total_interactions": decoy["interaction_count"],
                },
                intelligence_packets=packets,
                warnings=[
                    "Active adversary detected — review interactions and initiate incident response"
                ] if any(r["severity"] in ("critical", "high") for r in recorded) else [],
            )

        # Retrieve interactions
        interactions = self.interactions
        if decoy_id:
            interactions = [i for i in interactions if i.get("decoy_id") == decoy_id]

        interactions.sort(key=lambda i: i.get("timestamp", ""), reverse=True)

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "interactions": interactions[:limit],
                "total_interactions": len(interactions),
                "returned": min(limit, len(interactions)),
                "unique_sources": list(set(i.get("source_ip", "") for i in interactions)),
                "severity_breakdown": {
                    s: sum(1 for i in interactions if i.get("severity") == s)
                    for s in ["critical", "high", "medium", "low", "info"]
                },
            },
        )

    # =========================================================================
    # Analyze Attacker
    # =========================================================================

    async def _analyze_attacker(self, params: Dict[str, Any]) -> SkillResult:
        """Analyze attacker behavior from deception interactions."""
        source_ip = params.get("source_ip")
        profile_id = params.get("profile_id")

        if source_ip:
            profile_id = hashlib.sha256(source_ip.encode()).hexdigest()[:12]

        if not profile_id:
            # Return all profiles
            profiles = list(self.attacker_profiles.values())
            profiles.sort(key=lambda p: p.get("risk_score", 0), reverse=True)
            return SkillResult(
                success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                data={
                    "attacker_profiles": profiles,
                    "total_profiles": len(profiles),
                },
            )

        profile = self.attacker_profiles.get(profile_id)
        if not profile:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"No attacker profile found for '{source_ip or profile_id}'"],
            )

        # Enrich with TTP analysis
        ttps_observed = profile.get("ttps_observed", [])
        ttp_phases = {}
        for ttp in ttps_observed:
            phase = ttp.get("phase", "unknown")
            ttp_phases[phase] = ttp_phases.get(phase, 0) + 1

        # Determine attack progression
        attack_phases_order = [
            "reconnaissance", "initial_access", "execution", "persistence",
            "privilege_escalation", "defense_evasion", "credential_access",
            "discovery", "lateral_movement", "collection", "command_and_control",
            "exfiltration", "impact",
        ]
        observed_phases = [p for p in attack_phases_order if p in ttp_phases]
        furthest_phase = observed_phases[-1] if observed_phases else "unknown"

        # Sophistication assessment
        sophistication = self._assess_sophistication(profile)

        profile["analysis"] = {
            "ttps_by_phase": ttp_phases,
            "observed_kill_chain_phases": observed_phases,
            "furthest_attack_phase": furthest_phase,
            "sophistication": sophistication,
            "dwell_time_estimate": self._estimate_dwell_time(profile),
            "intent_assessment": self._assess_intent(profile),
        }

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "attacker_profile": profile,
                "analysis": profile["analysis"],
                "recommendations": [
                    f"Block source IP(s): {', '.join(profile.get('source_ips', []))}",
                    f"Hunt for TTPs in production environment: {[t.get('technique') for t in ttps_observed[:5]]}",
                    "Review lateral movement paths from honeypot network segment",
                    "Check if attacker accessed any production systems from same source",
                    "Preserve all deception interaction logs as evidence",
                ],
            },
        )

    # =========================================================================
    # Remove Decoy
    # =========================================================================

    async def _remove_decoy(self, params: Dict[str, Any]) -> SkillResult:
        """Decommission a decoy."""
        decoy_id = params.get("decoy_id", "")
        reason = params.get("reason", "")

        if not decoy_id:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["'decoy_id' is required"],
            )

        decoy = self.decoys.get(decoy_id)
        if not decoy:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"Decoy '{decoy_id}' not found"],
            )

        decoy["status"] = DecoyStatus.DECOMMISSIONED.value
        decoy["decommissioned_at"] = datetime.now().isoformat()
        decoy["decommission_reason"] = reason

        related_interactions = [i for i in self.interactions if i.get("decoy_id") == decoy_id]

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "decoy": decoy,
                "total_interactions_recorded": len(related_interactions),
                "decommission_checklist": [
                    "Remove honeypot/honeytoken from deployment location",
                    "Remove breadcrumbs pointing to this decoy",
                    "Archive interaction logs for forensic retention",
                    "Update deception inventory documentation",
                    f"Ensure replacement decoy is planned if coverage gap exists in {decoy.get('network_segment', 'segment')}",
                ],
            },
        )

    # =========================================================================
    # Generate Report
    # =========================================================================

    async def _generate_report(self, params: Dict[str, Any]) -> SkillResult:
        """Generate a deception technology campaign report."""
        include_details = params.get("include_details", True)

        decoys = list(self.decoys.values())
        active = [d for d in decoys if d.get("status") in (DecoyStatus.ACTIVE.value, DecoyStatus.TRIGGERED.value)]
        triggered = [d for d in decoys if d.get("interaction_count", 0) > 0]

        # TTP coverage
        all_ttps = set()
        for d in decoys:
            for ttp in d.get("detectable_ttps", []):
                all_ttps.add(ttp.get("technique", ""))

        # Interaction timeline
        daily_interactions: Dict[str, int] = {}
        for interaction in self.interactions:
            day = interaction.get("timestamp", "")[:10]
            if day:
                daily_interactions[day] = daily_interactions.get(day, 0) + 1

        report = {
            "report_id": f"RPT-{uuid.uuid4().hex[:8]}",
            "generated_at": datetime.now().isoformat(),
            "campaign_summary": {
                "total_decoys": len(decoys),
                "active_decoys": len(active),
                "triggered_decoys": len(triggered),
                "total_honeypots": sum(1 for d in decoys if d.get("decoy_type") == "honeypot"),
                "total_honeytokens": sum(1 for d in decoys if d.get("decoy_type") == "honeytoken"),
                "total_interactions": len(self.interactions),
                "unique_attackers": len(self.attacker_profiles),
                "ttp_coverage": sorted(all_ttps),
                "ttp_count": len(all_ttps),
            },
            "interaction_timeline": dict(sorted(daily_interactions.items())),
            "severity_breakdown": {
                s: sum(1 for i in self.interactions if i.get("severity") == s)
                for s in ["critical", "high", "medium", "low", "info"]
            },
            "attacker_profiles": list(self.attacker_profiles.values()) if include_details else [
                {"profile_id": p["profile_id"], "source_ips": p.get("source_ips", []), "risk_score": p.get("risk_score", 0)}
                for p in self.attacker_profiles.values()
            ],
            "coverage_analysis": self._analyze_coverage(decoys),
            "recommendations": self._generate_recommendations(decoys),
        }

        if include_details:
            report["decoys"] = decoys
            report["recent_interactions"] = sorted(
                self.interactions, key=lambda i: i.get("timestamp", ""), reverse=True
            )[:50]

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={"report": report},
        )

    # =========================================================================
    # Internal Helpers
    # =========================================================================

    def _design_breadcrumb_trail(self, decoy_id: str, honeypot_type: str,
                                 provided_breadcrumbs: List[str], network_segment: str) -> List[Dict[str, Any]]:
        """Design a breadcrumb trail to guide adversaries toward the honeypot."""
        trail = []

        # Default breadcrumb strategies per honeypot type
        breadcrumb_strategies = {
            "ssh": [
                {"type": "config_entry", "location": "~/.ssh/config", "description": "SSH config entry pointing to honeypot"},
                {"type": "hosts_entry", "location": "/etc/hosts", "description": "Hosts file entry with suggestive hostname"},
                {"type": "history_entry", "location": "~/.bash_history", "description": "SSH command in shell history"},
            ],
            "http": [
                {"type": "bookmark", "location": "browser_bookmarks", "description": "Browser bookmark to honeypot URL"},
                {"type": "link", "location": "internal_wiki", "description": "Link on internal documentation page"},
                {"type": "config_entry", "location": "environment_variables", "description": "URL in env var (e.g., ADMIN_PORTAL)"},
            ],
            "smb": [
                {"type": "shortcut", "location": "user_desktop", "description": "Network shortcut to honeypot share"},
                {"type": "mapped_drive", "location": "group_policy", "description": "Mapped drive in GPO (inactive)"},
                {"type": "config_entry", "location": "fstab_or_mount", "description": "Mount entry for the share"},
            ],
            "database": [
                {"type": "config_entry", "location": "config_files", "description": "Connection string in application config"},
                {"type": "credential", "location": "password_manager", "description": "Database credential in shared vault"},
                {"type": "script", "location": "scripts_directory", "description": "Backup script referencing honeypot DB"},
            ],
        }

        # Use provided breadcrumbs
        for bc in provided_breadcrumbs:
            trail.append({
                "breadcrumb_id": f"BC-{uuid.uuid4().hex[:8]}",
                "decoy_id": decoy_id,
                "type": "custom",
                "location": bc,
                "description": f"Custom breadcrumb: {bc}",
            })

        # Add default breadcrumbs from strategy
        default_bcs = breadcrumb_strategies.get(honeypot_type, breadcrumb_strategies.get("http", []))
        for bc in default_bcs:
            trail.append({
                "breadcrumb_id": f"BC-{uuid.uuid4().hex[:8]}",
                "decoy_id": decoy_id,
                **bc,
            })

        return trail

    def _generate_token_value(self, token_type: str, decoy_id: str) -> str:
        """Generate a realistic-looking honeytoken value."""
        seed = uuid.uuid4().hex
        generators = {
            "credential": f"svc_backup_{seed[:8]}:P@ssw0rd_{seed[8:16]}!",
            "api_key": f"sk_live_{seed[:32]}",
            "aws_key": f"AKIA{seed[:16].upper()}",
            "dns_canary": f"{seed[:8]}.canary.internal.example.com",
            "url_canary": f"https://monitor.internal.example.com/c/{seed[:12]}",
            "email_canary": f"finance.backup.{seed[:6]}@example.com",
            "document": f"Q4-Financial-Report-CONFIDENTIAL-{seed[:8]}.docx",
            "database_record": f"admin_backup_{seed[:8]}",
        }
        return generators.get(token_type, f"token_{seed[:24]}")

    def _redact_value(self, value: str) -> str:
        """Redact a token value for display."""
        if len(value) <= 8:
            return value[:2] + "***"
        visible = max(4, len(value) // 5)
        return value[:visible] + "..." + value[-4:]

    def _map_interaction_to_ttps(self, decoy: Dict[str, Any], action: str, details: Dict[str, Any]) -> List[Dict[str, str]]:
        """Map an interaction action to MITRE ATT&CK TTPs."""
        ttps = []

        # Direct mapping from decoy's detectable TTPs
        for ttp in decoy.get("detectable_ttps", []):
            ttps.append(ttp)

        # Action-specific TTP mapping
        action_ttp_map = {
            "login_attempt": {"technique": "T1110", "name": "Brute Force", "phase": "credential_access"},
            "login_success": {"technique": "T1078", "name": "Valid Accounts", "phase": "initial_access"},
            "command_execution": {"technique": "T1059", "name": "Command and Scripting Interpreter", "phase": "execution"},
            "file_download": {"technique": "T1005", "name": "Data from Local System", "phase": "collection"},
            "file_upload": {"technique": "T1105", "name": "Ingress Tool Transfer", "phase": "command_and_control"},
            "directory_listing": {"technique": "T1083", "name": "File and Directory Discovery", "phase": "discovery"},
            "credential_use": {"technique": "T1078", "name": "Valid Accounts", "phase": "initial_access"},
            "port_scan": {"technique": "T1046", "name": "Network Service Discovery", "phase": "discovery"},
            "share_enumeration": {"technique": "T1135", "name": "Network Share Discovery", "phase": "discovery"},
            "lateral_movement": {"technique": "T1021", "name": "Remote Services", "phase": "lateral_movement"},
            "data_exfiltration": {"technique": "T1041", "name": "Exfiltration Over C2 Channel", "phase": "exfiltration"},
            "persistence_attempt": {"technique": "T1053", "name": "Scheduled Task/Job", "phase": "persistence"},
        }

        action_ttp = action_ttp_map.get(action)
        if action_ttp and action_ttp not in ttps:
            ttps.append(action_ttp)

        return ttps

    def _assess_interaction_severity(self, action: str, details: Dict[str, Any]) -> str:
        """Determine severity of a deception interaction."""
        critical_actions = {"data_exfiltration", "persistence_attempt", "lateral_movement", "credential_use"}
        high_actions = {"login_success", "command_execution", "file_upload", "file_download"}
        medium_actions = {"login_attempt", "share_enumeration", "directory_listing"}
        low_actions = {"port_scan"}

        if action in critical_actions:
            return "critical"
        elif action in high_actions:
            return "high"
        elif action in medium_actions:
            return "medium"
        elif action in low_actions:
            return "low"
        return "info"

    def _update_attacker_profile(self, source_ip: str, interaction: Dict[str, Any]):
        """Update or create an attacker profile based on interaction."""
        profile_id = hashlib.sha256(source_ip.encode()).hexdigest()[:12]

        if profile_id not in self.attacker_profiles:
            self.attacker_profiles[profile_id] = {
                "profile_id": profile_id,
                "source_ips": [source_ip],
                "first_seen": interaction.get("timestamp", datetime.now().isoformat()),
                "last_seen": interaction.get("timestamp", datetime.now().isoformat()),
                "interaction_count": 0,
                "ttps_observed": [],
                "actions_performed": [],
                "decoys_touched": [],
                "risk_score": 0,
            }

        profile = self.attacker_profiles[profile_id]

        if source_ip not in profile["source_ips"]:
            profile["source_ips"].append(source_ip)

        profile["last_seen"] = interaction.get("timestamp", datetime.now().isoformat())
        profile["interaction_count"] += 1

        for ttp in interaction.get("mapped_ttps", []):
            if ttp not in profile["ttps_observed"]:
                profile["ttps_observed"].append(ttp)

        action = interaction.get("action", "")
        if action and action not in profile["actions_performed"]:
            profile["actions_performed"].append(action)

        decoy_id = interaction.get("decoy_id", "")
        if decoy_id and decoy_id not in profile["decoys_touched"]:
            profile["decoys_touched"].append(decoy_id)

        # Update risk score
        severity_scores = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 1}
        profile["risk_score"] = min(100, profile["risk_score"] + severity_scores.get(interaction.get("severity", "info"), 1))

    def _assess_sophistication(self, profile: Dict[str, Any]) -> str:
        """Assess attacker sophistication from behavioral indicators."""
        ttp_count = len(profile.get("ttps_observed", []))
        decoy_count = len(profile.get("decoys_touched", []))
        action_diversity = len(profile.get("actions_performed", []))

        sophistication_score = ttp_count * 2 + decoy_count * 3 + action_diversity * 2

        if sophistication_score >= 20:
            return "high"
        elif sophistication_score >= 10:
            return "medium"
        return "low"

    def _estimate_dwell_time(self, profile: Dict[str, Any]) -> str:
        """Estimate attacker dwell time from first to last interaction."""
        first = profile.get("first_seen", "")
        last = profile.get("last_seen", "")
        if not first or not last:
            return "unknown"
        try:
            first_dt = datetime.fromisoformat(first.replace("Z", "+00:00"))
            last_dt = datetime.fromisoformat(last.replace("Z", "+00:00"))
            delta = last_dt - first_dt
            hours = delta.total_seconds() / 3600
            if hours < 1:
                return f"{int(delta.total_seconds() / 60)} minutes"
            elif hours < 24:
                return f"{hours:.1f} hours"
            return f"{delta.days} days"
        except (ValueError, TypeError):
            return "unknown"

    def _assess_intent(self, profile: Dict[str, Any]) -> str:
        """Assess likely attacker intent from observed actions."""
        actions = set(profile.get("actions_performed", []))

        if actions & {"data_exfiltration", "file_download"}:
            return "data_theft"
        elif actions & {"persistence_attempt", "file_upload"}:
            return "persistent_access"
        elif actions & {"lateral_movement", "share_enumeration"}:
            return "network_expansion"
        elif actions & {"command_execution", "login_success"}:
            return "system_access"
        elif actions & {"login_attempt", "port_scan"}:
            return "reconnaissance"
        return "unknown"

    def _analyze_coverage(self, decoys: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze deception coverage gaps."""
        network_segments = set(d.get("network_segment", "") for d in decoys if d.get("network_segment"))
        honeypot_types = set(d.get("honeypot_type", "") for d in decoys if d.get("decoy_type") == "honeypot")
        token_types = set(d.get("token_type", "") for d in decoys if d.get("decoy_type") == "honeytoken")

        all_honeypot_types = {ht.value for ht in HoneypotType} - {"custom"}
        all_token_types = {ht.value for ht in HoneytokenType}

        return {
            "network_segments_covered": sorted(network_segments),
            "honeypot_types_deployed": sorted(honeypot_types),
            "honeypot_types_missing": sorted(all_honeypot_types - honeypot_types),
            "honeytoken_types_deployed": sorted(token_types),
            "honeytoken_types_missing": sorted(all_token_types - token_types),
        }

    def _generate_recommendations(self, decoys: List[Dict[str, Any]]) -> List[str]:
        """Generate deception campaign recommendations."""
        recs = []
        active = [d for d in decoys if d.get("status") in (DecoyStatus.ACTIVE.value, DecoyStatus.TRIGGERED.value)]

        if not active:
            recs.append("CRITICAL: No active decoys deployed. Deploy honeypots and honeytokens to detect adversary activity.")

        coverage = self._analyze_coverage(decoys)
        if coverage["honeypot_types_missing"]:
            recs.append(f"Expand honeypot coverage to include: {', '.join(coverage['honeypot_types_missing'][:3])}")
        if coverage["honeytoken_types_missing"]:
            recs.append(f"Deploy additional honeytoken types: {', '.join(coverage['honeytoken_types_missing'][:3])}")

        triggered = [d for d in decoys if d.get("interaction_count", 0) > 0]
        if triggered:
            recs.append(f"{len(triggered)} decoys have been triggered — review all interactions for IOCs.")

        recs.extend([
            "Rotate honeytokens periodically to prevent attacker fingerprinting of deception infrastructure.",
            "Place breadcrumbs along likely lateral movement paths identified by red team assessments.",
            "Integrate deception alerts with SIEM and SOAR for automated incident response.",
            "Test deception infrastructure during red team exercises to validate detection capabilities.",
        ])

        return recs
