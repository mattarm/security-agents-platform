#!/usr/bin/env python3
"""
Threat Hunting Skill — Proactive hypothesis-driven threat discovery.

Primary owner: Gamma (Blue Team)
Also usable by: Alpha-4 (campaign hunting), Delta (detection validation)

Capabilities:
  - Hypothesis generation from threat intelligence
  - Hunt query generation (KQL, SPL, Sigma, YARA)
  - Behavioral baselining and anomaly detection
  - Lateral movement pattern detection
  - C2 communication pattern matching
  - Persistence mechanism discovery
  - Data exfiltration hunting
  - Hunt campaign management and tracking
"""

import hashlib
import re
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from enum import Enum

from security_agents.core.models import (
    SkillResult, IntelligencePacket, IntelligenceType, Priority,
    ThreatActorProfile, AttackPhase,
)
from security_agents.skills.base_skill import BaseSecuritySkill

class HuntStatus(Enum):
    PLANNED = "planned"
    ACTIVE = "active"
    COMPLETED = "completed"
    ESCALATED = "escalated"
    ARCHIVED = "archived"

class QueryLanguage(Enum):
    KQL = "kql"
    SPL = "spl"
    SIGMA = "sigma"
    YARA = "yara"
    FQL = "fql"
    NGSIEM = "ngsiem"

class ThreatHuntingSkill(BaseSecuritySkill):
    """Proactive, hypothesis-driven threat hunting."""

    SKILL_NAME = "threat_hunting"
    DESCRIPTION = "Hypothesis-driven threat hunting with query generation, anomaly detection, and hunt campaign tracking"
    VERSION = "1.0.0"
    COMPATIBLE_AGENTS = ["gamma_blue_team", "alpha_4_threat_intel", "delta_red_team"]
    REQUIRED_INTEGRATIONS = []

    # Known MITRE ATT&CK techniques for hunt hypothesis generation
    HUNT_HYPOTHESES = {
        "lateral_movement": {
            "description": "Adversary moving laterally through the network",
            "techniques": ["T1021", "T1021.001", "T1021.002", "T1021.004", "T1021.006", "T1550"],
            "indicators": [
                "Unusual RDP connections between workstations",
                "PsExec or SMB admin share access from non-admin hosts",
                "WinRM connections from unexpected sources",
                "SSH tunneling from internal hosts",
                "Pass-the-hash/ticket authentication patterns",
            ],
        },
        "persistence": {
            "description": "Adversary establishing persistence mechanisms",
            "techniques": ["T1053", "T1136", "T1543", "T1547", "T1574"],
            "indicators": [
                "New scheduled tasks or cron jobs",
                "Registry run key modifications",
                "New services or service modifications",
                "Startup folder additions",
                "DLL search order hijacking",
            ],
        },
        "credential_access": {
            "description": "Adversary attempting to harvest credentials",
            "techniques": ["T1003", "T1110", "T1555", "T1558", "T1552"],
            "indicators": [
                "LSASS process access from unexpected tools",
                "Kerberoasting — SPN requests from workstations",
                "Password spray patterns in auth logs",
                "Access to credential stores or vaults",
                "DCSync replication requests from non-DC sources",
            ],
        },
        "exfiltration": {
            "description": "Adversary exfiltrating data",
            "techniques": ["T1048", "T1041", "T1567", "T1537"],
            "indicators": [
                "Large outbound data transfers to rare destinations",
                "DNS tunneling — high-entropy DNS queries",
                "Uploads to cloud storage services from servers",
                "Encrypted traffic to non-standard ports",
                "Staging files in temp directories before transfer",
            ],
        },
        "command_and_control": {
            "description": "Adversary maintaining C2 communications",
            "techniques": ["T1071", "T1573", "T1105", "T1572", "T1090"],
            "indicators": [
                "Beaconing patterns — regular interval callbacks",
                "DNS over HTTPS to non-standard resolvers",
                "Long-duration connections to rare domains",
                "Encoded/obfuscated PowerShell execution",
                "Traffic to recently registered domains",
            ],
        },
        "defense_evasion": {
            "description": "Adversary evading detection",
            "techniques": ["T1027", "T1070", "T1140", "T1218", "T1562"],
            "indicators": [
                "Log clearing or tampering",
                "Disabling security tools or services",
                "Process injection into legitimate processes",
                "Living-off-the-land binary (LOLBin) abuse",
                "Timestomping or file attribute manipulation",
            ],
        },
        "initial_access_phishing": {
            "description": "Adversary gaining initial access via phishing",
            "techniques": ["T1566", "T1566.001", "T1566.002"],
            "indicators": [
                "Macro-enabled documents opened from email",
                "Links to credential harvesting pages",
                "HTML smuggling payloads",
                "QR code phishing (quishing)",
                "OAuth consent phishing",
            ],
        },
    }

    # Query templates for different SIEM platforms
    QUERY_TEMPLATES = {
        QueryLanguage.KQL: {
            "lateral_movement": (
                'SecurityEvent\n'
                '| where EventID in (4624, 4625) and LogonType in (3, 10)\n'
                '| where SourceNetworkAddress != TargetDomainName\n'
                '| summarize count() by SourceNetworkAddress, TargetUserName, Computer, bin(TimeGenerated, 1h)\n'
                '| where count_ > {threshold}'
            ),
            "persistence": (
                'SecurityEvent\n'
                '| where EventID in (4698, 4699, 4700, 4701, 7045)\n'
                '| project TimeGenerated, Computer, Account, EventID, EventData\n'
                '| where TimeGenerated > ago({timeframe})'
            ),
            "credential_access": (
                'SecurityEvent\n'
                '| where EventID in (4768, 4769) and TicketEncryptionType == "0x17"\n'
                '| where ServiceName !endswith "$"\n'
                '| summarize count() by IpAddress, ServiceName, bin(TimeGenerated, 1h)\n'
                '| where count_ > {threshold}'
            ),
            "exfiltration": (
                'CommonSecurityLog\n'
                '| where DeviceAction == "allow" and SentBytes > {bytes_threshold}\n'
                '| summarize TotalBytes=sum(SentBytes) by SourceIP, DestinationIP, bin(TimeGenerated, 1h)\n'
                '| where TotalBytes > {total_threshold}'
            ),
            "command_and_control": (
                'CommonSecurityLog\n'
                '| where TimeGenerated > ago({timeframe})\n'
                '| summarize BeaconCount=count(), AvgInterval=avg(diff) by SourceIP, DestinationIP\n'
                '| where BeaconCount > {threshold} and AvgInterval between (50 .. 70)'
            ),
            "defense_evasion": (
                'SecurityEvent\n'
                '| where EventID in (1102, 4688)\n'
                '| where (EventID == 1102) or (EventID == 4688 and NewProcessName has_any ("wevtutil", "powershell"))\n'
                '| project TimeGenerated, Computer, Account, NewProcessName, CommandLine'
            ),
        },
        QueryLanguage.SIGMA: {
            "lateral_movement": (
                'title: Suspicious Lateral Movement\n'
                'status: experimental\n'
                'logsource:\n'
                '  category: authentication\n'
                '  product: windows\n'
                'detection:\n'
                '  selection:\n'
                '    EventID:\n'
                '      - 4624\n'
                '      - 4625\n'
                '    LogonType:\n'
                '      - 3\n'
                '      - 10\n'
                '  condition: selection\n'
                'level: medium'
            ),
            "persistence": (
                'title: New Service Installation\n'
                'status: experimental\n'
                'logsource:\n'
                '  product: windows\n'
                '  service: system\n'
                'detection:\n'
                '  selection:\n'
                '    EventID: 7045\n'
                '  condition: selection\n'
                'level: medium'
            ),
        },
    }

    async def _setup(self):
        self.active_hunts: Dict[str, Dict[str, Any]] = {}
        self.hunt_history: List[Dict[str, Any]] = []
        self.findings: List[Dict[str, Any]] = []

    async def _execute(self, parameters: Dict[str, Any]) -> SkillResult:
        action = parameters.get("action", "generate_hypothesis")

        dispatch = {
            "generate_hypothesis": self._generate_hypothesis,
            "generate_query": self._generate_query,
            "start_hunt": self._start_hunt,
            "record_finding": self._record_finding,
            "complete_hunt": self._complete_hunt,
            "list_hunts": self._list_hunts,
            "detect_anomalies": self._detect_anomalies,
            "hunt_lateral_movement": self._hunt_lateral_movement,
            "hunt_persistence": self._hunt_persistence,
            "hunt_exfiltration": self._hunt_exfiltration,
            "hunt_c2": self._hunt_c2,
        }

        handler = dispatch.get(action)
        if not handler:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"Unknown action '{action}'. Supported: {list(dispatch.keys())}"],
            )
        return await handler(parameters)

    # =========================================================================
    # Hypothesis Generation
    # =========================================================================

    async def _generate_hypothesis(self, params: Dict[str, Any]) -> SkillResult:
        """Generate hunt hypotheses based on threat context."""
        threat_context = params.get("threat_context", "")
        focus_area = params.get("focus_area", "")  # e.g., "lateral_movement"
        intelligence = params.get("intelligence", {})  # Incoming intel packets

        hypotheses = []

        if focus_area and focus_area in self.HUNT_HYPOTHESES:
            areas = {focus_area: self.HUNT_HYPOTHESES[focus_area]}
        else:
            areas = self.HUNT_HYPOTHESES

        for area_name, area_data in areas.items():
            relevance = self._calculate_relevance(area_name, threat_context, intelligence)

            hypothesis = {
                "hypothesis_id": f"HYP-{uuid.uuid4().hex[:8]}",
                "area": area_name,
                "description": area_data["description"],
                "mitre_techniques": area_data["techniques"],
                "indicators_to_hunt": area_data["indicators"],
                "relevance_score": relevance,
                "priority": "high" if relevance >= 70 else "medium" if relevance >= 40 else "low",
                "suggested_data_sources": self._suggest_data_sources(area_name),
                "estimated_effort_hours": self._estimate_effort(area_name),
            }
            hypotheses.append(hypothesis)

        # Sort by relevance
        hypotheses.sort(key=lambda h: h["relevance_score"], reverse=True)

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "hypotheses": hypotheses,
                "total": len(hypotheses),
                "context_used": bool(threat_context or intelligence),
            },
        )

    def _calculate_relevance(self, area: str, context: str, intelligence: Dict) -> float:
        """Score relevance of a hunt area to current threat context."""
        score = 50.0  # Base relevance

        context_lower = context.lower()
        area_data = self.HUNT_HYPOTHESES.get(area, {})

        # Check if context mentions related techniques or terms
        keywords = {
            "lateral_movement": ["lateral", "rdp", "smb", "psexec", "pivot", "spread"],
            "persistence": ["persist", "backdoor", "scheduled task", "registry", "startup", "service"],
            "credential_access": ["credential", "password", "kerberos", "lsass", "hash", "brute"],
            "exfiltration": ["exfil", "data theft", "upload", "transfer", "staging"],
            "command_and_control": ["c2", "beacon", "callback", "command and control", "implant"],
            "defense_evasion": ["evasion", "obfusc", "disable", "tamper", "log clear"],
            "initial_access_phishing": ["phish", "email", "macro", "link", "attachment"],
        }

        for kw in keywords.get(area, []):
            if kw in context_lower:
                score += 15
                break

        # Boost if intelligence references related MITRE techniques
        intel_techniques = intelligence.get("techniques", [])
        for tech in area_data.get("techniques", []):
            if tech in intel_techniques:
                score += 20
                break

        # Boost if recent incident is related
        if intelligence.get("active_incident"):
            score += 10

        return min(100.0, score)

    def _suggest_data_sources(self, area: str) -> List[str]:
        sources = {
            "lateral_movement": ["Windows Security Event Log", "Firewall Logs", "Network Flow Data", "EDR Telemetry"],
            "persistence": ["Windows System Log", "Sysmon", "EDR Telemetry", "Autoruns"],
            "credential_access": ["Windows Security Log", "Domain Controller Logs", "EDR Telemetry", "Vault Audit Logs"],
            "exfiltration": ["Proxy Logs", "Firewall Logs", "DLP Alerts", "DNS Logs", "Cloud Access Logs"],
            "command_and_control": ["DNS Logs", "Proxy Logs", "Firewall Logs", "EDR Telemetry", "NetFlow"],
            "defense_evasion": ["Sysmon", "Windows Security Log", "EDR Telemetry", "AV Logs"],
            "initial_access_phishing": ["Email Gateway Logs", "EDR Telemetry", "Proxy Logs", "Sysmon"],
        }
        return sources.get(area, ["EDR Telemetry", "SIEM"])

    def _estimate_effort(self, area: str) -> float:
        efforts = {
            "lateral_movement": 4.0,
            "persistence": 3.0,
            "credential_access": 4.0,
            "exfiltration": 6.0,
            "command_and_control": 5.0,
            "defense_evasion": 4.0,
            "initial_access_phishing": 3.0,
        }
        return efforts.get(area, 4.0)

    # =========================================================================
    # Query Generation
    # =========================================================================

    async def _generate_query(self, params: Dict[str, Any]) -> SkillResult:
        """Generate hunting queries for a specific hypothesis."""
        hypothesis_area = params.get("area", "lateral_movement")
        language = params.get("language", "kql")
        timeframe = params.get("timeframe", "7d")
        threshold = params.get("threshold", 10)
        custom_iocs = params.get("iocs", [])

        try:
            lang = QueryLanguage(language)
        except ValueError:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"Unsupported language '{language}'. Supported: {[l.value for l in QueryLanguage]}"],
            )

        queries = []

        # Get template queries
        templates = self.QUERY_TEMPLATES.get(lang, {})
        if hypothesis_area in templates:
            query = templates[hypothesis_area].format(
                timeframe=timeframe,
                threshold=threshold,
                bytes_threshold=1_000_000,
                total_threshold=100_000_000,
            )
            queries.append({
                "query": query,
                "language": lang.value,
                "description": f"Hunt for {hypothesis_area.replace('_', ' ')}",
                "data_source": self._suggest_data_sources(hypothesis_area)[0],
            })

        # Generate IOC-based queries if provided
        if custom_iocs:
            ioc_query = self._generate_ioc_query(lang, custom_iocs, timeframe)
            if ioc_query:
                queries.append(ioc_query)

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "queries": queries,
                "area": hypothesis_area,
                "language": lang.value,
                "parameters": {"timeframe": timeframe, "threshold": threshold},
            },
        )

    def _generate_ioc_query(self, lang: QueryLanguage, iocs: List[str], timeframe: str) -> Optional[Dict]:
        if lang == QueryLanguage.KQL:
            ioc_list = ", ".join(f'"{ioc}"' for ioc in iocs[:50])
            query = (
                f'let iocs = dynamic([{ioc_list}]);\n'
                f'union SecurityEvent, CommonSecurityLog, DnsEvents\n'
                f'| where TimeGenerated > ago({timeframe})\n'
                f'| where SourceIP in (iocs) or DestinationIP in (iocs) '
                f'or Name in (iocs) or FileHash in (iocs)\n'
                f'| project TimeGenerated, Computer, SourceIP, DestinationIP, Name'
            )
            return {"query": query, "language": lang.value, "description": "IOC-based hunt query", "data_source": "Multiple"}
        return None

    # =========================================================================
    # Hunt Campaign Management
    # =========================================================================

    async def _start_hunt(self, params: Dict[str, Any]) -> SkillResult:
        """Start a new threat hunt campaign."""
        hunt_id = f"HUNT-{uuid.uuid4().hex[:8]}"
        hunt = {
            "hunt_id": hunt_id,
            "name": params.get("name", f"Hunt {hunt_id}"),
            "hypothesis": params.get("hypothesis", ""),
            "area": params.get("area", "general"),
            "analyst": params.get("analyst", "automated"),
            "status": HuntStatus.ACTIVE.value,
            "started_at": datetime.now().isoformat(),
            "findings": [],
            "queries_executed": [],
            "data_sources": params.get("data_sources", []),
            "notes": [],
        }
        self.active_hunts[hunt_id] = hunt

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={"hunt": hunt},
        )

    async def _record_finding(self, params: Dict[str, Any]) -> SkillResult:
        """Record a finding within an active hunt."""
        hunt_id = params.get("hunt_id")
        if not hunt_id or hunt_id not in self.active_hunts:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"Hunt '{hunt_id}' not found"],
            )

        finding = {
            "finding_id": f"FND-{uuid.uuid4().hex[:8]}",
            "hunt_id": hunt_id,
            "timestamp": datetime.now().isoformat(),
            "description": params.get("description", ""),
            "severity": params.get("severity", "medium"),
            "affected_systems": params.get("affected_systems", []),
            "iocs": params.get("iocs", []),
            "mitre_techniques": params.get("mitre_techniques", []),
            "evidence": params.get("evidence", {}),
            "recommended_actions": params.get("recommended_actions", []),
            "escalate": params.get("escalate", False),
        }

        self.active_hunts[hunt_id]["findings"].append(finding)
        self.findings.append(finding)

        # Auto-escalate high-severity findings
        packets = []
        if finding["severity"] in ("critical", "high") or finding["escalate"]:
            packets.append(IntelligencePacket(
                packet_id=f"PKT-HUNT-{finding['finding_id']}",
                source_agent=self.agent_id,
                target_agents=["all"],
                intelligence_type=IntelligenceType.THREAT_CAMPAIGN,
                priority=Priority.HIGH if finding["severity"] == "critical" else Priority.MEDIUM,
                confidence=75.0,
                timestamp=datetime.now(),
                data={
                    "finding_id": finding["finding_id"],
                    "hunt_id": hunt_id,
                    "description": finding["description"],
                    "severity": finding["severity"],
                    "iocs": finding["iocs"],
                    "techniques": finding["mitre_techniques"],
                },
                correlation_keys=finding["iocs"][:20],
            ))

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={"finding": finding},
            intelligence_packets=packets,
        )

    async def _complete_hunt(self, params: Dict[str, Any]) -> SkillResult:
        """Complete a hunt campaign and generate summary."""
        hunt_id = params.get("hunt_id")
        if not hunt_id or hunt_id not in self.active_hunts:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"Hunt '{hunt_id}' not found"],
            )

        hunt = self.active_hunts[hunt_id]
        hunt["status"] = HuntStatus.COMPLETED.value
        hunt["completed_at"] = datetime.now().isoformat()
        hunt["conclusion"] = params.get("conclusion", "")

        summary = {
            "hunt_id": hunt_id,
            "name": hunt["name"],
            "duration": hunt["completed_at"],
            "total_findings": len(hunt["findings"]),
            "critical_findings": sum(1 for f in hunt["findings"] if f["severity"] == "critical"),
            "high_findings": sum(1 for f in hunt["findings"] if f["severity"] == "high"),
            "unique_iocs": list(set(ioc for f in hunt["findings"] for ioc in f.get("iocs", []))),
            "techniques_observed": list(set(t for f in hunt["findings"] for t in f.get("mitre_techniques", []))),
            "conclusion": hunt["conclusion"],
        }

        self.hunt_history.append(summary)
        del self.active_hunts[hunt_id]

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={"summary": summary},
        )

    async def _list_hunts(self, params: Dict[str, Any]) -> SkillResult:
        status_filter = params.get("status", "all")
        hunts = []
        for h in self.active_hunts.values():
            if status_filter == "all" or h["status"] == status_filter:
                hunts.append({
                    "hunt_id": h["hunt_id"],
                    "name": h["name"],
                    "status": h["status"],
                    "findings_count": len(h["findings"]),
                    "started_at": h["started_at"],
                })
        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={"active_hunts": hunts, "completed_hunts": len(self.hunt_history)},
        )

    # =========================================================================
    # Specialized Hunt Patterns
    # =========================================================================

    async def _detect_anomalies(self, params: Dict[str, Any]) -> SkillResult:
        """Detect anomalies in provided behavioral data."""
        data_points = params.get("data_points", [])
        baseline = params.get("baseline", {})
        sensitivity = params.get("sensitivity", 2.0)  # Standard deviations

        if not data_points:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["'data_points' required — list of {entity, metric, value} dicts"],
            )

        anomalies = []
        for point in data_points:
            entity = point.get("entity", "unknown")
            metric = point.get("metric", "unknown")
            value = point.get("value", 0)

            # Use baseline if provided, otherwise simple statistical check
            baseline_mean = baseline.get(f"{entity}_{metric}_mean", 0)
            baseline_std = baseline.get(f"{entity}_{metric}_std", 1)

            if baseline_std > 0:
                z_score = abs(value - baseline_mean) / baseline_std
                if z_score > sensitivity:
                    anomalies.append({
                        "entity": entity,
                        "metric": metric,
                        "value": value,
                        "baseline_mean": baseline_mean,
                        "z_score": round(z_score, 2),
                        "severity": "critical" if z_score > 4 else "high" if z_score > 3 else "medium",
                    })

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={"anomalies": anomalies, "total_checked": len(data_points), "anomalies_found": len(anomalies)},
        )

    async def _hunt_lateral_movement(self, params: Dict[str, Any]) -> SkillResult:
        """Generate a comprehensive lateral movement hunt package."""
        timeframe = params.get("timeframe", "7d")
        return await self._generate_hunt_package("lateral_movement", timeframe, params)

    async def _hunt_persistence(self, params: Dict[str, Any]) -> SkillResult:
        timeframe = params.get("timeframe", "30d")
        return await self._generate_hunt_package("persistence", timeframe, params)

    async def _hunt_exfiltration(self, params: Dict[str, Any]) -> SkillResult:
        timeframe = params.get("timeframe", "7d")
        return await self._generate_hunt_package("exfiltration", timeframe, params)

    async def _hunt_c2(self, params: Dict[str, Any]) -> SkillResult:
        timeframe = params.get("timeframe", "7d")
        return await self._generate_hunt_package("command_and_control", timeframe, params)

    async def _generate_hunt_package(self, area: str, timeframe: str, params: Dict) -> SkillResult:
        """Generate a complete hunt package for a given area."""
        # Generate hypothesis
        hyp_result = await self._generate_hypothesis({"focus_area": area, **params})
        hypotheses = hyp_result.data.get("hypotheses", [])

        # Generate queries for multiple languages
        queries = {}
        for lang in [QueryLanguage.KQL, QueryLanguage.SIGMA]:
            q_result = await self._generate_query({
                "area": area,
                "language": lang.value,
                "timeframe": timeframe,
                "iocs": params.get("iocs", []),
            })
            queries[lang.value] = q_result.data.get("queries", [])

        area_data = self.HUNT_HYPOTHESES.get(area, {})

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "hunt_package": {
                    "area": area,
                    "description": area_data.get("description", ""),
                    "hypotheses": hypotheses[:3],
                    "queries": queries,
                    "indicators_to_look_for": area_data.get("indicators", []),
                    "data_sources": self._suggest_data_sources(area),
                    "mitre_techniques": area_data.get("techniques", []),
                    "estimated_effort_hours": self._estimate_effort(area),
                    "timeframe": timeframe,
                },
            },
        )
