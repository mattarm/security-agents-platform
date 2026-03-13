#!/usr/bin/env python3
"""
Forensics Collection Skill — digital evidence acquisition, timeline analysis, and chain-of-custody.

Primary owner: Gamma (Blue Team)
Also usable by: Delta (Red Team) for post-exercise artifact review

Capabilities:
  - Host-based artifact collection planning (memory, disk, registry, event logs)
  - Browser forensics (history, cache, downloads)
  - Timeline construction from multiple artifact sources
  - Hash correlation for known malware
  - Chain-of-custody documentation
  - Evidence packaging and integrity verification
  - Forensic artifact parsing (Windows Event Logs, registry hives, prefetch)
"""

import hashlib
import uuid
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Any, Optional

from security_agents.core.models import SkillResult, IntelligencePacket, IntelligenceType, Priority
from security_agents.skills.base_skill import BaseSecuritySkill

# ---------------------------------------------------------------------------
# Forensic artifact taxonomy
# ---------------------------------------------------------------------------

class ArtifactCategory(Enum):
    MEMORY = "memory"
    DISK = "disk"
    REGISTRY = "registry"
    EVENT_LOG = "event_log"
    BROWSER = "browser"
    NETWORK = "network"
    PREFETCH = "prefetch"
    AMCACHE = "amcache"
    SHIMCACHE = "shimcache"
    USER_ACTIVITY = "user_activity"

class VolatilityOrder(Enum):
    """RFC 3227 order of volatility — collect most volatile first."""
    REGISTERS_CACHE = 1
    MEMORY = 2
    NETWORK_STATE = 3
    RUNNING_PROCESSES = 4
    DISK = 5
    REMOTE_LOGS = 6
    PHYSICAL_CONFIG = 7
    ARCHIVAL_MEDIA = 8

class EvidenceState(Enum):
    PLANNED = "planned"
    COLLECTING = "collecting"
    COLLECTED = "collected"
    ANALYZING = "analyzing"
    ANALYZED = "analyzed"
    PACKAGED = "packaged"
    ARCHIVED = "archived"

# ---------------------------------------------------------------------------
# Artifact definitions
# ---------------------------------------------------------------------------

ARTIFACT_DEFINITIONS: Dict[str, Dict[str, Any]] = {
    # Memory artifacts
    "full_memory_dump": {
        "category": ArtifactCategory.MEMORY.value,
        "volatility_order": VolatilityOrder.MEMORY.value,
        "description": "Full physical memory acquisition",
        "tools": ["winpmem", "linpmem", "osxpmem", "FTK Imager"],
        "typical_size_gb": 16,
        "priority": "critical",
    },
    "process_list": {
        "category": ArtifactCategory.MEMORY.value,
        "volatility_order": VolatilityOrder.RUNNING_PROCESSES.value,
        "description": "Running processes with command lines, PIDs, parent PIDs",
        "tools": ["volatility3", "pslist", "tasklist"],
        "typical_size_gb": 0.001,
        "priority": "critical",
    },
    "network_connections": {
        "category": ArtifactCategory.NETWORK.value,
        "volatility_order": VolatilityOrder.NETWORK_STATE.value,
        "description": "Active network connections and listening ports",
        "tools": ["volatility3:netscan", "netstat", "ss"],
        "typical_size_gb": 0.001,
        "priority": "critical",
    },
    # Disk artifacts
    "mft": {
        "category": ArtifactCategory.DISK.value,
        "volatility_order": VolatilityOrder.DISK.value,
        "description": "NTFS Master File Table — file metadata, timestamps, paths",
        "tools": ["MFTECmd", "analyzeMFT", "FTK Imager"],
        "typical_size_gb": 0.5,
        "priority": "high",
    },
    "usn_journal": {
        "category": ArtifactCategory.DISK.value,
        "volatility_order": VolatilityOrder.DISK.value,
        "description": "NTFS USN Change Journal — file creation, deletion, rename events",
        "tools": ["MFTECmd", "fsutil"],
        "typical_size_gb": 0.3,
        "priority": "high",
    },
    # Registry artifacts
    "registry_sam": {
        "category": ArtifactCategory.REGISTRY.value,
        "volatility_order": VolatilityOrder.DISK.value,
        "description": "SAM hive — local user accounts and password hashes",
        "tools": ["RegRipper", "RECmd", "Registry Explorer"],
        "typical_size_gb": 0.001,
        "priority": "high",
    },
    "registry_system": {
        "category": ArtifactCategory.REGISTRY.value,
        "volatility_order": VolatilityOrder.DISK.value,
        "description": "SYSTEM hive — services, drivers, hostname, timezone",
        "tools": ["RegRipper", "RECmd"],
        "typical_size_gb": 0.05,
        "priority": "high",
    },
    "registry_ntuser": {
        "category": ArtifactCategory.REGISTRY.value,
        "volatility_order": VolatilityOrder.DISK.value,
        "description": "NTUSER.DAT — per-user settings, recent docs, typed URLs, run keys",
        "tools": ["RegRipper", "RECmd"],
        "typical_size_gb": 0.02,
        "priority": "high",
    },
    # Event logs
    "evtx_security": {
        "category": ArtifactCategory.EVENT_LOG.value,
        "volatility_order": VolatilityOrder.DISK.value,
        "description": "Windows Security event log — logons (4624/4625), privilege use, audit policy",
        "tools": ["EvtxECmd", "python-evtx", "LogParser"],
        "key_event_ids": [4624, 4625, 4648, 4672, 4688, 4697, 4698, 4720, 4732],
        "typical_size_gb": 0.2,
        "priority": "critical",
    },
    "evtx_system": {
        "category": ArtifactCategory.EVENT_LOG.value,
        "volatility_order": VolatilityOrder.DISK.value,
        "description": "Windows System event log — service installs (7045), driver loads",
        "tools": ["EvtxECmd", "python-evtx"],
        "key_event_ids": [7045, 7036, 7040, 1074],
        "typical_size_gb": 0.1,
        "priority": "high",
    },
    "evtx_powershell": {
        "category": ArtifactCategory.EVENT_LOG.value,
        "volatility_order": VolatilityOrder.DISK.value,
        "description": "PowerShell operational log — script block logging (4104), module logging",
        "tools": ["EvtxECmd", "python-evtx"],
        "key_event_ids": [4103, 4104, 4105, 4106],
        "typical_size_gb": 0.1,
        "priority": "critical",
    },
    "evtx_sysmon": {
        "category": ArtifactCategory.EVENT_LOG.value,
        "volatility_order": VolatilityOrder.DISK.value,
        "description": "Sysmon log — process creation (1), network (3), file create (11), registry (13)",
        "tools": ["EvtxECmd", "python-evtx"],
        "key_event_ids": [1, 3, 7, 8, 10, 11, 12, 13, 22, 23],
        "typical_size_gb": 0.5,
        "priority": "critical",
    },
    # Browser artifacts
    "browser_history": {
        "category": ArtifactCategory.BROWSER.value,
        "volatility_order": VolatilityOrder.DISK.value,
        "description": "Browser history databases (Chrome, Firefox, Edge)",
        "tools": ["BrowsingHistoryView", "Hindsight", "KAPE"],
        "paths": {
            "chrome": "AppData/Local/Google/Chrome/User Data/Default/History",
            "firefox": "AppData/Roaming/Mozilla/Firefox/Profiles/*/places.sqlite",
            "edge": "AppData/Local/Microsoft/Edge/User Data/Default/History",
        },
        "typical_size_gb": 0.05,
        "priority": "medium",
    },
    "browser_downloads": {
        "category": ArtifactCategory.BROWSER.value,
        "volatility_order": VolatilityOrder.DISK.value,
        "description": "Browser download records",
        "tools": ["Hindsight", "KAPE"],
        "typical_size_gb": 0.01,
        "priority": "high",
    },
    "browser_cache": {
        "category": ArtifactCategory.BROWSER.value,
        "volatility_order": VolatilityOrder.DISK.value,
        "description": "Browser cache — may contain downloaded payloads",
        "tools": ["ChromeCacheView", "KAPE"],
        "typical_size_gb": 1.0,
        "priority": "medium",
    },
    # Execution artifacts
    "prefetch": {
        "category": ArtifactCategory.PREFETCH.value,
        "volatility_order": VolatilityOrder.DISK.value,
        "description": "Windows Prefetch — evidence of program execution with timestamps",
        "tools": ["PECmd", "WinPrefetchView"],
        "path": "C:/Windows/Prefetch/*.pf",
        "typical_size_gb": 0.01,
        "priority": "high",
    },
    "amcache": {
        "category": ArtifactCategory.AMCACHE.value,
        "volatility_order": VolatilityOrder.DISK.value,
        "description": "Amcache.hve — SHA1 hashes and paths of executed programs",
        "tools": ["AmcacheParser", "RECmd"],
        "path": "C:/Windows/AppCompat/Programs/Amcache.hve",
        "typical_size_gb": 0.01,
        "priority": "high",
    },
    "shimcache": {
        "category": ArtifactCategory.SHIMCACHE.value,
        "volatility_order": VolatilityOrder.DISK.value,
        "description": "Application Compatibility Cache — tracks executables, not proof of execution",
        "tools": ["AppCompatCacheParser", "ShimCacheParser"],
        "typical_size_gb": 0.001,
        "priority": "medium",
    },
}

# ---------------------------------------------------------------------------
# Known malware hash sets (sample entries for correlation)
# ---------------------------------------------------------------------------

KNOWN_MALWARE_HASHES: Dict[str, Dict[str, str]] = {
    "d41d8cd98f00b204e9800998ecf8427e": {"family": "empty_file", "severity": "info"},
    "44d88612fea8a8f36de82e1278abb02f": {"family": "EICAR_test", "severity": "info"},
    "a3c3b8e2f7c6d4e8f9a1b2c3d4e5f6a7": {"family": "Cobalt Strike Beacon", "severity": "critical"},
    "b7e8c9d0e1f2a3b4c5d6e7f8a9b0c1d2": {"family": "Mimikatz", "severity": "critical"},
    "c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6": {"family": "BloodHound Collector", "severity": "high"},
}

class ForensicsCollectionSkill(BaseSecuritySkill):
    """Plan, execute, and manage digital forensic evidence collection and analysis."""

    SKILL_NAME = "forensics_collection"
    DESCRIPTION = (
        "Digital forensics — artifact collection planning, timeline analysis, "
        "hash correlation, chain-of-custody, and evidence packaging"
    )
    VERSION = "1.0.0"
    COMPATIBLE_AGENTS = ["gamma_blue_team", "delta_red_team"]
    REQUIRED_INTEGRATIONS = []

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def _setup(self):
        """Initialize forensics state stores."""
        self.collection_plans: Dict[str, Dict[str, Any]] = {}
        self.evidence_store: Dict[str, Dict[str, Any]] = {}
        self.custody_chains: Dict[str, List[Dict[str, Any]]] = {}
        self.timelines: Dict[str, List[Dict[str, Any]]] = {}

    async def _execute(self, parameters: Dict[str, Any]) -> SkillResult:
        """
        Dispatch to the appropriate forensics action.

        Supported actions:
          plan_collection   — build a collection plan for a host
          collect_artifacts  — simulate artifact collection from a plan
          analyze_timeline   — construct a unified timeline from artifacts
          correlate_hashes   — check hashes against known malware databases
          document_custody   — record chain-of-custody transfer
          package_evidence   — seal and hash evidence for archival
          parse_artifacts    — parse specific artifact types (evtx, registry, prefetch)
        """
        action = parameters.get("action", "plan_collection")

        dispatch = {
            "plan_collection": self._plan_collection,
            "collect_artifacts": self._collect_artifacts,
            "analyze_timeline": self._analyze_timeline,
            "correlate_hashes": self._correlate_hashes,
            "document_custody": self._document_custody,
            "package_evidence": self._package_evidence,
            "parse_artifacts": self._parse_artifacts,
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
    # Collection Planning
    # ==================================================================

    async def _plan_collection(self, params: Dict[str, Any]) -> SkillResult:
        """Build a prioritized evidence collection plan following RFC 3227 volatility order."""
        hostname = params.get("hostname", "")
        os_type = params.get("os_type", "windows")
        incident_type = params.get("incident_type", "general")
        scope = params.get("scope", "full")  # full, memory_only, disk_only, logs_only

        if not hostname:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["'hostname' parameter required"],
            )

        # Select artifacts based on scope and incident type
        selected_artifacts = self._select_artifacts(os_type, incident_type, scope)

        # Sort by volatility order (most volatile first)
        selected_artifacts.sort(key=lambda a: a["volatility_order"])

        plan_id = f"PLAN-{uuid.uuid4().hex[:8]}"
        estimated_size_gb = sum(a["typical_size_gb"] for a in selected_artifacts)
        estimated_time_min = max(5, int(estimated_size_gb * 10))  # rough: ~10 min per GB

        plan = {
            "plan_id": plan_id,
            "hostname": hostname,
            "os_type": os_type,
            "incident_type": incident_type,
            "scope": scope,
            "state": EvidenceState.PLANNED.value,
            "artifacts": selected_artifacts,
            "estimated_size_gb": round(estimated_size_gb, 2),
            "estimated_time_minutes": estimated_time_min,
            "created_at": datetime.now().isoformat(),
            "created_by": self.agent_id,
            "notes": [],
        }
        self.collection_plans[plan_id] = plan

        # Initialize custody chain
        self.custody_chains[plan_id] = [{
            "action": "plan_created",
            "actor": self.agent_id,
            "timestamp": datetime.now().isoformat(),
            "description": f"Collection plan created for {hostname}",
        }]

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "plan_id": plan_id,
                "hostname": hostname,
                "artifact_count": len(selected_artifacts),
                "estimated_size_gb": round(estimated_size_gb, 2),
                "estimated_time_minutes": estimated_time_min,
                "collection_order": [a["name"] for a in selected_artifacts],
            },
        )

    # ==================================================================
    # Artifact Collection
    # ==================================================================

    async def _collect_artifacts(self, params: Dict[str, Any]) -> SkillResult:
        """Simulate artifact collection from a plan."""
        plan_id = params.get("plan_id", "")
        artifact_filter = params.get("artifacts")  # optional list to collect subset

        plan = self.collection_plans.get(plan_id)
        if not plan:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"Plan '{plan_id}' not found"],
            )

        plan["state"] = EvidenceState.COLLECTING.value
        artifacts = plan["artifacts"]
        if artifact_filter:
            artifacts = [a for a in artifacts if a["name"] in artifact_filter]

        collected = []
        for artifact in artifacts:
            evidence_id = f"EV-{uuid.uuid4().hex[:8]}"
            integrity_hash = hashlib.sha256(
                f"{evidence_id}:{artifact['name']}:{datetime.now().isoformat()}".encode()
            ).hexdigest()

            evidence = {
                "evidence_id": evidence_id,
                "plan_id": plan_id,
                "artifact_name": artifact["name"],
                "category": artifact["category"],
                "hostname": plan["hostname"],
                "collected_at": datetime.now().isoformat(),
                "collected_by": self.agent_id,
                "size_bytes": int(artifact["typical_size_gb"] * 1024 * 1024 * 1024),
                "sha256": integrity_hash,
                "state": EvidenceState.COLLECTED.value,
                "tool_used": artifact["tools"][0] if artifact["tools"] else "manual",
            }
            self.evidence_store[evidence_id] = evidence
            collected.append(evidence)

            # Record custody transfer
            if plan_id in self.custody_chains:
                self.custody_chains[plan_id].append({
                    "action": "artifact_collected",
                    "evidence_id": evidence_id,
                    "artifact": artifact["name"],
                    "actor": self.agent_id,
                    "timestamp": datetime.now().isoformat(),
                    "integrity_hash": integrity_hash,
                })

        plan["state"] = EvidenceState.COLLECTED.value

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "plan_id": plan_id,
                "collected_count": len(collected),
                "evidence_ids": [e["evidence_id"] for e in collected],
                "total_size_bytes": sum(e["size_bytes"] for e in collected),
            },
        )

    # ==================================================================
    # Timeline Analysis
    # ==================================================================

    async def _analyze_timeline(self, params: Dict[str, Any]) -> SkillResult:
        """Construct a unified forensic timeline from collected artifacts."""
        plan_id = params.get("plan_id", "")
        time_range_hours = params.get("time_range_hours", 24)
        focus_keywords = params.get("focus_keywords", [])

        plan = self.collection_plans.get(plan_id)
        if not plan:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"Plan '{plan_id}' not found"],
            )

        # Get evidence items for this plan
        evidence_items = [
            e for e in self.evidence_store.values() if e["plan_id"] == plan_id
        ]

        if not evidence_items:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"No collected evidence found for plan '{plan_id}'"],
            )

        # Simulate timeline construction — generate representative events
        timeline_id = f"TL-{uuid.uuid4().hex[:8]}"
        base_time = datetime.now() - timedelta(hours=time_range_hours)
        events = self._generate_timeline_events(evidence_items, base_time, time_range_hours)

        # Filter by keywords if provided
        if focus_keywords:
            events = [
                e for e in events
                if any(kw.lower() in e.get("description", "").lower() for kw in focus_keywords)
            ]

        self.timelines[timeline_id] = events

        # Identify suspicious clusters
        suspicious_clusters = self._identify_suspicious_patterns(events)

        packets: List[IntelligencePacket] = []
        if suspicious_clusters:
            packets.append(IntelligencePacket(
                packet_id=f"PKT-FORENSIC-{timeline_id}",
                source_agent=self.agent_id,
                target_agents=["all"],
                intelligence_type=IntelligenceType.INCIDENT,
                priority=Priority.HIGH,
                confidence=75.0,
                timestamp=datetime.now(),
                data={
                    "timeline_id": timeline_id,
                    "plan_id": plan_id,
                    "hostname": plan["hostname"],
                    "suspicious_patterns": suspicious_clusters,
                },
                correlation_keys=[plan["hostname"], plan_id],
            ))

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "timeline_id": timeline_id,
                "plan_id": plan_id,
                "event_count": len(events),
                "time_range_hours": time_range_hours,
                "events": events[:50],  # return first 50 for readability
                "suspicious_patterns": suspicious_clusters,
            },
            intelligence_packets=packets,
        )

    # ==================================================================
    # Hash Correlation
    # ==================================================================

    async def _correlate_hashes(self, params: Dict[str, Any]) -> SkillResult:
        """Correlate file hashes against known malware databases."""
        hashes = params.get("hashes", [])
        hash_type = params.get("hash_type", "md5")

        if not hashes:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["'hashes' parameter required — provide a list of hash values"],
            )

        matches = []
        clean = []
        unknown = []

        for h in hashes:
            h_lower = h.lower().strip()
            match = KNOWN_MALWARE_HASHES.get(h_lower)
            if match:
                matches.append({
                    "hash": h_lower,
                    "hash_type": hash_type,
                    "family": match["family"],
                    "severity": match["severity"],
                    "match_source": "internal_threat_db",
                })
            else:
                # Heuristic: check entropy-like patterns (simplified)
                if len(h_lower) == 32 and all(c in "0123456789abcdef" for c in h_lower):
                    unknown.append({"hash": h_lower, "hash_type": "md5", "status": "unknown"})
                elif len(h_lower) == 64 and all(c in "0123456789abcdef" for c in h_lower):
                    unknown.append({"hash": h_lower, "hash_type": "sha256", "status": "unknown"})
                else:
                    clean.append({"hash": h_lower, "status": "invalid_format"})

        packets: List[IntelligencePacket] = []
        if matches:
            critical_matches = [m for m in matches if m["severity"] == "critical"]
            if critical_matches:
                packets.append(IntelligencePacket(
                    packet_id=f"PKT-HASH-{uuid.uuid4().hex[:8]}",
                    source_agent=self.agent_id,
                    target_agents=["all"],
                    intelligence_type=IntelligenceType.IOC_ENRICHMENT,
                    priority=Priority.CRITICAL,
                    confidence=95.0,
                    timestamp=datetime.now(),
                    data={
                        "matches": critical_matches,
                        "context": "Forensic hash correlation found known malware",
                    },
                    correlation_keys=[m["hash"] for m in critical_matches],
                ))

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "total_checked": len(hashes),
                "matches": matches,
                "unknown": unknown,
                "clean": clean,
                "match_count": len(matches),
            },
            intelligence_packets=packets,
        )

    # ==================================================================
    # Chain of Custody
    # ==================================================================

    async def _document_custody(self, params: Dict[str, Any]) -> SkillResult:
        """Record a chain-of-custody transfer event."""
        plan_id = params.get("plan_id", "")
        evidence_id = params.get("evidence_id")
        action = params.get("custody_action", "transfer")
        from_actor = params.get("from_actor", self.agent_id)
        to_actor = params.get("to_actor", "")
        reason = params.get("reason", "")
        location = params.get("location", "")

        chain = self.custody_chains.get(plan_id)
        if chain is None:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"No custody chain found for plan '{plan_id}'"],
            )

        entry = {
            "action": action,
            "evidence_id": evidence_id,
            "from_actor": from_actor,
            "to_actor": to_actor,
            "reason": reason,
            "location": location,
            "timestamp": datetime.now().isoformat(),
            "entry_hash": hashlib.sha256(
                f"{action}:{evidence_id}:{from_actor}:{to_actor}:{datetime.now().isoformat()}".encode()
            ).hexdigest()[:16],
        }
        chain.append(entry)

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "plan_id": plan_id,
                "custody_entry": entry,
                "chain_length": len(chain),
            },
        )

    # ==================================================================
    # Evidence Packaging
    # ==================================================================

    async def _package_evidence(self, params: Dict[str, Any]) -> SkillResult:
        """Seal and hash evidence items for archival or legal hold."""
        plan_id = params.get("plan_id", "")
        case_id = params.get("case_id", "")
        examiner = params.get("examiner", self.agent_id)

        plan = self.collection_plans.get(plan_id)
        if not plan:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"Plan '{plan_id}' not found"],
            )

        evidence_items = [
            e for e in self.evidence_store.values() if e["plan_id"] == plan_id
        ]

        if not evidence_items:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["No evidence to package"],
            )

        # Build package manifest
        package_id = f"PKG-{uuid.uuid4().hex[:8]}"
        manifest_content = f"Package: {package_id}\nCase: {case_id}\nExaminer: {examiner}\n"
        for item in evidence_items:
            manifest_content += f"\n  {item['evidence_id']}: {item['artifact_name']} (SHA256: {item['sha256']})"
            item["state"] = EvidenceState.PACKAGED.value

        manifest_hash = hashlib.sha256(manifest_content.encode()).hexdigest()

        plan["state"] = EvidenceState.PACKAGED.value

        # Record in custody chain
        if plan_id in self.custody_chains:
            self.custody_chains[plan_id].append({
                "action": "evidence_packaged",
                "package_id": package_id,
                "actor": examiner,
                "timestamp": datetime.now().isoformat(),
                "manifest_hash": manifest_hash,
                "item_count": len(evidence_items),
            })

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "package_id": package_id,
                "plan_id": plan_id,
                "case_id": case_id,
                "item_count": len(evidence_items),
                "manifest_hash": manifest_hash,
                "total_size_bytes": sum(e["size_bytes"] for e in evidence_items),
                "evidence_ids": [e["evidence_id"] for e in evidence_items],
            },
        )

    # ==================================================================
    # Artifact Parsing
    # ==================================================================

    async def _parse_artifacts(self, params: Dict[str, Any]) -> SkillResult:
        """Parse specific forensic artifact types and extract structured data."""
        artifact_type = params.get("artifact_type", "")
        evidence_id = params.get("evidence_id", "")

        evidence = self.evidence_store.get(evidence_id)
        if not evidence:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"Evidence '{evidence_id}' not found"],
            )

        parsers = {
            "evtx": self._parse_evtx,
            "registry": self._parse_registry,
            "prefetch": self._parse_prefetch,
            "mft": self._parse_mft,
            "browser_history": self._parse_browser,
        }

        parser = parsers.get(artifact_type)
        if not parser:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"Unknown artifact type '{artifact_type}'. Supported: {', '.join(parsers.keys())}"],
            )

        parsed_data = parser(evidence)
        evidence["state"] = EvidenceState.ANALYZED.value

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "evidence_id": evidence_id,
                "artifact_type": artifact_type,
                "parsed_records": len(parsed_data),
                "records": parsed_data[:100],  # cap output
            },
        )

    # ==================================================================
    # Internal Helpers
    # ==================================================================

    def _select_artifacts(
        self, os_type: str, incident_type: str, scope: str,
    ) -> List[Dict[str, Any]]:
        """Select relevant artifacts based on OS, incident type, and scope."""
        artifacts = []
        for name, defn in ARTIFACT_DEFINITIONS.items():
            # Scope filtering
            cat = defn["category"]
            if scope == "memory_only" and cat != ArtifactCategory.MEMORY.value:
                continue
            if scope == "disk_only" and cat in (ArtifactCategory.MEMORY.value, ArtifactCategory.NETWORK.value):
                continue
            if scope == "logs_only" and cat != ArtifactCategory.EVENT_LOG.value:
                continue

            # OS filtering — skip Windows-specific artifacts on non-Windows
            windows_only = {"registry_sam", "registry_system", "registry_ntuser",
                            "evtx_security", "evtx_system", "evtx_powershell",
                            "evtx_sysmon", "prefetch", "amcache", "shimcache", "mft", "usn_journal"}
            if os_type != "windows" and name in windows_only:
                continue

            # Incident type priority boost
            priority = defn.get("priority", "medium")
            if incident_type == "malware" and cat in (
                ArtifactCategory.MEMORY.value, ArtifactCategory.PREFETCH.value,
                ArtifactCategory.AMCACHE.value,
            ):
                priority = "critical"
            elif incident_type == "lateral_movement" and cat in (
                ArtifactCategory.EVENT_LOG.value, ArtifactCategory.NETWORK.value,
            ):
                priority = "critical"
            elif incident_type == "data_exfil" and cat in (
                ArtifactCategory.NETWORK.value, ArtifactCategory.BROWSER.value,
            ):
                priority = "critical"

            artifact_entry = dict(defn)
            artifact_entry["name"] = name
            artifact_entry["priority"] = priority
            artifacts.append(artifact_entry)

        return artifacts

    def _generate_timeline_events(
        self, evidence_items: List[Dict[str, Any]], base_time: datetime, hours: int,
    ) -> List[Dict[str, Any]]:
        """Generate representative timeline events from collected artifacts."""
        events: List[Dict[str, Any]] = []
        event_templates = [
            {"source": "evtx_security", "event_id": 4624, "description": "Successful logon — user {user}",
             "severity": "info"},
            {"source": "evtx_security", "event_id": 4625, "description": "Failed logon attempt — user {user}",
             "severity": "medium"},
            {"source": "evtx_security", "event_id": 4688, "description": "Process created: {process}",
             "severity": "info"},
            {"source": "evtx_sysmon", "event_id": 1, "description": "Process creation: {process} (PID {pid})",
             "severity": "info"},
            {"source": "evtx_sysmon", "event_id": 3, "description": "Network connection: {src} -> {dst}:{port}",
             "severity": "low"},
            {"source": "evtx_powershell", "event_id": 4104, "description": "PowerShell script block: {snippet}",
             "severity": "medium"},
            {"source": "prefetch", "event_id": None, "description": "Program executed: {binary}",
             "severity": "info"},
            {"source": "registry", "event_id": None, "description": "Registry modification: {key}",
             "severity": "low"},
        ]

        # Generate a set of events spread across the time range
        import random
        rng = random.Random(42)  # deterministic for reproducibility
        sample_values = {
            "user": ["admin", "svc_account", "jsmith", "SYSTEM"],
            "process": ["cmd.exe", "powershell.exe", "rundll32.exe", "svchost.exe", "explorer.exe"],
            "pid": ["1234", "5678", "9012", "3456"],
            "src": ["10.0.1.50", "192.168.1.100"],
            "dst": ["203.0.113.50", "198.51.100.10", "10.0.1.1"],
            "port": ["443", "80", "8080", "4444"],
            "snippet": ["Invoke-Expression", "DownloadString", "Set-MpPreference -DisableRealtimeMonitoring"],
            "binary": ["mimikatz.exe", "psexec.exe", "whoami.exe", "net.exe"],
            "key": ["HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU\\Software\\Classes\\ms-settings"],
        }

        for i in range(min(200, len(evidence_items) * 25)):
            template = rng.choice(event_templates)
            offset_minutes = rng.randint(0, hours * 60)
            event_time = base_time + timedelta(minutes=offset_minutes)

            desc = template["description"]
            for key, values in sample_values.items():
                placeholder = "{" + key + "}"
                if placeholder in desc:
                    desc = desc.replace(placeholder, rng.choice(values))

            events.append({
                "timestamp": event_time.isoformat(),
                "source": template["source"],
                "event_id": template["event_id"],
                "description": desc,
                "severity": template["severity"],
            })

        events.sort(key=lambda e: e["timestamp"])
        return events

    def _identify_suspicious_patterns(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify suspicious clusters in the timeline."""
        patterns = []
        suspicious_keywords = [
            "mimikatz", "powershell", "Invoke-Expression", "DownloadString",
            "psexec", "rundll32", "DisableRealtimeMonitoring", "4444",
        ]

        flagged_events = [
            e for e in events
            if any(kw.lower() in e.get("description", "").lower() for kw in suspicious_keywords)
        ]

        if flagged_events:
            patterns.append({
                "pattern": "suspicious_tool_execution",
                "event_count": len(flagged_events),
                "severity": "high",
                "description": "Detected execution of known offensive tools or suspicious commands",
                "sample_events": flagged_events[:5],
            })

        # Check for brute-force pattern (multiple failed logons)
        failed_logons = [e for e in events if "Failed logon" in e.get("description", "")]
        if len(failed_logons) >= 5:
            patterns.append({
                "pattern": "brute_force_attempt",
                "event_count": len(failed_logons),
                "severity": "medium",
                "description": f"Detected {len(failed_logons)} failed logon attempts",
            })

        return patterns

    def _parse_evtx(self, evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Simulate parsing of Windows Event Log (EVTX) files."""
        return [
            {"event_id": 4624, "timestamp": datetime.now().isoformat(), "logon_type": 3,
             "account": "admin", "source_ip": "10.0.1.50", "status": "success"},
            {"event_id": 4688, "timestamp": datetime.now().isoformat(),
             "process": "cmd.exe", "parent_process": "explorer.exe", "command_line": "cmd /c whoami"},
            {"event_id": 7045, "timestamp": datetime.now().isoformat(),
             "service_name": "SuspiciousSvc", "binary_path": "C:\\Temp\\payload.exe", "start_type": "auto"},
        ]

    def _parse_registry(self, evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Simulate parsing of Windows registry hive."""
        return [
            {"hive": "SYSTEM", "key": "ControlSet001\\Services\\SuspiciousSvc",
             "value": "C:\\Temp\\payload.exe", "last_modified": datetime.now().isoformat()},
            {"hive": "NTUSER", "key": "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
             "value": "C:\\Users\\admin\\AppData\\updater.exe", "last_modified": datetime.now().isoformat()},
        ]

    def _parse_prefetch(self, evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Simulate parsing of Windows Prefetch files."""
        return [
            {"executable": "MIMIKATZ.EXE", "run_count": 3,
             "last_run": datetime.now().isoformat(), "hash": "A3C3B8E2"},
            {"executable": "PSEXEC.EXE", "run_count": 1,
             "last_run": datetime.now().isoformat(), "hash": "B7E8C9D0"},
            {"executable": "CMD.EXE", "run_count": 47,
             "last_run": datetime.now().isoformat(), "hash": "E19B3A08"},
        ]

    def _parse_mft(self, evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Simulate parsing of NTFS MFT entries."""
        return [
            {"record_number": 12345, "filename": "payload.exe",
             "path": "C:\\Temp\\payload.exe", "size": 45056,
             "created": datetime.now().isoformat(), "modified": datetime.now().isoformat(),
             "is_deleted": False},
            {"record_number": 12346, "filename": "exfil.zip",
             "path": "C:\\Users\\admin\\Documents\\exfil.zip", "size": 1048576,
             "created": datetime.now().isoformat(), "modified": datetime.now().isoformat(),
             "is_deleted": True},
        ]

    def _parse_browser(self, evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Simulate parsing of browser history databases."""
        return [
            {"browser": "chrome", "url": "https://drive.google.com/upload",
             "title": "Google Drive", "visit_time": datetime.now().isoformat(), "visit_count": 5},
            {"browser": "chrome", "url": "https://paste.ee/p/abc123",
             "title": "Paste.ee", "visit_time": datetime.now().isoformat(), "visit_count": 1},
            {"browser": "chrome", "url": "https://mega.nz/file/xyz",
             "title": "MEGA", "visit_time": datetime.now().isoformat(), "visit_count": 2},
        ]
