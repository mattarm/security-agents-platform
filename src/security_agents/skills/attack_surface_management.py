#!/usr/bin/env python3
"""
Attack Surface Management Skill — Discover, monitor, and reduce external attack surface.

Primary owners: Delta (Red Team), Alpha-4 (Threat Intel)

Capabilities:
  - Asset discovery (domains, IPs, ports, services, cloud resources)
  - Exposure scoring per asset and aggregate
  - Change tracking with delta analysis over time
  - Technology fingerprinting for web services
  - Certificate monitoring (expiry, weak ciphers, trust chain)
  - Subdomain enumeration logic
  - Risk prioritization with business context
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

class AssetType(Enum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP_ADDRESS = "ip_address"
    PORT_SERVICE = "port_service"
    WEB_APPLICATION = "web_application"
    API_ENDPOINT = "api_endpoint"
    CLOUD_RESOURCE = "cloud_resource"
    CERTIFICATE = "certificate"
    DNS_RECORD = "dns_record"
    EMAIL_SERVICE = "email_service"

class ExposureLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"

class ChangeType(Enum):
    NEW_ASSET = "new_asset"
    REMOVED_ASSET = "removed_asset"
    PORT_OPENED = "port_opened"
    PORT_CLOSED = "port_closed"
    SERVICE_CHANGED = "service_changed"
    CERTIFICATE_CHANGED = "certificate_changed"
    TECHNOLOGY_CHANGED = "technology_changed"
    EXPOSURE_CHANGED = "exposure_changed"

# =============================================================================
# Risk data: port risk scores, technology fingerprints
# =============================================================================

# Higher score = more risky when exposed to the internet
PORT_RISK_SCORES: Dict[int, Dict[str, Any]] = {
    21: {"service": "FTP", "risk": 9, "reason": "Cleartext file transfer, credential sniffing"},
    22: {"service": "SSH", "risk": 5, "reason": "Remote access, brute-force target"},
    23: {"service": "Telnet", "risk": 10, "reason": "Cleartext remote access, no encryption"},
    25: {"service": "SMTP", "risk": 6, "reason": "Email relay, spam vector if misconfigured"},
    53: {"service": "DNS", "risk": 5, "reason": "DNS amplification, zone transfer leaks"},
    80: {"service": "HTTP", "risk": 4, "reason": "Unencrypted web traffic"},
    110: {"service": "POP3", "risk": 7, "reason": "Cleartext email retrieval"},
    111: {"service": "RPCbind", "risk": 8, "reason": "RPC service enumeration, historical exploits"},
    135: {"service": "MS-RPC", "risk": 8, "reason": "Windows RPC, lateral movement vector"},
    139: {"service": "NetBIOS", "risk": 9, "reason": "SMB session enumeration, legacy protocol"},
    143: {"service": "IMAP", "risk": 6, "reason": "Cleartext email access"},
    443: {"service": "HTTPS", "risk": 2, "reason": "Standard encrypted web — low risk if properly configured"},
    445: {"service": "SMB", "risk": 9, "reason": "File sharing, WannaCry/EternalBlue vector"},
    993: {"service": "IMAPS", "risk": 2, "reason": "Encrypted email access"},
    995: {"service": "POP3S", "risk": 2, "reason": "Encrypted email retrieval"},
    1433: {"service": "MSSQL", "risk": 9, "reason": "Database direct access from internet"},
    1521: {"service": "Oracle DB", "risk": 9, "reason": "Database direct access from internet"},
    2049: {"service": "NFS", "risk": 9, "reason": "Network file system, data exfiltration risk"},
    3306: {"service": "MySQL", "risk": 9, "reason": "Database direct access from internet"},
    3389: {"service": "RDP", "risk": 9, "reason": "Remote desktop, brute-force and exploit target"},
    5432: {"service": "PostgreSQL", "risk": 9, "reason": "Database direct access from internet"},
    5900: {"service": "VNC", "risk": 9, "reason": "Remote desktop, often weak or no auth"},
    6379: {"service": "Redis", "risk": 10, "reason": "In-memory store, often unauthenticated by default"},
    8080: {"service": "HTTP-Alt", "risk": 5, "reason": "Alternative HTTP, often dev/admin interfaces"},
    8443: {"service": "HTTPS-Alt", "risk": 3, "reason": "Alternative HTTPS endpoint"},
    9200: {"service": "Elasticsearch", "risk": 9, "reason": "Search engine, often unauthenticated"},
    11211: {"service": "Memcached", "risk": 9, "reason": "Cache, amplification attacks, data exposure"},
    27017: {"service": "MongoDB", "risk": 10, "reason": "NoSQL database, historically default no-auth"},
}

TECHNOLOGY_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "nginx": {"category": "web_server", "risk_modifier": 0, "notes": "Well-maintained, but check version"},
    "apache": {"category": "web_server", "risk_modifier": 0, "notes": "Check for mod_status exposure"},
    "iis": {"category": "web_server", "risk_modifier": 1, "notes": "Ensure Windows Server is patched"},
    "express": {"category": "framework", "risk_modifier": 0, "notes": "Node.js framework"},
    "django": {"category": "framework", "risk_modifier": 0, "notes": "Python framework"},
    "rails": {"category": "framework", "risk_modifier": 0, "notes": "Ruby framework"},
    "spring": {"category": "framework", "risk_modifier": 0, "notes": "Java framework, check actuator endpoints"},
    "wordpress": {"category": "cms", "risk_modifier": 3, "notes": "Plugin vulnerabilities common, keep updated"},
    "drupal": {"category": "cms", "risk_modifier": 2, "notes": "Drupalgeddon history, ensure patched"},
    "joomla": {"category": "cms", "risk_modifier": 2, "notes": "Extension vulnerabilities common"},
    "php": {"category": "language", "risk_modifier": 1, "notes": "Check version, disable dangerous functions"},
    "tomcat": {"category": "app_server", "risk_modifier": 1, "notes": "Check manager interface exposure"},
    "jenkins": {"category": "ci_cd", "risk_modifier": 4, "notes": "CI/CD — high value target, check auth"},
    "grafana": {"category": "monitoring", "risk_modifier": 2, "notes": "Dashboard exposure, check anonymous access"},
    "kibana": {"category": "monitoring", "risk_modifier": 3, "notes": "Often paired with open Elasticsearch"},
    "phpmyadmin": {"category": "admin_tool", "risk_modifier": 5, "notes": "Database admin interface — critical if exposed"},
    "kubernetes-dashboard": {"category": "orchestration", "risk_modifier": 5, "notes": "Cluster admin — must not be public"},
}

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "admin", "portal", "api", "dev", "staging", "test",
    "uat", "demo", "beta", "app", "mobile", "m", "cdn", "assets", "static",
    "media", "img", "images", "docs", "wiki", "git", "gitlab", "jenkins",
    "ci", "jira", "confluence", "grafana", "kibana", "prometheus", "monitor",
    "status", "health", "internal", "intranet", "db", "database", "redis",
    "elastic", "search", "auth", "login", "sso", "oauth", "id", "accounts",
    "support", "help", "shop", "store", "pay", "billing", "crm", "erp",
    "mx", "pop", "imap", "exchange", "autodiscover", "relay", "backup",
]

class AttackSurfaceManagementSkill(BaseSecuritySkill):
    """Discover, monitor, and prioritize attack surface exposure."""

    SKILL_NAME = "attack_surface_management"
    DESCRIPTION = (
        "Discover and monitor external attack surface including domains, IPs, ports, "
        "services, and cloud resources with exposure scoring and change tracking"
    )
    VERSION = "1.0.0"
    COMPATIBLE_AGENTS = ["delta_red_team", "alpha_4_threat_intel"]
    REQUIRED_INTEGRATIONS = []

    async def _setup(self):
        self.assets: Dict[str, Dict[str, Any]] = {}  # asset_id -> asset data
        self.scan_history: List[Dict[str, Any]] = []
        self.changes: List[Dict[str, Any]] = []

    async def _execute(self, parameters: Dict[str, Any]) -> SkillResult:
        action = parameters.get("action", "discover_assets")

        dispatch = {
            "discover_assets": self._discover_assets,
            "scan_surface": self._scan_surface,
            "assess_exposure": self._assess_exposure,
            "track_changes": self._track_changes,
            "prioritize_risks": self._prioritize_risks,
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
    # Discover Assets
    # =========================================================================

    async def _discover_assets(self, params: Dict[str, Any]) -> SkillResult:
        """Discover assets from provided seed data (domains, IPs, cloud accounts)."""
        seed_domains = params.get("domains", [])
        seed_ips = params.get("ip_addresses", [])
        cloud_resources = params.get("cloud_resources", [])
        dns_records = params.get("dns_records", [])
        include_subdomain_enum = params.get("enumerate_subdomains", True)

        if not seed_domains and not seed_ips and not cloud_resources:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["Provide at least one of: 'domains', 'ip_addresses', or 'cloud_resources'"],
            )

        discovered = []
        scan_id = f"DISC-{uuid.uuid4().hex[:8]}"

        # Register primary domains
        for domain in seed_domains:
            asset = self._register_asset(
                name=domain, asset_type=AssetType.DOMAIN.value,
                details={"source": "seed", "registrable_domain": domain},
            )
            discovered.append(asset)

            # Enumerate subdomains
            if include_subdomain_enum:
                subdomain_assets = self._enumerate_subdomains(domain)
                discovered.extend(subdomain_assets)

        # Register IP addresses
        for ip_entry in seed_ips:
            ip = ip_entry if isinstance(ip_entry, str) else ip_entry.get("address", "")
            details = ip_entry if isinstance(ip_entry, dict) else {"address": ip}
            asset = self._register_asset(
                name=ip, asset_type=AssetType.IP_ADDRESS.value,
                details={**details, "source": "seed"},
            )
            discovered.append(asset)

        # Register cloud resources
        for resource in cloud_resources:
            asset = self._register_asset(
                name=resource.get("name", resource.get("id", "unknown")),
                asset_type=AssetType.CLOUD_RESOURCE.value,
                details={
                    "provider": resource.get("provider", "unknown"),
                    "resource_type": resource.get("type", "unknown"),
                    "region": resource.get("region", "unknown"),
                    "public": resource.get("public", False),
                    "source": "seed",
                    **resource,
                },
            )
            discovered.append(asset)

        # Register DNS records
        for record in dns_records:
            asset = self._register_asset(
                name=f"{record.get('name', 'unknown')}:{record.get('type', 'A')}",
                asset_type=AssetType.DNS_RECORD.value,
                details=record,
            )
            discovered.append(asset)

        scan_record = {
            "scan_id": scan_id,
            "scan_type": "discovery",
            "timestamp": datetime.now().isoformat(),
            "seed_domains": len(seed_domains),
            "seed_ips": len(seed_ips),
            "cloud_resources": len(cloud_resources),
            "total_discovered": len(discovered),
        }
        self.scan_history.append(scan_record)

        type_breakdown = {}
        for a in discovered:
            at = a.get("asset_type", "unknown")
            type_breakdown[at] = type_breakdown.get(at, 0) + 1

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "scan_id": scan_id,
                "discovered_assets": discovered,
                "total_discovered": len(discovered),
                "type_breakdown": type_breakdown,
                "total_inventory": len(self.assets),
            },
        )

    # =========================================================================
    # Scan Surface
    # =========================================================================

    async def _scan_surface(self, params: Dict[str, Any]) -> SkillResult:
        """Scan known assets for open ports, services, technologies, and certificates."""
        target_assets = params.get("asset_ids", [])
        port_scan_results = params.get("port_scan_results", [])  # [{asset, ports: [{port, state, service, version}]}]
        http_responses = params.get("http_responses", [])  # [{asset, status, headers, technologies}]
        certificates = params.get("certificates", [])  # [{asset, subject, issuer, not_after, san, ...}]

        scan_id = f"SCAN-{uuid.uuid4().hex[:8]}"
        findings = []

        # Process port scan results
        for result in port_scan_results:
            asset_name = result.get("asset", "")
            for port_info in result.get("ports", []):
                port = port_info.get("port", 0)
                state = port_info.get("state", "open")
                service = port_info.get("service", "")
                version = port_info.get("version", "")

                port_risk = PORT_RISK_SCORES.get(port, {"service": service or "unknown", "risk": 3, "reason": "Unknown service"})

                port_asset = self._register_asset(
                    name=f"{asset_name}:{port}",
                    asset_type=AssetType.PORT_SERVICE.value,
                    details={
                        "host": asset_name,
                        "port": port,
                        "state": state,
                        "service": service or port_risk["service"],
                        "version": version,
                        "risk_score": port_risk["risk"],
                        "risk_reason": port_risk["reason"],
                    },
                )
                findings.append(port_asset)

                # Flag high-risk open ports
                if port_risk["risk"] >= 8:
                    findings.append({
                        "type": "high_risk_port",
                        "asset": asset_name,
                        "port": port,
                        "service": port_risk["service"],
                        "risk_score": port_risk["risk"],
                        "reason": port_risk["reason"],
                        "recommendation": f"Close port {port} ({port_risk['service']}) or restrict access with firewall rules",
                    })

        # Process HTTP responses for technology fingerprinting
        for response in http_responses:
            asset_name = response.get("asset", "")
            headers = response.get("headers", {})
            technologies = response.get("technologies", [])
            status_code = response.get("status", 0)

            # Fingerprint from headers
            detected_tech = list(technologies)
            server_header = headers.get("server", headers.get("Server", ""))
            if server_header:
                for tech_name, tech_info in TECHNOLOGY_SIGNATURES.items():
                    if tech_name.lower() in server_header.lower():
                        detected_tech.append(tech_name)

            powered_by = headers.get("x-powered-by", headers.get("X-Powered-By", ""))
            if powered_by:
                for tech_name in TECHNOLOGY_SIGNATURES:
                    if tech_name.lower() in powered_by.lower():
                        detected_tech.append(tech_name)

            # Check security headers
            security_headers = self._check_security_headers(headers)

            web_asset = self._register_asset(
                name=asset_name,
                asset_type=AssetType.WEB_APPLICATION.value,
                details={
                    "status_code": status_code,
                    "technologies": list(set(detected_tech)),
                    "security_headers": security_headers,
                    "server": server_header,
                    "x_powered_by": powered_by,
                },
            )
            findings.append(web_asset)

        # Process certificates
        for cert in certificates:
            asset_name = cert.get("asset", "")
            not_after_str = cert.get("not_after", "")
            issues = []

            # Check expiry
            if not_after_str:
                try:
                    not_after = datetime.fromisoformat(not_after_str.replace("Z", "+00:00"))
                    days_remaining = (not_after - datetime.now(not_after.tzinfo if not_after.tzinfo else None)).days
                    if days_remaining < 0:
                        issues.append({"issue": "expired", "severity": "critical", "detail": f"Certificate expired {abs(days_remaining)} days ago"})
                    elif days_remaining < 30:
                        issues.append({"issue": "expiring_soon", "severity": "high", "detail": f"Certificate expires in {days_remaining} days"})
                    elif days_remaining < 90:
                        issues.append({"issue": "expiring", "severity": "medium", "detail": f"Certificate expires in {days_remaining} days"})
                    cert["days_remaining"] = days_remaining
                except (ValueError, TypeError):
                    cert["days_remaining"] = None

            # Check for weak key
            key_size = cert.get("key_size", 0)
            if key_size and key_size < 2048:
                issues.append({"issue": "weak_key", "severity": "high", "detail": f"Key size {key_size} bits is below minimum 2048"})

            # Check for self-signed
            if cert.get("self_signed", False):
                issues.append({"issue": "self_signed", "severity": "medium", "detail": "Self-signed certificate — not trusted by browsers"})

            cert_asset = self._register_asset(
                name=f"cert:{asset_name}",
                asset_type=AssetType.CERTIFICATE.value,
                details={**cert, "issues": issues},
            )
            findings.append(cert_asset)

        scan_record = {
            "scan_id": scan_id,
            "scan_type": "surface_scan",
            "timestamp": datetime.now().isoformat(),
            "port_scans": len(port_scan_results),
            "http_responses": len(http_responses),
            "certificates": len(certificates),
            "findings_count": len(findings),
        }
        self.scan_history.append(scan_record)

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "scan_id": scan_id,
                "findings": findings,
                "total_findings": len(findings),
                "high_risk_ports": [f for f in findings if isinstance(f, dict) and f.get("type") == "high_risk_port"],
                "total_inventory": len(self.assets),
            },
        )

    # =========================================================================
    # Assess Exposure
    # =========================================================================

    async def _assess_exposure(self, params: Dict[str, Any]) -> SkillResult:
        """Calculate exposure scores for all discovered assets."""
        asset_filter_type = params.get("asset_type")

        assets_to_assess = list(self.assets.values())
        if asset_filter_type:
            assets_to_assess = [a for a in assets_to_assess if a.get("asset_type") == asset_filter_type]

        if not assets_to_assess:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["No assets to assess. Run discover_assets or scan_surface first."],
            )

        scored_assets = []
        total_exposure = 0

        for asset in assets_to_assess:
            score = self._calculate_exposure_score(asset)
            asset["exposure_score"] = score
            asset["exposure_level"] = self._score_to_level(score)
            scored_assets.append(asset)
            total_exposure += score

        scored_assets.sort(key=lambda a: a.get("exposure_score", 0), reverse=True)

        avg_exposure = total_exposure / len(scored_assets) if scored_assets else 0

        exposure_distribution = {}
        for level in ["critical", "high", "medium", "low", "minimal"]:
            exposure_distribution[level] = sum(
                1 for a in scored_assets if a.get("exposure_level") == level
            )

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "scored_assets": scored_assets,
                "total_assets": len(scored_assets),
                "average_exposure_score": round(avg_exposure, 1),
                "max_exposure_score": scored_assets[0]["exposure_score"] if scored_assets else 0,
                "exposure_distribution": exposure_distribution,
                "top_exposures": scored_assets[:10],
                "critical_exposures": [a for a in scored_assets if a.get("exposure_level") == "critical"],
            },
            warnings=[
                f"{exposure_distribution.get('critical', 0)} assets at critical exposure level"
            ] if exposure_distribution.get("critical", 0) > 0 else [],
        )

    # =========================================================================
    # Track Changes
    # =========================================================================

    async def _track_changes(self, params: Dict[str, Any]) -> SkillResult:
        """Detect changes between current and previous asset inventory snapshots."""
        previous_snapshot = params.get("previous_snapshot", {})  # {asset_id: asset_data}
        current_snapshot = params.get("current_snapshot")  # optional, defaults to current assets

        if not previous_snapshot:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["'previous_snapshot' required — dict of asset_id -> asset data from prior scan"],
            )

        current = current_snapshot or self.assets
        changes = []

        # Find new assets
        for asset_id, asset_data in current.items():
            if asset_id not in previous_snapshot:
                changes.append({
                    "change_id": f"CHG-{uuid.uuid4().hex[:8]}",
                    "change_type": ChangeType.NEW_ASSET.value,
                    "asset_id": asset_id,
                    "asset_name": asset_data.get("name", ""),
                    "asset_type": asset_data.get("asset_type", ""),
                    "details": asset_data,
                    "risk_implication": "New asset discovered — review for unauthorized services",
                    "detected_at": datetime.now().isoformat(),
                })

        # Find removed assets
        for asset_id, asset_data in previous_snapshot.items():
            if asset_id not in current:
                changes.append({
                    "change_id": f"CHG-{uuid.uuid4().hex[:8]}",
                    "change_type": ChangeType.REMOVED_ASSET.value,
                    "asset_id": asset_id,
                    "asset_name": asset_data.get("name", ""),
                    "asset_type": asset_data.get("asset_type", ""),
                    "details": asset_data,
                    "risk_implication": "Asset no longer detected — verify intentional decommission",
                    "detected_at": datetime.now().isoformat(),
                })

        # Find modified assets
        for asset_id in set(current.keys()) & set(previous_snapshot.keys()):
            curr = current[asset_id]
            prev = previous_snapshot[asset_id]
            curr_details = curr.get("details", {})
            prev_details = prev.get("details", {})

            # Check for port changes
            if curr.get("asset_type") == AssetType.PORT_SERVICE.value:
                if curr_details.get("state") != prev_details.get("state"):
                    change_type = ChangeType.PORT_OPENED.value if curr_details.get("state") == "open" else ChangeType.PORT_CLOSED.value
                    changes.append({
                        "change_id": f"CHG-{uuid.uuid4().hex[:8]}",
                        "change_type": change_type,
                        "asset_id": asset_id,
                        "asset_name": curr.get("name", ""),
                        "previous_state": prev_details.get("state"),
                        "current_state": curr_details.get("state"),
                        "risk_implication": "Port state changed — review firewall rules" if change_type == ChangeType.PORT_OPENED.value else "Port closed — verify service availability",
                        "detected_at": datetime.now().isoformat(),
                    })

            # Check for service version changes
            if curr_details.get("version") and curr_details.get("version") != prev_details.get("version"):
                changes.append({
                    "change_id": f"CHG-{uuid.uuid4().hex[:8]}",
                    "change_type": ChangeType.SERVICE_CHANGED.value,
                    "asset_id": asset_id,
                    "asset_name": curr.get("name", ""),
                    "previous_version": prev_details.get("version"),
                    "current_version": curr_details.get("version"),
                    "risk_implication": "Service version changed — check for known vulnerabilities in new version",
                    "detected_at": datetime.now().isoformat(),
                })

            # Check exposure score changes
            curr_score = curr.get("exposure_score", 0)
            prev_score = prev.get("exposure_score", 0)
            if abs(curr_score - prev_score) >= 10:
                changes.append({
                    "change_id": f"CHG-{uuid.uuid4().hex[:8]}",
                    "change_type": ChangeType.EXPOSURE_CHANGED.value,
                    "asset_id": asset_id,
                    "asset_name": curr.get("name", ""),
                    "previous_score": prev_score,
                    "current_score": curr_score,
                    "delta": curr_score - prev_score,
                    "risk_implication": "Exposure increased" if curr_score > prev_score else "Exposure decreased",
                    "detected_at": datetime.now().isoformat(),
                })

        self.changes.extend(changes)

        # Generate intelligence packet for significant changes
        packets = []
        new_assets = [c for c in changes if c["change_type"] == ChangeType.NEW_ASSET.value]
        if new_assets:
            packets.append(IntelligencePacket(
                packet_id=f"PKT-ASM-{uuid.uuid4().hex[:8]}",
                source_agent=self.agent_id,
                target_agents=["all"],
                intelligence_type=IntelligenceType.INFRASTRUCTURE,
                priority=Priority.HIGH,
                confidence=85.0,
                timestamp=datetime.now(),
                data={
                    "change_type": "new_assets_detected",
                    "count": len(new_assets),
                    "assets": [c.get("asset_name") for c in new_assets],
                    "message": f"{len(new_assets)} new assets discovered in attack surface scan",
                },
                correlation_keys=["attack_surface", "asset_discovery"],
            ))

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "changes": changes,
                "total_changes": len(changes),
                "change_breakdown": {
                    ct.value: sum(1 for c in changes if c["change_type"] == ct.value)
                    for ct in ChangeType
                },
                "new_assets": len([c for c in changes if c["change_type"] == ChangeType.NEW_ASSET.value]),
                "removed_assets": len([c for c in changes if c["change_type"] == ChangeType.REMOVED_ASSET.value]),
            },
            intelligence_packets=packets,
        )

    # =========================================================================
    # Prioritize Risks
    # =========================================================================

    async def _prioritize_risks(self, params: Dict[str, Any]) -> SkillResult:
        """Prioritize attack surface risks by exposure score, business context, and threat data."""
        business_critical_assets = params.get("business_critical_assets", [])  # asset names
        known_exploited = params.get("known_exploited_services", [])  # service names with active exploits

        if not self.assets:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["No assets in inventory. Run discover_assets first."],
            )

        risk_items = []
        for asset_id, asset in self.assets.items():
            base_score = self._calculate_exposure_score(asset)

            # Business criticality multiplier
            multiplier = 1.0
            if asset.get("name") in business_critical_assets:
                multiplier = 1.5

            # Known exploited service boost
            details = asset.get("details", {})
            service = details.get("service", "")
            if service.lower() in [s.lower() for s in known_exploited]:
                multiplier *= 2.0

            final_score = round(base_score * multiplier, 1)

            risk_items.append({
                "asset_id": asset_id,
                "asset_name": asset.get("name", ""),
                "asset_type": asset.get("asset_type", ""),
                "base_exposure_score": base_score,
                "business_critical": asset.get("name") in business_critical_assets,
                "known_exploited": service.lower() in [s.lower() for s in known_exploited],
                "priority_score": final_score,
                "priority_level": self._score_to_level(final_score),
                "recommended_action": self._recommend_action(asset, final_score),
            })

        risk_items.sort(key=lambda r: r["priority_score"], reverse=True)

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "prioritized_risks": risk_items,
                "total_risks": len(risk_items),
                "top_10_risks": risk_items[:10],
                "priority_distribution": {
                    level: sum(1 for r in risk_items if r["priority_level"] == level)
                    for level in ["critical", "high", "medium", "low", "minimal"]
                },
                "immediate_actions": [
                    r["recommended_action"] for r in risk_items[:5] if r["priority_level"] in ("critical", "high")
                ],
            },
        )

    # =========================================================================
    # Generate Report
    # =========================================================================

    async def _generate_report(self, params: Dict[str, Any]) -> SkillResult:
        """Generate a comprehensive attack surface report."""
        include_details = params.get("include_details", True)

        type_breakdown = {}
        for asset in self.assets.values():
            at = asset.get("asset_type", "unknown")
            type_breakdown[at] = type_breakdown.get(at, 0) + 1

        exposure_levels = {}
        total_exposure = 0
        for asset in self.assets.values():
            score = asset.get("exposure_score", self._calculate_exposure_score(asset))
            level = asset.get("exposure_level", self._score_to_level(score))
            exposure_levels[level] = exposure_levels.get(level, 0) + 1
            total_exposure += score

        avg_exposure = round(total_exposure / len(self.assets), 1) if self.assets else 0

        # Identify top technologies
        tech_counts: Dict[str, int] = {}
        for asset in self.assets.values():
            for tech in asset.get("details", {}).get("technologies", []):
                tech_counts[tech] = tech_counts.get(tech, 0) + 1

        report = {
            "report_id": f"RPT-{uuid.uuid4().hex[:8]}",
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "total_assets": len(self.assets),
                "asset_type_breakdown": type_breakdown,
                "exposure_distribution": exposure_levels,
                "average_exposure_score": avg_exposure,
                "scans_performed": len(self.scan_history),
                "changes_detected": len(self.changes),
            },
            "technology_landscape": sorted(tech_counts.items(), key=lambda x: x[1], reverse=True)[:20],
            "critical_findings": [
                a for a in self.assets.values()
                if a.get("exposure_level") == "critical" or self._score_to_level(a.get("exposure_score", 0)) == "critical"
            ],
            "recent_changes": self.changes[-20:] if self.changes else [],
            "recommendations": self._generate_recommendations(),
        }

        if include_details:
            report["all_assets"] = list(self.assets.values())
            report["scan_history"] = self.scan_history

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={"report": report},
        )

    # =========================================================================
    # Internal Helpers
    # =========================================================================

    def _register_asset(self, name: str, asset_type: str, details: Dict[str, Any]) -> Dict[str, Any]:
        """Register or update an asset in the inventory."""
        asset_id = hashlib.sha256(f"{asset_type}:{name}".encode()).hexdigest()[:16]

        asset = {
            "asset_id": asset_id,
            "name": name,
            "asset_type": asset_type,
            "details": details,
            "first_seen": self.assets.get(asset_id, {}).get("first_seen", datetime.now().isoformat()),
            "last_seen": datetime.now().isoformat(),
            "exposure_score": 0,
            "exposure_level": "minimal",
        }

        self.assets[asset_id] = asset
        return asset

    def _enumerate_subdomains(self, domain: str) -> List[Dict[str, Any]]:
        """Generate potential subdomains for a given domain."""
        subdomains = []
        for prefix in COMMON_SUBDOMAINS:
            subdomain_name = f"{prefix}.{domain}"
            asset = self._register_asset(
                name=subdomain_name,
                asset_type=AssetType.SUBDOMAIN.value,
                details={
                    "parent_domain": domain,
                    "prefix": prefix,
                    "source": "enumeration",
                    "status": "potential",
                },
            )
            subdomains.append(asset)
        return subdomains

    def _calculate_exposure_score(self, asset: Dict[str, Any]) -> float:
        """Calculate an exposure score (0-100) for an asset."""
        score = 0.0
        asset_type = asset.get("asset_type", "")
        details = asset.get("details", {})

        # Base score by asset type
        type_base_scores = {
            AssetType.PORT_SERVICE.value: 30,
            AssetType.WEB_APPLICATION.value: 20,
            AssetType.CLOUD_RESOURCE.value: 25,
            AssetType.CERTIFICATE.value: 10,
            AssetType.DOMAIN.value: 5,
            AssetType.SUBDOMAIN.value: 5,
            AssetType.IP_ADDRESS.value: 10,
            AssetType.API_ENDPOINT.value: 25,
            AssetType.DNS_RECORD.value: 5,
        }
        score += type_base_scores.get(asset_type, 10)

        # Port risk scoring
        if asset_type == AssetType.PORT_SERVICE.value:
            port_risk = details.get("risk_score", 3)
            score += port_risk * 5  # 0-50 additional points

        # Cloud resource public exposure
        if asset_type == AssetType.CLOUD_RESOURCE.value:
            if details.get("public", False):
                score += 30

        # Certificate issues
        if asset_type == AssetType.CERTIFICATE.value:
            for issue in details.get("issues", []):
                if issue.get("severity") == "critical":
                    score += 40
                elif issue.get("severity") == "high":
                    score += 25
                elif issue.get("severity") == "medium":
                    score += 10

        # Technology risk modifier
        for tech in details.get("technologies", []):
            tech_info = TECHNOLOGY_SIGNATURES.get(tech.lower(), {})
            score += tech_info.get("risk_modifier", 0) * 3

        # Missing security headers penalty
        sec_headers = details.get("security_headers", {})
        missing = [h for h, v in sec_headers.items() if not v.get("present", False)]
        score += len(missing) * 2

        return min(100.0, round(score, 1))

    def _score_to_level(self, score: float) -> str:
        """Convert numeric score to exposure level."""
        if score >= 80:
            return "critical"
        elif score >= 60:
            return "high"
        elif score >= 40:
            return "medium"
        elif score >= 20:
            return "low"
        return "minimal"

    def _check_security_headers(self, headers: Dict[str, str]) -> Dict[str, Dict[str, Any]]:
        """Check for presence of important security headers."""
        required_headers = {
            "Strict-Transport-Security": {"alias": "HSTS", "importance": "high"},
            "Content-Security-Policy": {"alias": "CSP", "importance": "high"},
            "X-Content-Type-Options": {"alias": "XCTO", "importance": "medium"},
            "X-Frame-Options": {"alias": "XFO", "importance": "medium"},
            "X-XSS-Protection": {"alias": "XXP", "importance": "low"},
            "Referrer-Policy": {"alias": "RP", "importance": "medium"},
            "Permissions-Policy": {"alias": "PP", "importance": "medium"},
        }

        results = {}
        normalized_headers = {k.lower(): v for k, v in headers.items()}

        for header, meta in required_headers.items():
            present = header.lower() in normalized_headers
            results[header] = {
                "present": present,
                "value": normalized_headers.get(header.lower(), ""),
                "importance": meta["importance"],
            }

        return results

    def _recommend_action(self, asset: Dict[str, Any], score: float) -> str:
        """Generate a recommended action for a risky asset."""
        asset_type = asset.get("asset_type", "")
        details = asset.get("details", {})

        if score >= 80:
            if asset_type == AssetType.PORT_SERVICE.value:
                return f"CRITICAL: Close or restrict port {details.get('port')} ({details.get('service')}) immediately"
            if asset_type == AssetType.CLOUD_RESOURCE.value and details.get("public"):
                return f"CRITICAL: Remove public access from {asset.get('name')}"
            return f"CRITICAL: Immediate review and remediation required for {asset.get('name')}"
        elif score >= 60:
            return f"HIGH: Schedule remediation for {asset.get('name')} within 7 days"
        elif score >= 40:
            return f"MEDIUM: Plan remediation for {asset.get('name')} within 30 days"
        return f"LOW: Monitor {asset.get('name')} during regular reviews"

    def _generate_recommendations(self) -> List[str]:
        """Generate strategic attack surface recommendations."""
        recs = []
        assets = list(self.assets.values())

        critical_count = sum(
            1 for a in assets
            if self._score_to_level(a.get("exposure_score", self._calculate_exposure_score(a))) == "critical"
        )
        if critical_count > 0:
            recs.append(f"IMMEDIATE: {critical_count} assets at critical exposure — remediate before attackers discover them.")

        port_assets = [a for a in assets if a.get("asset_type") == AssetType.PORT_SERVICE.value]
        high_risk_ports = [a for a in port_assets if a.get("details", {}).get("risk_score", 0) >= 8]
        if high_risk_ports:
            recs.append(f"Close or firewall-restrict {len(high_risk_ports)} high-risk open ports (databases, RDP, SMB, etc.).")

        cloud_public = [a for a in assets if a.get("asset_type") == AssetType.CLOUD_RESOURCE.value and a.get("details", {}).get("public")]
        if cloud_public:
            recs.append(f"Review {len(cloud_public)} publicly accessible cloud resources for necessity and proper access controls.")

        recs.extend([
            "Implement continuous attack surface monitoring with automated alerting on changes.",
            "Establish an asset inventory baseline and track drift weekly.",
            "Deploy certificate monitoring to prevent expiry-related outages and security gaps.",
            "Consolidate technology stack where possible to reduce patch surface.",
        ])

        return recs
