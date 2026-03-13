#!/usr/bin/env python3
"""
Multi-Source IOC Enrichment Skill — indicator of compromise enrichment and correlation.

Primary owner: Alpha-4 (Threat Intelligence)
Also usable by: Gamma (Blue Team)
Wraps: osint/threat_intel_enrichment.py

Capabilities:
  - Single IOC enrichment across VirusTotal, Shodan, DNS, WHOIS
  - Bulk IOC enrichment with rate-limit-aware batching
  - Reputation scoring with weighted multi-source aggregation
  - Cross-IOC correlation for campaign identification
  - STIX 2.1 bundle export
"""

import hashlib
import re
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional
from collections import defaultdict

from security_agents.core.models import (
    SkillResult, IntelligencePacket, IntelligenceType, Priority,
    EnrichedIOC, IOCType,
)
from security_agents.skills.base_skill import BaseSecuritySkill

class IOCEnrichmentSkill(BaseSecuritySkill):
    """Multi-source IOC enrichment, correlation, and STIX export."""

    SKILL_NAME = "ioc_enrichment"
    DESCRIPTION = (
        "Multi-source IOC enrichment via VirusTotal, Shodan, DNS, and WHOIS "
        "with reputation scoring, cross-IOC correlation, and STIX 2.1 export"
    )
    VERSION = "1.0.0"
    COMPATIBLE_AGENTS = ["alpha_4_threat_intel", "gamma_blue_team"]
    REQUIRED_INTEGRATIONS = []  # Gracefully degrades when API keys are absent

    # IOC type detection patterns
    IP_PATTERN = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}

    # Source reliability weights for reputation aggregation
    SOURCE_WEIGHTS = {
        "virustotal": 0.40,
        "shodan": 0.25,
        "dns": 0.15,
        "whois": 0.10,
        "internal": 0.10,
    }

    # -------------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------------

    async def _setup(self):
        """Initialize caches and tracking state."""
        self.enrichment_cache: Dict[str, Dict[str, Any]] = {}
        self.cache_ttl = timedelta(hours=6)
        self.correlation_store: Dict[str, List[str]] = defaultdict(list)
        self.enrichment_history: List[Dict[str, Any]] = []

    # -------------------------------------------------------------------------
    # Action dispatch
    # -------------------------------------------------------------------------

    async def _execute(self, parameters: Dict[str, Any]) -> SkillResult:
        """
        Dispatch to the appropriate action.

        Supported actions:
          enrich_ioc     -- enrich a single IOC
          bulk_enrich    -- enrich multiple IOCs with batching
          get_reputation -- quick reputation lookup (cache-preferred)
          correlate_iocs -- find correlations across enriched IOCs
          export_stix    -- export enrichment data as STIX 2.1 bundle
        """
        action = parameters.get("action", "enrich_ioc")
        dispatch = {
            "enrich_ioc": self._enrich_ioc,
            "bulk_enrich": self._bulk_enrich,
            "get_reputation": self._get_reputation,
            "correlate_iocs": self._correlate_iocs,
            "export_stix": self._export_stix,
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

    # =========================================================================
    # enrich_ioc
    # =========================================================================

    async def _enrich_ioc(self, params: Dict[str, Any]) -> SkillResult:
        """Enrich a single IOC across all available sources."""
        indicator = params.get("indicator", "")
        indicator_type = params.get("indicator_type") or self._detect_type(indicator)

        if not indicator:
            return SkillResult(
                success=False,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                errors=["'indicator' parameter is required"],
            )

        # Check cache
        cache_key = f"{indicator_type}:{indicator}"
        cached = self._get_cached(cache_key)
        if cached is not None:
            cached["from_cache"] = True
            return SkillResult(
                success=True,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                data=cached,
            )

        # Gather source results
        source_results: Dict[str, Dict[str, Any]] = {}
        reputation_scores: List[float] = []
        threat_types: set = set()
        campaigns: set = set()

        # VirusTotal enrichment
        vt_result = self._enrich_virustotal(indicator, indicator_type)
        if vt_result:
            source_results["virustotal"] = vt_result
            reputation_scores.append(vt_result["reputation_score"])
            threat_types.update(vt_result.get("threat_types", []))

        # Shodan enrichment (IP/domain only)
        if indicator_type in ("ip", "domain"):
            shodan_result = self._enrich_shodan(indicator, indicator_type)
            if shodan_result:
                source_results["shodan"] = shodan_result
                reputation_scores.append(shodan_result["reputation_score"])
                threat_types.update(shodan_result.get("threat_types", []))

        # DNS enrichment (domain/url only)
        if indicator_type in ("domain", "url"):
            dns_result = self._enrich_dns(indicator, indicator_type)
            if dns_result:
                source_results["dns"] = dns_result
                reputation_scores.append(dns_result["reputation_score"])

        # WHOIS enrichment (IP/domain only)
        if indicator_type in ("ip", "domain"):
            whois_result = self._enrich_whois(indicator, indicator_type)
            if whois_result:
                source_results["whois"] = whois_result

        # Aggregate scores
        sources_used = list(source_results.keys())
        reputation = self._weighted_reputation(source_results)
        confidence = self._calculate_confidence(sources_used)
        classification = self._classify_threat(reputation, threat_types)

        # Build enriched IOC model
        ioc_type_map = {
            "ip": IOCType.IP_ADDRESS,
            "domain": IOCType.DOMAIN,
            "url": IOCType.URL,
            "hash": IOCType.HASH_SHA256,
            "md5": IOCType.HASH_MD5,
            "sha1": IOCType.HASH_SHA1,
            "sha256": IOCType.HASH_SHA256,
        }
        enriched = EnrichedIOC(
            value=indicator,
            ioc_type=ioc_type_map.get(indicator_type, IOCType.DOMAIN),
            threat_types=list(threat_types),
            confidence_score=confidence,
            related_campaigns=list(campaigns),
            last_seen=datetime.now(timezone.utc),
        )

        # Cache result
        result_data = {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "reputation_score": round(reputation, 1),
            "confidence_score": round(confidence, 1),
            "classification": classification,
            "sources": sources_used,
            "source_details": source_results,
            "threat_types": list(threat_types),
            "enriched_ioc": {
                "value": enriched.value,
                "ioc_type": enriched.ioc_type.value,
                "threat_types": enriched.threat_types,
                "confidence_score": enriched.confidence_score,
            },
            "from_cache": False,
        }
        self._put_cache(cache_key, result_data)

        # Track for correlation
        self.correlation_store[indicator].extend(sources_used)
        self.enrichment_history.append({
            "indicator": indicator,
            "type": indicator_type,
            "reputation": reputation,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        # Emit intelligence for high-reputation (malicious) IOCs
        packets: List[IntelligencePacket] = []
        if reputation >= 60:
            packets.append(
                IntelligencePacket(
                    packet_id=f"PKT-IOC-{uuid.uuid4().hex[:8]}",
                    source_agent=self.agent_id,
                    target_agents=["all"],
                    intelligence_type=IntelligenceType.IOC_ENRICHMENT,
                    priority=Priority.HIGH if reputation >= 80 else Priority.MEDIUM,
                    confidence=confidence,
                    timestamp=datetime.now(timezone.utc),
                    data={
                        "indicator": indicator,
                        "indicator_type": indicator_type,
                        "reputation_score": reputation,
                        "classification": classification,
                        "threat_types": list(threat_types),
                    },
                    correlation_keys=[indicator],
                )
            )

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data=result_data,
            intelligence_packets=packets,
        )

    # =========================================================================
    # bulk_enrich
    # =========================================================================

    async def _bulk_enrich(self, params: Dict[str, Any]) -> SkillResult:
        """Enrich multiple IOCs with batched processing."""
        indicators = params.get("indicators", [])
        if not indicators:
            return SkillResult(
                success=False,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                errors=["'indicators' list is required and must not be empty"],
            )

        batch_size = params.get("batch_size", 10)
        results = []
        errors = []

        for i in range(0, len(indicators), batch_size):
            batch = indicators[i : i + batch_size]
            for ind in batch:
                try:
                    ioc_val = ind if isinstance(ind, str) else ind.get("indicator", "")
                    ioc_type = None if isinstance(ind, str) else ind.get("indicator_type")
                    result = await self._enrich_ioc({
                        "indicator": ioc_val,
                        "indicator_type": ioc_type,
                    })
                    if result.success:
                        results.append(result.data)
                    else:
                        errors.extend(result.errors)
                except Exception as e:
                    errors.append(f"Failed to enrich {ind}: {e}")

        # Summary statistics
        reputations = [r["reputation_score"] for r in results if "reputation_score" in r]
        malicious = [r for r in results if r.get("classification") == "malicious"]
        suspicious = [r for r in results if r.get("classification") == "suspicious"]

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "total_requested": len(indicators),
                "total_enriched": len(results),
                "total_errors": len(errors),
                "summary": {
                    "malicious_count": len(malicious),
                    "suspicious_count": len(suspicious),
                    "clean_count": len(results) - len(malicious) - len(suspicious),
                    "avg_reputation": round(sum(reputations) / len(reputations), 1) if reputations else 0,
                },
                "results": results,
                "errors": errors[:20],  # Cap error list
            },
        )

    # =========================================================================
    # get_reputation
    # =========================================================================

    async def _get_reputation(self, params: Dict[str, Any]) -> SkillResult:
        """Quick reputation lookup, preferring cache."""
        indicator = params.get("indicator", "")
        if not indicator:
            return SkillResult(
                success=False,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                errors=["'indicator' parameter is required"],
            )

        indicator_type = params.get("indicator_type") or self._detect_type(indicator)
        cache_key = f"{indicator_type}:{indicator}"
        cached = self._get_cached(cache_key)

        if cached:
            return SkillResult(
                success=True,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                data={
                    "indicator": indicator,
                    "indicator_type": indicator_type,
                    "reputation_score": cached.get("reputation_score", 0),
                    "classification": cached.get("classification", "unknown"),
                    "sources": cached.get("sources", []),
                    "from_cache": True,
                },
            )

        # Fall through to full enrichment
        return await self._enrich_ioc(params)

    # =========================================================================
    # correlate_iocs
    # =========================================================================

    async def _correlate_iocs(self, params: Dict[str, Any]) -> SkillResult:
        """Find correlations across previously enriched IOCs."""
        indicators = params.get("indicators", list(self.correlation_store.keys()))

        if not indicators:
            return SkillResult(
                success=False,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                errors=["No enriched IOCs available for correlation"],
            )

        # Group by shared threat types
        threat_groups: Dict[str, List[str]] = defaultdict(list)
        ioc_details: Dict[str, Dict[str, Any]] = {}

        for ind in indicators:
            ind_type = self._detect_type(ind)
            cache_key = f"{ind_type}:{ind}"
            cached = self._get_cached(cache_key)
            if cached:
                ioc_details[ind] = cached
                for tt in cached.get("threat_types", []):
                    threat_groups[tt].append(ind)

        # Identify clusters (IOCs sharing 2+ threat types)
        clusters: List[Dict[str, Any]] = []
        seen_pairs: set = set()
        for threat_type, iocs in threat_groups.items():
            if len(iocs) >= 2:
                pair_key = frozenset(iocs)
                if pair_key not in seen_pairs:
                    seen_pairs.add(pair_key)
                    cluster_reputation = max(
                        ioc_details.get(i, {}).get("reputation_score", 0) for i in iocs
                    )
                    clusters.append({
                        "cluster_id": f"CL-{uuid.uuid4().hex[:6]}",
                        "shared_threat_type": threat_type,
                        "indicators": iocs,
                        "max_reputation": cluster_reputation,
                        "potential_campaign": cluster_reputation >= 70,
                    })

        # Emit intelligence for potential campaigns
        packets: List[IntelligencePacket] = []
        campaign_clusters = [c for c in clusters if c["potential_campaign"]]
        if campaign_clusters:
            packets.append(
                IntelligencePacket(
                    packet_id=f"PKT-IOC-CORR-{uuid.uuid4().hex[:8]}",
                    source_agent=self.agent_id,
                    target_agents=["all"],
                    intelligence_type=IntelligenceType.CORRELATION,
                    priority=Priority.HIGH,
                    confidence=85.0,
                    timestamp=datetime.now(timezone.utc),
                    data={
                        "campaign_clusters": campaign_clusters,
                        "total_correlated_iocs": len(indicators),
                    },
                    correlation_keys=indicators[:20],
                )
            )

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "total_iocs_analyzed": len(indicators),
                "total_clusters": len(clusters),
                "potential_campaigns": len(campaign_clusters),
                "clusters": clusters,
                "threat_type_distribution": {k: len(v) for k, v in threat_groups.items()},
            },
            intelligence_packets=packets,
        )

    # =========================================================================
    # export_stix
    # =========================================================================

    async def _export_stix(self, params: Dict[str, Any]) -> SkillResult:
        """Export enriched IOCs as a STIX 2.1 bundle."""
        indicators = params.get("indicators", list(self.correlation_store.keys()))
        bundle_id = f"bundle--{uuid.uuid4()}"
        stix_objects: List[Dict[str, Any]] = []

        stix_type_map = {
            "ip": "ipv4-addr",
            "domain": "domain-name",
            "url": "url",
            "hash": "file",
            "md5": "file",
            "sha1": "file",
            "sha256": "file",
        }

        for ind in indicators:
            ind_type = self._detect_type(ind)
            cache_key = f"{ind_type}:{ind}"
            cached = self._get_cached(cache_key)
            reputation = cached.get("reputation_score", 0) if cached else 0
            threat_types = cached.get("threat_types", []) if cached else []

            # STIX indicator object
            pattern_type = stix_type_map.get(ind_type, "domain-name")
            if ind_type in ("md5", "sha1", "sha256", "hash"):
                hash_algo = "SHA-256" if len(ind) == 64 else ("SHA-1" if len(ind) == 40 else "MD5")
                pattern = f"[file:hashes.'{hash_algo}' = '{ind}']"
            elif ind_type == "ip":
                pattern = f"[ipv4-addr:value = '{ind}']"
            elif ind_type == "url":
                pattern = f"[url:value = '{ind}']"
            else:
                pattern = f"[domain-name:value = '{ind}']"

            stix_indicator = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": datetime.now(timezone.utc).isoformat(),
                "modified": datetime.now(timezone.utc).isoformat(),
                "name": f"IOC: {ind}",
                "description": f"Enriched indicator with reputation {reputation}/100",
                "indicator_types": threat_types[:5] if threat_types else ["unknown"],
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": datetime.now(timezone.utc).isoformat(),
                "confidence": min(int(reputation), 100),
            }
            stix_objects.append(stix_indicator)

        bundle = {
            "type": "bundle",
            "id": bundle_id,
            "objects": stix_objects,
        }

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "bundle_id": bundle_id,
                "total_objects": len(stix_objects),
                "stix_bundle": bundle,
            },
        )

    # =========================================================================
    # Internal helpers
    # =========================================================================

    def _detect_type(self, indicator: str) -> str:
        """Auto-detect IOC type."""
        if self.IP_PATTERN.match(indicator):
            return "ip"
        if indicator.startswith(("http://", "https://")):
            return "url"
        if len(indicator) in self.HASH_LENGTHS and all(
            c in "0123456789abcdefABCDEF" for c in indicator
        ):
            return self.HASH_LENGTHS[len(indicator)]
        return "domain"

    def _get_cached(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Return cached enrichment if fresh, else None."""
        entry = self.enrichment_cache.get(cache_key)
        if entry and datetime.now(timezone.utc) - entry["cached_at"] < self.cache_ttl:
            return entry["data"]
        return None

    def _put_cache(self, cache_key: str, data: Dict[str, Any]) -> None:
        self.enrichment_cache[cache_key] = {
            "data": data,
            "cached_at": datetime.now(timezone.utc),
        }

    # --- Source enrichment stubs (mirror osint/threat_intel_enrichment.py) ---
    # In production these call live APIs; the skill wraps the pattern and
    # returns structured data regardless of API availability.

    def _enrich_virustotal(self, indicator: str, ind_type: str) -> Optional[Dict[str, Any]]:
        """VirusTotal enrichment (structured stub for API integration)."""
        # In production: delegates to ThreatIntelEnrichment.enrich_with_virustotal
        return {
            "source": "virustotal",
            "reputation_score": 0.0,
            "threat_types": [],
            "analysis_stats": {"malicious": 0, "suspicious": 0, "undetected": 0, "harmless": 0},
            "detection_ratio": "0/0",
            "available": False,
            "note": "Connect VIRUSTOTAL_API_KEY for live enrichment",
        }

    def _enrich_shodan(self, indicator: str, ind_type: str) -> Optional[Dict[str, Any]]:
        """Shodan enrichment (structured stub for API integration)."""
        return {
            "source": "shodan",
            "reputation_score": 0.0,
            "threat_types": [],
            "open_ports": [],
            "services": [],
            "vulnerabilities": [],
            "available": False,
            "note": "Connect SHODAN_API_KEY for live enrichment",
        }

    def _enrich_dns(self, indicator: str, ind_type: str) -> Optional[Dict[str, Any]]:
        """DNS enrichment (structured stub)."""
        return {
            "source": "dns",
            "reputation_score": 0.0,
            "a_records": [],
            "mx_records": [],
            "txt_records": [],
            "available": True,
        }

    def _enrich_whois(self, indicator: str, ind_type: str) -> Optional[Dict[str, Any]]:
        """WHOIS enrichment (structured stub)."""
        return {
            "source": "whois",
            "creation_date": None,
            "expiration_date": None,
            "registrar": None,
            "available": True,
        }

    def _weighted_reputation(self, source_results: Dict[str, Dict[str, Any]]) -> float:
        """Compute weighted reputation across sources."""
        total_weight = 0.0
        weighted_sum = 0.0
        for source, data in source_results.items():
            score = data.get("reputation_score", 0)
            weight = self.SOURCE_WEIGHTS.get(source, 0.1)
            weighted_sum += score * weight
            total_weight += weight
        return (weighted_sum / total_weight) if total_weight > 0 else 0.0

    def _calculate_confidence(self, sources: List[str]) -> float:
        """Calculate confidence based on number and quality of sources."""
        if not sources:
            return 0.0
        base = min(len(sources) * 25, 75)
        if "virustotal" in sources:
            base += 20
        if "shodan" in sources:
            base += 15
        return min(base, 100.0)

    def _classify_threat(self, reputation: float, threat_types: set) -> str:
        """Classify the IOC based on reputation and threat data."""
        if reputation >= 70:
            return "malicious"
        if reputation >= 40:
            return "suspicious"
        if reputation >= 15:
            return "potentially_unwanted"
        return "clean"
