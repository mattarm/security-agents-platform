#!/usr/bin/env python3
"""
Alpha-4 Threat Intelligence Skills - Enhanced with CrowdStrike MCP
Advanced threat intelligence capabilities using CrowdStrike Falcon platform
"""

import asyncio
import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from framework.mcp_client import SecurityAgentsMCPIntegration, SecurityAgent, FQLQueryBuilder

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ThreatActorCategory(Enum):
    APT = "advanced_persistent_threat"
    CRIMINAL = "criminal_organization"
    HACKTIVIST = "hacktivist_group"
    NATION_STATE = "nation_state"
    UNKNOWN = "unknown"

class IOCType(Enum):
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1" 
    HASH_SHA256 = "hash_sha256"
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email_address"
    FILE_PATH = "file_path"

@dataclass
class ThreatActorProfile:
    """Enhanced threat actor profile from CrowdStrike intelligence"""
    name: str
    aliases: List[str]
    category: ThreatActorCategory
    target_sectors: List[str]
    target_countries: List[str]
    first_seen: Optional[datetime]
    last_activity: Optional[datetime]
    mitre_techniques: List[str]
    confidence_score: float
    intelligence_source: str = "crowdstrike"

@dataclass
class EnrichedIOC:
    """IOC enriched with CrowdStrike intelligence"""
    value: str
    ioc_type: IOCType
    threat_types: List[str]
    confidence_score: float
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    related_campaigns: List[str]
    related_actors: List[str]
    intelligence_reports: List[str]
    malware_families: List[str]

@dataclass
class ThreatCampaign:
    """Threat campaign analysis result"""
    campaign_id: str
    name: Optional[str]
    attributed_actors: List[str]
    target_sectors: List[str]
    start_date: Optional[datetime]
    end_date: Optional[datetime]
    techniques_used: List[str]
    iocs_identified: List[str]
    confidence_score: float
    intelligence_summary: str

class Alpha4ThreatIntelSkills:
    """Enhanced threat intelligence skills for Alpha-4 agent using CrowdStrike MCP"""
    
    def __init__(self):
        self.mcp_integration = SecurityAgentsMCPIntegration(SecurityAgent.ALPHA_4)
        self.query_builder = FQLQueryBuilder()
        self.session_active = False
        
    async def initialize(self) -> bool:
        """Initialize CrowdStrike MCP integration"""
        self.session_active = await self.mcp_integration.initialize()
        return self.session_active
    
    async def research_threat_actor(self, actor_name: str, include_related: bool = True) -> ThreatActorProfile:
        """
        Enhanced threat actor research using CrowdStrike intelligence
        
        Args:
            actor_name: Name or alias of threat actor
            include_related: Include related campaigns and indicators
            
        Returns:
            Comprehensive threat actor profile
        """
        if not self.session_active:
            raise RuntimeError("MCP integration not initialized")
        
        logger.info(f"Researching threat actor: {actor_name}")
        
        # Execute threat actor investigation workflow
        result = await self.mcp_integration.execute_workflow(
            "threat_actor_investigation",
            {
                "actor_name": actor_name,
                "include_related": include_related
            }
        )
        
        # Parse and structure the results
        profile = self._parse_threat_actor_result(result)
        
        # If we found the actor, get additional enrichment
        if profile and include_related:
            profile = await self._enrich_threat_actor_profile(profile, result)
        
        return profile
    
    async def analyze_ioc_intelligence(self, iocs: List[str]) -> List[EnrichedIOC]:
        """
        Analyze IOCs against CrowdStrike threat intelligence
        
        Args:
            iocs: List of indicators to analyze
            
        Returns:
            List of enriched IOCs with intelligence data
        """
        if not self.session_active:
            raise RuntimeError("MCP integration not initialized")
        
        logger.info(f"Analyzing {len(iocs)} IOCs against CrowdStrike intelligence")
        
        # Execute IOC enrichment workflow
        result = await self.mcp_integration.execute_workflow(
            "ioc_enrichment",
            {"iocs": iocs}
        )
        
        # Parse and structure the results
        enriched_iocs = []
        for ioc_result in result.get("enriched_iocs", []):
            enriched = self._parse_ioc_result(ioc_result)
            if enriched:
                enriched_iocs.append(enriched)
        
        return enriched_iocs
    
    async def investigate_campaign(self, 
                                  campaign_indicators: List[str] = None,
                                  timeframe: str = "30d",
                                  confidence_threshold: float = 0.7) -> ThreatCampaign:
        """
        Investigate threat campaign using indicators and timeline analysis
        
        Args:
            campaign_indicators: Known indicators associated with campaign
            timeframe: Time period to analyze (e.g., "30d", "7d", "24h")
            confidence_threshold: Minimum confidence score for correlations
            
        Returns:
            Threat campaign analysis result
        """
        if not self.session_active:
            raise RuntimeError("MCP integration not initialized")
        
        logger.info(f"Investigating threat campaign with {len(campaign_indicators or [])} indicators")
        
        # Execute campaign analysis workflow
        result = await self.mcp_integration.execute_workflow(
            "campaign_analysis",
            {
                "indicators": campaign_indicators or [],
                "timeframe": timeframe,
                "confidence_threshold": confidence_threshold
            }
        )
        
        # Parse and structure the results
        campaign = self._parse_campaign_result(result)
        
        return campaign
    
    async def generate_hunt_queries(self, 
                                   actor_name: str = None, 
                                   techniques: List[str] = None,
                                   iocs: List[str] = None) -> Dict[str, List[str]]:
        """
        Generate threat hunting queries based on intelligence
        
        Args:
            actor_name: Threat actor to hunt for
            techniques: MITRE ATT&CK techniques to hunt for  
            iocs: Indicators to hunt for
            
        Returns:
            Dictionary of hunting queries by platform/tool
        """
        hunt_queries = {
            "falcon_fql": [],
            "ngsiem_cql": [],
            "sigma_rules": [],
            "yara_rules": []
        }
        
        # Generate FQL queries for Falcon platform
        if actor_name:
            # Get actor intelligence first
            actor_profile = await self.research_threat_actor(actor_name)
            if actor_profile:
                # Generate queries based on actor TTPs
                for technique in actor_profile.mitre_techniques:
                    fql_query = self._generate_fql_hunt_query(technique, actor_name)
                    hunt_queries["falcon_fql"].append(fql_query)
        
        if techniques:
            for technique in techniques:
                fql_query = self._generate_fql_hunt_query(technique)
                hunt_queries["falcon_fql"].append(fql_query)
        
        if iocs:
            for ioc in iocs:
                fql_query = self._generate_ioc_hunt_query(ioc)
                hunt_queries["falcon_fql"].append(fql_query)
        
        # Generate NGSIEM CQL queries
        if actor_name or techniques:
            cql_queries = await self._generate_ngsiem_queries(actor_name, techniques)
            hunt_queries["ngsiem_cql"].extend(cql_queries)
        
        return hunt_queries
    
    async def attribution_analysis(self, 
                                  indicators: List[str],
                                  attack_patterns: List[str] = None) -> Dict[str, Any]:
        """
        Perform threat actor attribution analysis
        
        Args:
            indicators: IOCs observed in incident/campaign
            attack_patterns: Observed attack patterns or techniques
            
        Returns:
            Attribution analysis with confidence scores
        """
        attribution_result = {
            "attributed_actors": [],
            "confidence_scores": {},
            "supporting_evidence": {},
            "alternative_hypotheses": []
        }
        
        # Analyze each indicator for actor associations
        enriched_iocs = await self.analyze_ioc_intelligence(indicators)
        
        # Collect potential actors from IOC analysis
        potential_actors = {}
        for ioc in enriched_iocs:
            for actor in ioc.related_actors:
                if actor not in potential_actors:
                    potential_actors[actor] = []
                potential_actors[actor].append(ioc.value)
        
        # Score each potential actor
        for actor, supporting_iocs in potential_actors.items():
            # Get detailed actor profile
            actor_profile = await self.research_threat_actor(actor)
            
            if actor_profile:
                # Calculate confidence score based on multiple factors
                confidence_score = self._calculate_attribution_confidence(
                    actor_profile, 
                    supporting_iocs,
                    attack_patterns or []
                )
                
                if confidence_score > 0.3:  # Minimum threshold
                    attribution_result["attributed_actors"].append(actor)
                    attribution_result["confidence_scores"][actor] = confidence_score
                    attribution_result["supporting_evidence"][actor] = {
                        "matching_iocs": supporting_iocs,
                        "technique_overlap": self._calculate_technique_overlap(
                            actor_profile.mitre_techniques, 
                            attack_patterns or []
                        ),
                        "target_sector_match": True  # Would need target analysis
                    }
        
        # Sort by confidence score
        attribution_result["attributed_actors"].sort(
            key=lambda x: attribution_result["confidence_scores"][x], 
            reverse=True
        )
        
        return attribution_result
    
    async def intelligence_briefing(self, 
                                   timeframe: str = "7d",
                                   focus_areas: List[str] = None) -> Dict[str, Any]:
        """
        Generate intelligence briefing based on recent threats
        
        Args:
            timeframe: Period to analyze for briefing
            focus_areas: Specific areas to focus on (actors, sectors, techniques)
            
        Returns:
            Structured intelligence briefing
        """
        briefing = {
            "executive_summary": "",
            "key_threats": [],
            "emerging_campaigns": [],
            "ioc_highlights": [],
            "hunting_priorities": [],
            "recommendations": []
        }
        
        # Get recent threat intelligence reports
        reports_result = await self.mcp_integration.mcp_client.execute_tool(
            "falcon_search_reports",
            {"filter": f"created_date:>now-{timeframe}"}
        )
        
        if reports_result["success"] and reports_result["result"]:
            # Analyze recent reports for trends
            briefing = await self._analyze_reports_for_briefing(
                reports_result["result"], 
                focus_areas or []
            )
        
        # Get recent high-confidence detections for context
        detections_result = await self.mcp_integration.mcp_client.execute_tool(
            "falcon_search_detections",
            {"filter": f"confidence:>0.8 AND first_behavior:>now-{timeframe}"}
        )
        
        if detections_result["success"]:
            briefing["recent_detections"] = len(detections_result["result"])
        
        return briefing
    
    # Private helper methods
    def _parse_threat_actor_result(self, result: Dict[str, Any]) -> Optional[ThreatActorProfile]:
        """Parse threat actor investigation result into structured profile"""
        actor_search = result.get("actor_search", {})
        
        if not actor_search.get("success") or not actor_search.get("result"):
            return None
        
        actor_data = actor_search["result"][0]  # Take first result
        
        # Parse MITRE report for techniques
        mitre_techniques = []
        mitre_report = result.get("mitre_report", {})
        if mitre_report.get("success") and mitre_report.get("result"):
            mitre_data = mitre_report["result"]
            if isinstance(mitre_data, dict) and "techniques" in mitre_data:
                mitre_techniques = [t.get("technique_id", "") for t in mitre_data["techniques"]]
        
        return ThreatActorProfile(
            name=actor_data.get("name", ""),
            aliases=actor_data.get("known_as", []),
            category=ThreatActorCategory.APT,  # Would need parsing logic
            target_sectors=actor_data.get("target_industries", []),
            target_countries=actor_data.get("target_countries", []),
            first_seen=self._parse_date(actor_data.get("first_activity_date")),
            last_activity=self._parse_date(actor_data.get("last_activity_date")),
            mitre_techniques=mitre_techniques,
            confidence_score=0.9,  # Would calculate based on data quality
            intelligence_source="crowdstrike"
        )
    
    async def _enrich_threat_actor_profile(self, 
                                          profile: ThreatActorProfile, 
                                          base_result: Dict[str, Any]) -> ThreatActorProfile:
        """Enrich threat actor profile with additional intelligence"""
        # Add related indicators analysis
        indicators_result = base_result.get("related_indicators", {})
        if indicators_result.get("success") and indicators_result.get("result"):
            # Could extend profile with related IOCs, campaigns, etc.
            pass
        
        return profile
    
    def _parse_ioc_result(self, ioc_result: Dict[str, Any]) -> Optional[EnrichedIOC]:
        """Parse IOC enrichment result into structured format"""
        ioc_value = ioc_result.get("ioc", "")
        intel_data = ioc_result.get("crowdstrike_intel", {})
        
        if not intel_data.get("success") or not intel_data.get("result"):
            return None
        
        intel = intel_data["result"][0] if intel_data["result"] else {}
        
        return EnrichedIOC(
            value=ioc_value,
            ioc_type=self._detect_ioc_type(ioc_value),
            threat_types=intel.get("threat_types", []),
            confidence_score=intel.get("confidence", 0.5),
            first_seen=self._parse_date(intel.get("first_seen")),
            last_seen=self._parse_date(intel.get("last_seen")),
            related_campaigns=intel.get("kill_chains", []),
            related_actors=intel.get("actors", []),
            intelligence_reports=intel.get("reports", []),
            malware_families=intel.get("malware_families", [])
        )
    
    def _parse_campaign_result(self, result: Dict[str, Any]) -> ThreatCampaign:
        """Parse campaign analysis result into structured format"""
        detections = result.get("campaign_detections", {}).get("result", [])
        incidents = result.get("related_incidents", {}).get("result", [])
        
        # Generate campaign ID
        campaign_id = f"CAMP-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        
        # Extract techniques from detections
        techniques = []
        for detection in detections:
            behaviors = detection.get("behaviors", [])
            for behavior in behaviors:
                technique = behavior.get("technique")
                if technique and technique not in techniques:
                    techniques.append(technique)
        
        # Extract IOCs from detections
        iocs = []
        for detection in detections:
            behaviors = detection.get("behaviors", [])
            for behavior in behaviors:
                if "ioc" in behavior:
                    iocs.append(behavior["ioc"])
        
        return ThreatCampaign(
            campaign_id=campaign_id,
            name=f"Campaign {campaign_id}",
            attributed_actors=[],  # Would need actor analysis
            target_sectors=[],     # Would need sector analysis
            start_date=None,       # Would parse from earliest detection
            end_date=None,         # Would parse from latest detection  
            techniques_used=techniques,
            iocs_identified=list(set(iocs)),
            confidence_score=0.7,  # Would calculate based on data quality
            intelligence_summary=f"Campaign analysis identified {len(detections)} detections and {len(incidents)} incidents"
        )
    
    def _generate_fql_hunt_query(self, technique: str, actor: str = None) -> str:
        """Generate FQL hunt query for technique/actor"""
        base_query = f"behaviors.technique:'{technique}'"
        
        if actor:
            base_query += f" AND behaviors.threat_graph.actors:'{actor}'"
        
        # Add time constraint
        base_query += " AND first_behavior:>now-7d"
        
        return base_query
    
    def _generate_ioc_hunt_query(self, ioc: str) -> str:
        """Generate FQL hunt query for IOC"""
        return f"behaviors.ioc:'{ioc}' AND first_behavior:>now-7d"
    
    async def _generate_ngsiem_queries(self, actor: str, techniques: List[str]) -> List[str]:
        """Generate NGSIEM CQL queries for hunting"""
        queries = []
        
        if actor:
            # Generate CQL for actor hunting
            cql_query = f'threat_graph.actors="{actor}" | head 100'
            queries.append(cql_query)
        
        for technique in techniques:
            # Generate CQL for technique hunting
            cql_query = f'mitre_technique="{technique}" | head 100'
            queries.append(cql_query)
        
        return queries
    
    def _calculate_attribution_confidence(self, 
                                        actor_profile: ThreatActorProfile,
                                        supporting_iocs: List[str],
                                        attack_patterns: List[str]) -> float:
        """Calculate attribution confidence score"""
        confidence = 0.0
        
        # IOC match weight (40%)
        ioc_weight = min(len(supporting_iocs) * 0.1, 0.4)
        confidence += ioc_weight
        
        # Technique overlap weight (40%) 
        technique_overlap = self._calculate_technique_overlap(
            actor_profile.mitre_techniques,
            attack_patterns
        )
        confidence += technique_overlap * 0.4
        
        # Base confidence from actor profile (20%)
        confidence += actor_profile.confidence_score * 0.2
        
        return min(confidence, 1.0)
    
    def _calculate_technique_overlap(self, actor_techniques: List[str], observed_techniques: List[str]) -> float:
        """Calculate overlap percentage between actor and observed techniques"""
        if not actor_techniques or not observed_techniques:
            return 0.0
        
        overlap = set(actor_techniques) & set(observed_techniques)
        return len(overlap) / len(set(observed_techniques))
    
    async def _analyze_reports_for_briefing(self, reports: List[Dict], focus_areas: List[str]) -> Dict[str, Any]:
        """Analyze intelligence reports for briefing generation"""
        briefing = {
            "executive_summary": f"Analysis of {len(reports)} recent intelligence reports",
            "key_threats": [],
            "emerging_campaigns": [],
            "ioc_highlights": [],
            "hunting_priorities": [],
            "recommendations": []
        }
        
        # Extract key threats from reports
        for report in reports[:5]:  # Top 5 reports
            threat = {
                "title": report.get("name", ""),
                "description": report.get("description", ""),
                "confidence": report.get("confidence", 0.5),
                "date": report.get("created_date", "")
            }
            briefing["key_threats"].append(threat)
        
        # Generate recommendations
        briefing["recommendations"] = [
            "Monitor for indicators associated with recent campaigns",
            "Update detection rules based on new TTPs",
            "Conduct targeted threat hunting for high-confidence actors",
            "Review and update incident response procedures"
        ]
        
        return briefing
    
    def _detect_ioc_type(self, ioc: str) -> IOCType:
        """Detect IOC type from value"""
        import re
        
        if re.match(r'^[a-fA-F0-9]{32}$', ioc):
            return IOCType.HASH_MD5
        elif re.match(r'^[a-fA-F0-9]{40}$', ioc):
            return IOCType.HASH_SHA1
        elif re.match(r'^[a-fA-F0-9]{64}$', ioc):
            return IOCType.HASH_SHA256
        elif re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', ioc):
            return IOCType.IP_ADDRESS
        elif '@' in ioc:
            return IOCType.EMAIL
        elif '://' in ioc:
            return IOCType.URL
        elif '.' in ioc and not '/' in ioc:
            return IOCType.DOMAIN
        else:
            return IOCType.FILE_PATH
    
    def _parse_date(self, date_str: str) -> Optional[datetime]:
        """Parse date string to datetime object"""
        if not date_str:
            return None
        
        try:
            # Handle various date formats
            if 'T' in date_str:
                return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
            else:
                return datetime.strptime(date_str, '%Y-%m-%d')
        except:
            return None


# Example usage and testing
async def main():
    """Example usage of Alpha-4 enhanced threat intelligence skills"""
    
    # Initialize skills
    skills = Alpha4ThreatIntelSkills()
    
    if await skills.initialize():
        print("✅ Alpha-4 CrowdStrike MCP skills initialized")
        
        # Example 1: Research threat actor
        try:
            actor_profile = await skills.research_threat_actor("APT28")
            if actor_profile:
                print(f"📊 Threat Actor: {actor_profile.name}")
                print(f"   Aliases: {', '.join(actor_profile.aliases)}")
                print(f"   Techniques: {len(actor_profile.mitre_techniques)}")
                print(f"   Confidence: {actor_profile.confidence_score}")
        except Exception as e:
            print(f"❌ Threat actor research error: {e}")
        
        # Example 2: Analyze IOCs
        try:
            test_iocs = ["8.8.8.8", "malware.example.com"]
            enriched_iocs = await skills.analyze_ioc_intelligence(test_iocs)
            print(f"📊 Analyzed {len(enriched_iocs)} IOCs with CrowdStrike intel")
        except Exception as e:
            print(f"❌ IOC analysis error: {e}")
        
        # Example 3: Generate hunt queries
        try:
            hunt_queries = await skills.generate_hunt_queries(
                actor_name="APT28",
                techniques=["T1059.001"]
            )
            print(f"📊 Generated hunt queries:")
            for platform, queries in hunt_queries.items():
                print(f"   {platform}: {len(queries)} queries")
        except Exception as e:
            print(f"❌ Hunt query generation error: {e}")
    else:
        print("❌ Failed to initialize Alpha-4 CrowdStrike MCP skills")


if __name__ == "__main__":
    asyncio.run(main())