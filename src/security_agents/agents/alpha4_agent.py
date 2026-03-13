#!/usr/bin/env python3
"""
Alpha-4 Threat Intelligence Agent — unified adapter.
Wraps the existing AdvancedThreatIntelligence engine behind BaseSecurityAgent.
"""

from typing import Dict, List, Any, Optional
from datetime import datetime
import uuid

from security_agents.core.base_agent import BaseSecurityAgent
from security_agents.core.agent_registry import register_agent
from security_agents.core.models import (
    AgentType, IntelligenceType, Priority, SecurityTask,
    IntelligencePacket, ThreatCampaign,
)
from security_agents.agents.engines.tiger_team_alpha_4 import AdvancedThreatIntelligence


@register_agent
class Alpha4ThreatIntelAgent(BaseSecurityAgent):
    """Threat intelligence agent — OSINT, IOC analysis, campaign attribution."""

    AGENT_ID = "alpha_4_threat_intel"
    AGENT_TYPE = AgentType.ALPHA_4
    DISPLAY_NAME = "Alpha-4 Threat Intelligence"
    CAPABILITIES = [
        "threat_campaigns",
        "actor_profiling",
        "ioc_enrichment",
        "campaign_attribution",
        "threat_hunting_queries",
    ]
    SUBSCRIPTIONS = [
        IntelligenceType.VULNERABILITY,
        IntelligenceType.INFRASTRUCTURE,
        IntelligenceType.CORRELATION,
        IntelligenceType.PHISHING,
    ]

    async def _setup(self):
        """Initialize the underlying threat intel engine."""
        self._engine = AdvancedThreatIntelligence()

    async def process_task(self, task: SecurityTask) -> Dict[str, Any]:
        """Route tasks to the appropriate threat intel capability."""
        task_type = task.task_type
        params = task.parameters

        if task_type == "analyze_campaign":
            iocs = params.get("iocs", [])
            context = params.get("context", "")
            campaign = await self._engine.analyze_threat_campaign(iocs, context)
            if campaign:
                # Emit intelligence packet for fusion
                packet = self.create_intelligence_packet(
                    intelligence_type=IntelligenceType.THREAT_CAMPAIGN,
                    priority=task.priority,
                    confidence=campaign.confidence,
                    data={
                        "campaign_id": campaign.campaign_id,
                        "name": campaign.name,
                        "threat_actor": campaign.threat_actor,
                        "ttps": campaign.ttps,
                        "risk_score": campaign.risk_score,
                    },
                    correlation_keys=campaign.iocs[:20],
                )
                return {
                    "campaign": {
                        "campaign_id": campaign.campaign_id,
                        "name": campaign.name,
                        "threat_actor": campaign.threat_actor,
                        "confidence": campaign.confidence,
                        "risk_score": campaign.risk_score,
                        "ttps": campaign.ttps,
                        "ioc_count": len(campaign.iocs),
                    },
                    "intelligence_packets": [packet.to_dict()],
                }
            return {"campaign": None, "message": "No campaign identified from provided IOCs"}

        elif task_type == "enrich_iocs":
            iocs = params.get("iocs", [])
            results = []
            for ioc in iocs:
                cluster = await self._engine.cluster_iocs_by_campaign([ioc])
                results.append({"ioc": ioc, "clusters": len(cluster) if cluster else 0})
            return {"enrichment_results": results}

        elif task_type == "hunt_threats":
            context = params.get("context", "")
            iocs = params.get("iocs", [])
            campaign = await self._engine.analyze_threat_campaign(iocs, context)
            return {
                "hunting_results": {
                    "campaign_found": campaign is not None,
                    "campaign_name": campaign.name if campaign else None,
                },
            }

        else:
            raise ValueError(
                f"Unknown task type '{task_type}' for {self.AGENT_ID}. "
                f"Supported: analyze_campaign, enrich_iocs, hunt_threats"
            )

    async def on_intelligence(self, packet: IntelligencePacket):
        """Correlate incoming intel with known campaigns."""
        if packet.intelligence_type == IntelligenceType.VULNERABILITY:
            self.logger.info(
                f"Correlating vulnerability intel with {len(self._engine.campaigns)} known campaigns"
            )
        elif packet.intelligence_type == IntelligenceType.PHISHING:
            self.logger.info("Received phishing intelligence — checking for campaign links")
