#!/usr/bin/env python3
"""
Gamma Blue Team Agent — unified adapter.
Wraps the existing GammaBlueTeamAgent behind BaseSecurityAgent.
"""

from typing import Dict, List, Any, Optional

from security_agents.core.base_agent import BaseSecurityAgent
from security_agents.core.agent_registry import register_agent
from security_agents.core.models import (
    AgentType, IntelligenceType, Priority, SecurityTask,
    IntelligencePacket,
)

# Import the original agent module under a different name to avoid collision
from security_agents.agents.engines.gamma_blue_team_agent import GammaBlueTeamAgent as _OriginalGamma


@register_agent
class GammaBlueTeamAgent(BaseSecurityAgent):
    """Blue team agent — SOC operations, incident response, threat hunting."""

    AGENT_ID = "gamma_blue_team"
    AGENT_TYPE = AgentType.GAMMA
    DISPLAY_NAME = "Gamma Blue Team"
    CAPABILITIES = [
        "incident_response",
        "threat_hunting",
        "alert_triage",
        "containment",
        "threat_intel_enrichment",
        "phishing_analysis",
    ]
    SUBSCRIPTIONS = [
        IntelligenceType.THREAT_CAMPAIGN,
        IntelligenceType.IOC_ENRICHMENT,
        IntelligenceType.ACTOR_PROFILE,
        IntelligenceType.CORRELATION,
        IntelligenceType.PHISHING,
        IntelligenceType.IDENTITY_THREAT,
    ]

    async def _setup(self):
        config_path = self.config.get("config_path", "config/gamma_config.yaml")
        self._engine = _OriginalGamma(config_path=config_path)

    async def process_task(self, task: SecurityTask) -> Dict[str, Any]:
        task_type = task.task_type
        params = task.parameters

        if task_type == "process_alert":
            alert_data = params.get("alert_data", {})
            result = await self._engine.process_security_alert(alert_data)
            # Emit incident intelligence if case was created
            if result.get("case_created"):
                packet = self.create_intelligence_packet(
                    intelligence_type=IntelligenceType.INCIDENT,
                    priority=task.priority,
                    confidence=result.get("triage", {}).get("confidence", 70.0),
                    data={
                        "case_id": result.get("case", {}).get("case_id"),
                        "severity": result.get("alert", {}).get("severity"),
                        "containment_actions": result.get("containment_actions", []),
                    },
                    correlation_keys=result.get("alert", {}).get("iocs", [])[:20],
                )
                result["intelligence_packets"] = [packet.to_dict()]
            return result

        elif task_type == "triage_alert":
            alert_data = params.get("alert_data", {})
            alert = self._engine.parse_alert(alert_data)
            triage = await self._engine.automated_triage(alert)
            return {"triage_result": triage}

        elif task_type == "hunt_threats":
            # Use alert enrichment as a hunting mechanism
            alert_data = params.get("alert_data", {})
            alert = self._engine.parse_alert(alert_data)
            enrichment = await self._engine.enrich_with_threat_intel(alert)
            return {"hunting_results": enrichment}

        elif task_type == "analyze_phishing":
            # Delegate to phishing skill if registered
            if "phishing_analysis" in self.skills:
                result = await self.execute_skill("phishing_analysis", params)
                return result.data if result.success else {"error": result.errors}
            return {"error": "Phishing analysis skill not registered"}

        elif task_type == "containment":
            alert_data = params.get("alert_data", {})
            alert = self._engine.parse_alert(alert_data)
            triage = params.get("triage_result", {})
            actions = await self._engine.execute_containment_actions(alert, triage)
            return {"containment_actions": [a.value if hasattr(a, 'value') else str(a) for a in actions]}

        else:
            raise ValueError(
                f"Unknown task type '{task_type}' for {self.AGENT_ID}. "
                f"Supported: process_alert, triage_alert, hunt_threats, "
                f"analyze_phishing, containment"
            )

    async def on_intelligence(self, packet: IntelligencePacket):
        if packet.intelligence_type == IntelligenceType.THREAT_CAMPAIGN:
            self.logger.info("Received campaign intel — updating detection rules")
        elif packet.intelligence_type == IntelligenceType.PHISHING:
            self.logger.info("Received phishing intel — correlating with open cases")
        elif packet.intelligence_type == IntelligenceType.IDENTITY_THREAT:
            self.logger.info("Received identity threat — triggering account review")
