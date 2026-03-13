#!/usr/bin/env python3
"""
Zeta GRC Agent — unified adapter.
Wraps the ZetaGRCEngine behind BaseSecurityAgent for GRC operations.
"""

from typing import Dict, List, Any, Optional

from security_agents.core.base_agent import BaseSecurityAgent
from security_agents.core.agent_registry import register_agent
from security_agents.core.models import (
    AgentType, IntelligenceType, Priority, SecurityTask,
    IntelligencePacket,
)
from security_agents.agents.engines.zeta_grc_engine import ZetaGRCEngine


@register_agent
class ZetaGRCAgent(BaseSecurityAgent):
    """GRC agent — compliance assessment, control mapping, risk management, audit."""

    AGENT_ID = "zeta_grc"
    AGENT_TYPE = AgentType.ZETA
    DISPLAY_NAME = "Zeta GRC"
    CAPABILITIES = [
        "compliance_assessment",
        "control_mapping",
        "evidence_collection",
        "gap_analysis",
        "risk_register",
        "mitre_coverage",
        "ai_governance",
        "audit_readiness",
        "grc_reporting",
    ]
    SUBSCRIPTIONS = [
        IntelligenceType.VULNERABILITY,
        IntelligenceType.COMPLIANCE,
        IntelligenceType.INCIDENT,
        IntelligenceType.CORRELATION,
        IntelligenceType.METRICS,
    ]

    async def _setup(self):
        """Initialize the GRC engine."""
        self._engine = ZetaGRCEngine()

    async def process_task(self, task: SecurityTask) -> Dict[str, Any]:
        """Route tasks to the appropriate GRC capability."""
        task_type = task.task_type
        params = task.parameters

        try:
            if task_type == "assess_compliance":
                framework_id = params.get("framework_id", "nist_csf_2_0")
                scope = params.get("scope", "full")
                team_id = params.get("team_id", "default")
                posture = await self._engine.assess_compliance(framework_id, scope, team_id)

                # Emit compliance intelligence
                packet = self.create_intelligence_packet(
                    intelligence_type=IntelligenceType.COMPLIANCE,
                    priority=Priority.MEDIUM,
                    confidence=posture.overall_score,
                    data={
                        "framework_id": framework_id,
                        "overall_score": posture.overall_score,
                        "gap_count": len(posture.gaps),
                        "function_scores": posture.function_scores,
                    },
                    correlation_keys=[framework_id],
                )
                result = posture.model_dump()
                result["intelligence_packets"] = [packet.to_dict()]
                return result

            elif task_type == "map_controls":
                source = params.get("source_framework")
                target = params.get("target_framework")
                if not source or not target:
                    return {
                        "error": "Both 'source_framework' and 'target_framework' parameters are required",
                        "task_type": task_type,
                        "success": False,
                    }
                control_ids = params.get("control_ids")
                mappings = await self._engine.map_controls(source, target, control_ids)
                return {"mappings": mappings, "count": len(mappings)}

            elif task_type == "collect_evidence":
                control_ids = params.get("control_ids", [])
                if not control_ids:
                    return {
                        "error": "'control_ids' parameter is required and must not be empty",
                        "task_type": task_type,
                        "success": False,
                    }
                sources = params.get("sources")
                evidence = await self._engine.collect_evidence(control_ids, sources)
                return {"evidence": [e.model_dump() for e in evidence], "count": len(evidence)}

            elif task_type == "analyze_gaps":
                framework_id = params.get("framework_id", "nist_csf_2_0")
                gaps = await self._engine.analyze_gaps(framework_id)
                return {"gaps": [g.model_dump() for g in gaps], "count": len(gaps)}

            elif task_type == "manage_risk_register":
                team_id = params.get("team_id", "default")
                action = params.get("action", "list")
                entry = params.get("entry")
                return await self._engine.manage_risk_register(team_id, action, entry)

            elif task_type == "assess_mitre_coverage":
                detection_rules = params.get("detection_rules")
                matrix = await self._engine.assess_mitre_coverage(detection_rules)
                return matrix.model_dump()

            elif task_type == "assess_ai_system":
                agent_id = params.get("agent_id", "alpha_4_threat_intel")
                return await self._engine.assess_ai_system(agent_id)

            elif task_type == "generate_soa":
                scope = params.get("scope", "full")
                soa = await self._engine.generate_soa(scope)
                return soa.model_dump()

            elif task_type == "generate_audit_package":
                framework_id = params.get("framework_id", "nist_csf_2_0")
                scope = params.get("scope", "full")
                package = await self._engine.generate_audit_package(framework_id, scope)
                return package.model_dump()

            else:
                return {
                    "error": (
                        f"Unknown task type '{task_type}' for {self.AGENT_ID}. "
                        f"Supported: assess_compliance, map_controls, collect_evidence, "
                        f"analyze_gaps, manage_risk_register, assess_mitre_coverage, "
                        f"assess_ai_system, generate_soa, generate_audit_package"
                    ),
                    "task_type": task_type,
                    "success": False,
                }

        except Exception as e:
            self.logger.error(f"Error processing task '{task_type}': {e}")
            return {"error": str(e), "task_type": task_type, "success": False}

    async def on_intelligence(self, packet: IntelligencePacket) -> Dict[str, Any]:
        """React to incoming intelligence for GRC implications.

        TODO: Implement actual re-assessment triggers:
          - VULNERABILITY: trigger compliance re-assessment for affected controls
          - INCIDENT: auto-add risk register entry for the incident
          - COMPLIANCE: cross-reference with cached posture and flag drift
        """
        intel_type = packet.intelligence_type
        action_taken = None

        if intel_type == IntelligenceType.VULNERABILITY:
            self.logger.info(
                "Received vulnerability intel — assessing compliance impact"
            )
            action_taken = "logged_for_compliance_review"
        elif intel_type == IntelligenceType.INCIDENT:
            self.logger.info(
                "Received incident intel — updating risk register"
            )
            action_taken = "logged_for_risk_register_update"
        elif intel_type == IntelligenceType.COMPLIANCE:
            self.logger.info(
                "Received compliance intel — cross-referencing with posture"
            )
            action_taken = "logged_for_posture_cross_reference"
        else:
            self.logger.debug(
                f"Received {intel_type} intel — no GRC action defined"
            )
            action_taken = "no_action"

        return {
            "received": True,
            "intelligence_type": str(intel_type),
            "action_taken": action_taken,
            "acted": False,  # No real action yet — see TODO above
        }
