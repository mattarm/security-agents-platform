#!/usr/bin/env python3
"""
Delta Red Team Agent — unified adapter.
Wraps the existing DeltaRedTeamAgent behind BaseSecurityAgent.
"""

from typing import Dict, List, Any, Optional

from security_agents.core.base_agent import BaseSecurityAgent
from security_agents.core.agent_registry import register_agent
from security_agents.core.models import (
    AgentType, IntelligenceType, Priority, SecurityTask,
    IntelligencePacket,
)
from security_agents.agents.engines.delta_red_team_agent import DeltaRedTeamAgent as _OriginalDelta


@register_agent
class DeltaRedTeamAgent(BaseSecurityAgent):
    """Red team agent — adversary simulation, attack paths, detection validation."""

    AGENT_ID = "delta_red_team"
    AGENT_TYPE = AgentType.DELTA
    DISPLAY_NAME = "Delta Red Team"
    CAPABILITIES = [
        "adversary_emulation",
        "attack_path_analysis",
        "detection_validation",
        "purple_team_exercises",
        "technique_simulation",
    ]
    SUBSCRIPTIONS = [
        IntelligenceType.THREAT_CAMPAIGN,
        IntelligenceType.ACTOR_PROFILE,
        IntelligenceType.VULNERABILITY,
        IntelligenceType.CORRELATION,
    ]

    async def _setup(self):
        config_path = self.config.get("config_path", "config/delta_config.yaml")
        self._engine = _OriginalDelta(config_path=config_path)

    async def process_task(self, task: SecurityTask) -> Dict[str, Any]:
        task_type = task.task_type
        params = task.parameters

        if task_type == "adversary_emulation":
            operation_config = params.get("operation_config", {})
            result = await self._engine.start_adversary_emulation(operation_config)
            return result

        elif task_type == "attack_path_analysis":
            target = params.get("target_environment", "default")
            paths = await self._engine.analyze_attack_paths(target)
            return {
                "attack_paths": [
                    {
                        "path_id": p.path_id,
                        "source": p.source_node,
                        "target": p.target_node,
                        "risk_score": p.risk_score,
                        "difficulty": p.difficulty,
                        "steps": len(p.steps),
                    }
                    for p in paths
                ],
                "total_paths": len(paths),
            }

        elif task_type == "detection_validation":
            operation_config = params.get("operation_config", {})
            operation_config.setdefault("name", "Detection Validation")
            operation_config.setdefault("target_environment", "staging")
            result = await self._engine.start_adversary_emulation(operation_config)
            return {"validation_results": result}

        elif task_type == "operation_status":
            op_id = params.get("operation_id")
            if not op_id:
                return {"error": "operation_id required"}
            status = await self._engine.get_operation_status(op_id)
            return status

        elif task_type == "terminate_operation":
            op_id = params.get("operation_id")
            if not op_id:
                return {"error": "operation_id required"}
            result = await self._engine.terminate_operation(op_id)
            return result

        else:
            raise ValueError(
                f"Unknown task type '{task_type}' for {self.AGENT_ID}. "
                f"Supported: adversary_emulation, attack_path_analysis, "
                f"detection_validation, operation_status, terminate_operation"
            )

    async def on_intelligence(self, packet: IntelligencePacket):
        if packet.intelligence_type == IntelligenceType.THREAT_CAMPAIGN:
            self.logger.info(
                "Received campaign intel — may inform adversary emulation profiles"
            )
        elif packet.intelligence_type == IntelligenceType.VULNERABILITY:
            self.logger.info(
                "Received vulnerability intel — updating attack path analysis"
            )
