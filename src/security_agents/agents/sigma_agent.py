#!/usr/bin/env python3
"""
Sigma Metrics Agent — unified adapter.
Wraps the existing SigmaMetricsAgent behind BaseSecurityAgent.
"""

from typing import Dict, List, Any, Optional

from security_agents.core.base_agent import BaseSecurityAgent
from security_agents.core.agent_registry import register_agent
from security_agents.core.models import (
    AgentType, IntelligenceType, Priority, SecurityTask,
    IntelligencePacket, MetricType,
)

# Import original — the class name is SigmaSecurityMetricsAgent
from security_agents.agents.engines.sigma_metrics_agent import SigmaMetricsAgent as _OriginalSigma


@register_agent
class SigmaMetricsAgent(BaseSecurityAgent):
    """Metrics agent — security program performance, ODM tracking, reporting."""

    AGENT_ID = "sigma_metrics"
    AGENT_TYPE = AgentType.SIGMA
    DISPLAY_NAME = "Sigma Metrics"
    CAPABILITIES = [
        "executive_dashboard",
        "strategic_reporting",
        "tactical_reporting",
        "metrics_collection",
        "odm_tracking",
        "compliance_metrics",
    ]
    SUBSCRIPTIONS = [
        IntelligenceType.INCIDENT,
        IntelligenceType.VULNERABILITY,
        IntelligenceType.CORRELATION,
        IntelligenceType.COMPLIANCE,
        IntelligenceType.METRICS,
    ]

    async def _setup(self):
        self._engine = _OriginalSigma()

    async def process_task(self, task: SecurityTask) -> Dict[str, Any]:
        task_type = task.task_type
        params = task.parameters

        if task_type == "executive_dashboard":
            dashboard = await self._engine.generate_executive_dashboard()
            # Emit metrics intelligence
            if dashboard.get("overall_score") is not None:
                packet = self.create_intelligence_packet(
                    intelligence_type=IntelligenceType.METRICS,
                    priority=Priority.INFO,
                    confidence=95.0,
                    data={
                        "overall_score": dashboard.get("overall_score"),
                        "achievement_rate": dashboard.get("achievement_rate"),
                        "critical_attention": dashboard.get("critical_attention"),
                    },
                    correlation_keys=["metrics_dashboard"],
                )
                dashboard["intelligence_packets"] = [packet.to_dict()]
            return dashboard

        elif task_type == "strategic_report":
            time_period = params.get("time_period", "monthly")
            result = await self._engine.run_scheduled_reporting()
            return result

        elif task_type == "tactical_report":
            time_period = params.get("time_period", "weekly")
            result = await self._engine.run_scheduled_reporting()
            return result

        elif task_type == "collect_metrics":
            metrics = await self._engine.collector.collect_all_metrics()
            return {"metrics": metrics}

        elif task_type == "update_metrics":
            await self._engine.update_metrics_from_sources()
            return {"status": "metrics_updated"}

        else:
            raise ValueError(
                f"Unknown task type '{task_type}' for {self.AGENT_ID}. "
                f"Supported: executive_dashboard, strategic_report, "
                f"tactical_report, collect_metrics, update_metrics"
            )

    async def on_intelligence(self, packet: IntelligencePacket):
        if packet.intelligence_type == IntelligenceType.INCIDENT:
            self.logger.info("Received incident intel — updating IR metrics")
        elif packet.intelligence_type == IntelligenceType.VULNERABILITY:
            self.logger.info("Received vulnerability intel — updating vuln metrics")
