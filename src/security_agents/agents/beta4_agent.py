#!/usr/bin/env python3
"""
Beta-4 DevSecOps Agent — unified adapter.
Wraps the existing AdvancedDevSecOpsEngine behind BaseSecurityAgent.
"""

from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import asdict

from security_agents.core.base_agent import BaseSecurityAgent
from security_agents.core.agent_registry import register_agent
from security_agents.core.models import (
    AgentType, IntelligenceType, Priority, SecurityTask,
    IntelligencePacket,
)
from security_agents.agents.engines.tiger_team_beta_4 import AdvancedDevSecOpsEngine


@register_agent
class Beta4DevSecOpsAgent(BaseSecurityAgent):
    """DevSecOps agent — SAST, container scanning, IaC security, supply chain."""

    AGENT_ID = "beta_4_devsecops"
    AGENT_TYPE = AgentType.BETA_4
    DISPLAY_NAME = "Beta-4 DevSecOps"
    CAPABILITIES = [
        "sast_analysis",
        "container_security",
        "iac_security",
        "supply_chain",
        "architecture_assessment",
        "cicd_security",
    ]
    SUBSCRIPTIONS = [
        IntelligenceType.THREAT_CAMPAIGN,
        IntelligenceType.ACTOR_PROFILE,
        IntelligenceType.IOC_ENRICHMENT,
        IntelligenceType.CORRELATION,
    ]

    async def _setup(self):
        workspace = self.config.get("workspace_path", ".")
        self._engine = AdvancedDevSecOpsEngine(workspace_path=workspace)

    async def process_task(self, task: SecurityTask) -> Dict[str, Any]:
        task_type = task.task_type
        params = task.parameters

        if task_type == "comprehensive_scan":
            target_path = Path(params.get("target_path", "."))
            include_arch = params.get("include_architecture", True)
            include_supply = params.get("include_supply_chain", True)
            results = await self._engine.comprehensive_security_analysis(
                target_path=target_path,
                include_architecture=include_arch,
                include_supply_chain=include_supply,
            )
            # Emit vulnerability intel
            vuln_count = len(results.get("vulnerabilities", []))
            if vuln_count > 0:
                packet = self.create_intelligence_packet(
                    intelligence_type=IntelligenceType.VULNERABILITY,
                    priority=Priority.HIGH if vuln_count > 10 else Priority.MEDIUM,
                    confidence=85.0,
                    data={"vulnerability_count": vuln_count, "target": str(target_path)},
                    correlation_keys=[str(target_path)],
                )
                results["intelligence_packets"] = [packet.to_dict()]
            return results

        elif task_type == "sast_scan":
            target_path = Path(params.get("target_path", "."))
            vulns = await self._engine.perform_advanced_sast(target_path)
            return {"vulnerabilities": [asdict(v) for v in vulns], "count": len(vulns)}

        elif task_type == "container_scan":
            target_path = Path(params.get("target_path", "."))
            vulns = await self._engine.analyze_container_security(target_path)
            return {"vulnerabilities": [asdict(v) for v in vulns], "count": len(vulns)}

        elif task_type == "supply_chain_scan":
            target_path = Path(params.get("target_path", "."))
            risks = await self._engine.analyze_dependencies(target_path)
            return {"supply_chain_risks": [asdict(r) for r in risks], "count": len(risks)}

        elif task_type == "iac_scan":
            target_path = Path(params.get("target_path", "."))
            vulns = await self._engine.analyze_infrastructure_as_code(target_path)
            return {"vulnerabilities": [asdict(v) for v in vulns], "count": len(vulns)}

        else:
            raise ValueError(
                f"Unknown task type '{task_type}' for {self.AGENT_ID}. "
                f"Supported: comprehensive_scan, sast_scan, container_scan, "
                f"supply_chain_scan, iac_scan"
            )

    async def on_intelligence(self, packet: IntelligencePacket):
        if packet.intelligence_type == IntelligenceType.THREAT_CAMPAIGN:
            self.logger.info(
                "Received threat campaign intel — will prioritize related vulnerabilities"
            )
