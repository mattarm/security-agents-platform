#!/usr/bin/env python3
"""ComplianceCheckSkill — quick compliance check any agent can trigger."""

from typing import Dict, List, Any, Optional

from security_agents.skills.base_skill import BaseSecuritySkill
from security_agents.core.models import SkillResult, IntelligencePacket


class ComplianceCheckSkill(BaseSecuritySkill):
    """Quick compliance check against a specified framework."""

    SKILL_NAME = "compliance_check"
    DESCRIPTION = "Quick compliance check any agent can trigger to assess control status"
    VERSION = "1.0.0"
    COMPATIBLE_AGENTS: List[str] = []  # All agents

    async def _setup(self):
        self._engine = None

    def _get_engine(self):
        if self._engine is None:
            from security_agents.agents.engines.zeta_grc_engine import ZetaGRCEngine
            self._engine = ZetaGRCEngine()
        return self._engine

    async def _execute(self, parameters: Dict[str, Any]) -> SkillResult:
        """Execute a quick compliance check.

        Parameters:
            framework_id: Framework to check (default: nist_csf_2_0)
            control_ids: Optional list of specific controls to check
            scope: Assessment scope (default: full)
        """
        from security_agents.core.grc_frameworks import list_frameworks

        framework_id = parameters.get("framework_id", "nist_csf_2_0")
        scope = parameters.get("scope", "full")

        # Validate framework_id is known
        known_ids = {f["id"] for f in list_frameworks()}
        if framework_id not in known_ids:
            return SkillResult(
                success=False,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                data={},
                errors=[f"unknown framework '{framework_id}'. Known: {', '.join(sorted(known_ids))}"],
            )

        engine = self._get_engine()
        posture = await engine.assess_compliance(framework_id, scope)

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "framework_id": framework_id,
                "overall_score": posture.overall_score,
                "gap_count": len(posture.gaps),
                "function_scores": posture.function_scores,
                "top_gaps": [g.model_dump() for g in posture.gaps[:5]],
            },
        )
