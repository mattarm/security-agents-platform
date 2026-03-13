#!/usr/bin/env python3
"""EvidenceCollectionSkill — standardized compliance evidence gathering."""

from typing import Dict, List, Any, Optional

from security_agents.skills.base_skill import BaseSecuritySkill
from security_agents.core.models import SkillResult


class EvidenceCollectionSkill(BaseSecuritySkill):
    """Standardized evidence gathering for compliance controls."""

    SKILL_NAME = "evidence_collection"
    DESCRIPTION = "Collect compliance evidence from platform integrations for specified controls"
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
        """Collect evidence for controls.

        Parameters:
            control_ids: List of control IDs to collect evidence for
            sources: Optional list of evidence sources
        """
        control_ids = parameters.get("control_ids", [])
        sources = parameters.get("sources")

        if not control_ids:
            return SkillResult(
                success=False,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                errors=["control_ids parameter is required"],
            )

        engine = self._get_engine()
        evidence = await engine.collect_evidence(control_ids, sources)

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "evidence": [e.model_dump() for e in evidence],
                "count": len(evidence),
                "control_ids": control_ids,
            },
        )
