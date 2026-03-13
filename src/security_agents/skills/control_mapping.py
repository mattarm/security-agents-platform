#!/usr/bin/env python3
"""ControlMappingSkill — cross-framework control lookups any agent can use."""

from typing import Dict, List, Any, Optional

from security_agents.skills.base_skill import BaseSecuritySkill
from security_agents.core.models import SkillResult


class ControlMappingSkill(BaseSecuritySkill):
    """Cross-framework control mapping lookups."""

    SKILL_NAME = "control_mapping"
    DESCRIPTION = "Cross-framework control lookups (NIST CSF, ISO 27001, ISO 42001, MITRE ATT&CK)"
    VERSION = "1.0.0"
    COMPATIBLE_AGENTS: List[str] = []  # All agents

    async def _setup(self):
        pass

    async def _execute(self, parameters: Dict[str, Any]) -> SkillResult:
        """Execute a control mapping lookup.

        Parameters:
            source_framework: Source framework ID
            target_framework: Target framework ID
            control_ids: Optional list of specific controls to map
        """
        from security_agents.core.grc_frameworks import list_frameworks
        from security_agents.core.grc_frameworks.cross_mappings import get_mappings

        source = parameters.get("source_framework", "nist_csf_2_0")
        target = parameters.get("target_framework", "iso_27001_2022")
        control_ids = parameters.get("control_ids")

        # Validate: source and target must differ
        if source == target:
            return SkillResult(
                success=False,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                data={},
                errors=[f"source and target framework must be different, got '{source}' for both"],
            )

        # Validate: both frameworks must be known
        known_ids = {f["id"] for f in list_frameworks()}
        unknown = [fw for fw in (source, target) if fw not in known_ids]
        if unknown:
            return SkillResult(
                success=False,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                data={},
                errors=[f"unknown framework(s): {', '.join(unknown)}. Known: {', '.join(sorted(known_ids))}"],
            )

        mappings = get_mappings(source, target)
        if control_ids:
            mappings = [m for m in mappings if m.source_control in control_ids]

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "source_framework": source,
                "target_framework": target,
                "mappings": [m.model_dump() for m in mappings],
                "count": len(mappings),
            },
        )
