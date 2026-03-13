#!/usr/bin/env python3
"""RiskScoringSkill — ISO 31000 risk calculation any agent can use."""

from typing import Dict, List, Any, Optional

from security_agents.skills.base_skill import BaseSecuritySkill
from security_agents.core.models import SkillResult


class RiskScoringSkill(BaseSecuritySkill):
    """ISO 31000 risk scoring: likelihood x impact with treatment options."""

    SKILL_NAME = "risk_scoring"
    DESCRIPTION = "Calculate risk scores using ISO 31000 methodology (likelihood x impact)"
    VERSION = "1.0.0"
    COMPATIBLE_AGENTS: List[str] = []  # All agents

    async def _setup(self):
        pass

    async def _execute(self, parameters: Dict[str, Any]) -> SkillResult:
        """Calculate risk score.

        Parameters:
            description: Risk description
            likelihood: 1-5 scale (1=rare, 5=almost certain)
            impact: 1-5 scale (1=negligible, 5=catastrophic)
            controls: Optional list of existing controls
            category: Risk category (operational, strategic, compliance, technical)
        """
        description = parameters.get("description", "")
        raw_likelihood = parameters.get("likelihood", 3)
        raw_impact = parameters.get("impact", 3)

        # Input validation: likelihood and impact must be numeric
        if not isinstance(raw_likelihood, (int, float)) or not isinstance(raw_impact, (int, float)):
            return SkillResult(
                success=False,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                data={},
                errors=["likelihood and impact must be numbers between 1 and 5"],
            )

        likelihood = min(max(raw_likelihood, 1), 5)
        impact = min(max(raw_impact, 1), 5)
        controls = parameters.get("controls", [])
        category = parameters.get("category", "operational")

        inherent_risk = likelihood * impact

        # Residual risk reduction based on number of controls
        control_effectiveness = min(len(controls) * 0.15, 0.6)  # Max 60% reduction
        residual_risk = round(inherent_risk * (1 - control_effectiveness), 1)

        # Risk level classification
        if inherent_risk >= 20:
            risk_level = "critical"
        elif inherent_risk >= 12:
            risk_level = "high"
        elif inherent_risk >= 6:
            risk_level = "medium"
        else:
            risk_level = "low"

        # Recommended treatment
        treatment = "mitigate" if residual_risk >= 8 else "accept"

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "description": description,
                "category": category,
                "likelihood": likelihood,
                "impact": impact,
                "inherent_risk": inherent_risk,
                "controls_count": len(controls),
                "control_effectiveness": round(control_effectiveness * 100, 1),
                "residual_risk": residual_risk,
                "risk_level": risk_level,
                "recommended_treatment": treatment,
            },
        )
