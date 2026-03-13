#!/usr/bin/env python3
"""Tests for GRC cross-agent skills."""

import pytest

from security_agents.skills.compliance_check import ComplianceCheckSkill
from security_agents.skills.control_mapping import ControlMappingSkill
from security_agents.skills.evidence_collection import EvidenceCollectionSkill
from security_agents.skills.risk_scoring import RiskScoringSkill


class TestComplianceCheckSkill:
    @pytest.fixture
    async def skill(self):
        s = ComplianceCheckSkill(agent_id="test_agent")
        await s.initialize()
        return s

    def test_metadata(self):
        s = ComplianceCheckSkill(agent_id="test")
        meta = s.get_metadata()
        assert meta["skill_name"] == "compliance_check"
        assert meta["compatible_agents"] == []  # all agents

    @pytest.mark.asyncio
    async def test_execute_default(self, skill):
        result = await skill.execute({"framework_id": "nist_csf_2_0"})
        assert result.success is True
        assert "overall_score" in result.data
        assert "gap_count" in result.data

    @pytest.mark.asyncio
    async def test_execute_iso27001(self, skill):
        result = await skill.execute({"framework_id": "iso_27001_2022"})
        assert result.success is True


class TestControlMappingSkill:
    @pytest.fixture
    async def skill(self):
        s = ControlMappingSkill(agent_id="test_agent")
        await s.initialize()
        return s

    @pytest.mark.asyncio
    async def test_execute(self, skill):
        result = await skill.execute({
            "source_framework": "nist_csf_2_0",
            "target_framework": "iso_27001_2022",
        })
        assert result.success is True
        assert result.data["count"] >= 1

    @pytest.mark.asyncio
    async def test_execute_with_control_filter(self, skill):
        result = await skill.execute({
            "source_framework": "nist_csf_2_0",
            "target_framework": "iso_27001_2022",
            "control_ids": ["GV.PO-01"],
        })
        assert result.success is True
        assert result.data["count"] >= 1


class TestEvidenceCollectionSkill:
    @pytest.fixture
    async def skill(self):
        s = EvidenceCollectionSkill(agent_id="test_agent")
        await s.initialize()
        return s

    @pytest.mark.asyncio
    async def test_execute(self, skill):
        result = await skill.execute({"control_ids": ["A.5.1", "A.5.2"]})
        assert result.success is True
        assert result.data["count"] > 0

    @pytest.mark.asyncio
    async def test_execute_no_controls(self, skill):
        result = await skill.execute({})
        assert result.success is False
        assert "control_ids" in result.errors[0]


class TestRiskScoringSkill:
    @pytest.fixture
    async def skill(self):
        s = RiskScoringSkill(agent_id="test_agent")
        await s.initialize()
        return s

    @pytest.mark.asyncio
    async def test_basic_scoring(self, skill):
        result = await skill.execute({
            "description": "Unpatched servers",
            "likelihood": 4, "impact": 5,
        })
        assert result.success is True
        assert result.data["inherent_risk"] == 20
        assert result.data["risk_level"] == "critical"

    @pytest.mark.asyncio
    async def test_scoring_with_controls(self, skill):
        result = await skill.execute({
            "description": "SQL injection",
            "likelihood": 3, "impact": 4,
            "controls": ["WAF", "Input validation", "Parameterized queries"],
        })
        assert result.success is True
        assert result.data["residual_risk"] < result.data["inherent_risk"]
        assert result.data["control_effectiveness"] > 0

    @pytest.mark.asyncio
    async def test_low_risk(self, skill):
        result = await skill.execute({"likelihood": 1, "impact": 1})
        assert result.data["risk_level"] == "low"
        assert result.data["inherent_risk"] == 1

    @pytest.mark.asyncio
    async def test_bounds_clamping(self, skill):
        result = await skill.execute({"likelihood": 10, "impact": -5})
        # Should clamp to valid range
        assert result.data["likelihood"] == 5
        assert result.data["impact"] == 1
