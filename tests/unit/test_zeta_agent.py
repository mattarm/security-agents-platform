#!/usr/bin/env python3
"""Tests for Zeta GRC Agent."""

import pytest
from datetime import datetime

from security_agents.core.models import (
    AgentType, IntelligenceType, Priority, SecurityTask, TaskStatus,
)
from security_agents.core.agent_registry import AgentRegistry
from security_agents.agents.zeta_agent import ZetaGRCAgent


class TestZetaAgentRegistration:
    def test_agent_registered(self):
        """Zeta should be in the registry after import."""
        agents = AgentRegistry.list_agents()
        ids = [a["agent_id"] for a in agents]
        assert "zeta_grc" in ids

    def test_agent_class_attributes(self):
        assert ZetaGRCAgent.AGENT_ID == "zeta_grc"
        assert ZetaGRCAgent.AGENT_TYPE == AgentType.ZETA
        assert ZetaGRCAgent.DISPLAY_NAME == "Zeta GRC"

    def test_capabilities(self):
        assert "compliance_assessment" in ZetaGRCAgent.CAPABILITIES
        assert "gap_analysis" in ZetaGRCAgent.CAPABILITIES
        assert "mitre_coverage" in ZetaGRCAgent.CAPABILITIES
        assert "ai_governance" in ZetaGRCAgent.CAPABILITIES

    def test_subscriptions(self):
        assert IntelligenceType.VULNERABILITY in ZetaGRCAgent.SUBSCRIPTIONS
        assert IntelligenceType.COMPLIANCE in ZetaGRCAgent.SUBSCRIPTIONS


class TestZetaAgentLifecycle:
    @pytest.fixture
    async def agent(self):
        agent = ZetaGRCAgent()
        await agent.initialize()
        yield agent
        await agent.shutdown()

    @pytest.mark.asyncio
    async def test_initialize(self, agent):
        assert agent.status.value == "active"
        assert agent._engine is not None

    @pytest.mark.asyncio
    async def test_get_info(self, agent):
        info = agent.get_info()
        assert info.agent_id == "zeta_grc"
        assert "compliance_assessment" in info.capabilities


class TestZetaProcessTask:
    @pytest.fixture
    async def agent(self):
        agent = ZetaGRCAgent()
        await agent.initialize()
        yield agent

    def _make_task(self, task_type, params=None):
        return SecurityTask(
            task_id=f"test-{task_type}",
            task_type=task_type,
            priority=Priority.MEDIUM,
            assigned_agent="zeta_grc",
            status=TaskStatus.PENDING,
            created_at=datetime.now(),
            parameters=params or {},
        )

    @pytest.mark.asyncio
    async def test_assess_compliance(self, agent):
        task = self._make_task("assess_compliance", {"framework_id": "nist_csf_2_0"})
        result = await agent.process_task(task)
        assert "overall_score" in result
        assert "gaps" in result
        assert "intelligence_packets" in result

    @pytest.mark.asyncio
    async def test_map_controls(self, agent):
        task = self._make_task("map_controls", {
            "source_framework": "nist_csf_2_0",
            "target_framework": "iso_27001_2022",
        })
        result = await agent.process_task(task)
        assert "mappings" in result
        assert result["count"] >= 1

    @pytest.mark.asyncio
    async def test_collect_evidence(self, agent):
        task = self._make_task("collect_evidence", {"control_ids": ["A.5.1", "A.5.2"]})
        result = await agent.process_task(task)
        assert result["count"] > 0

    @pytest.mark.asyncio
    async def test_analyze_gaps(self, agent):
        task = self._make_task("analyze_gaps", {"framework_id": "iso_27001_2022"})
        result = await agent.process_task(task)
        assert "gaps" in result

    @pytest.mark.asyncio
    async def test_manage_risk_register_list(self, agent):
        task = self._make_task("manage_risk_register", {
            "team_id": "test_team", "action": "list",
        })
        result = await agent.process_task(task)
        assert result["team_id"] == "test_team"

    @pytest.mark.asyncio
    async def test_manage_risk_register_add(self, agent):
        task = self._make_task("manage_risk_register", {
            "team_id": "test_team", "action": "add",
            "entry": {"description": "Test risk", "likelihood": 3, "impact": 4},
        })
        result = await agent.process_task(task)
        assert result["action"] == "added"

    @pytest.mark.asyncio
    async def test_assess_mitre_coverage(self, agent):
        task = self._make_task("assess_mitre_coverage")
        result = await agent.process_task(task)
        assert "tactic_coverage" in result
        assert "overall_coverage" in result

    @pytest.mark.asyncio
    async def test_assess_ai_system(self, agent):
        task = self._make_task("assess_ai_system", {"agent_id": "alpha_4_threat_intel"})
        result = await agent.process_task(task)
        assert "system" in result
        assert "impact_assessment" in result

    @pytest.mark.asyncio
    async def test_generate_soa(self, agent):
        task = self._make_task("generate_soa", {"scope": "full"})
        result = await agent.process_task(task)
        assert result["total_controls"] == 93

    @pytest.mark.asyncio
    async def test_generate_audit_package(self, agent):
        task = self._make_task("generate_audit_package", {"framework_id": "nist_csf_2_0"})
        result = await agent.process_task(task)
        assert result["framework_id"] == "nist_csf_2_0"
        assert "evidence" in result

    @pytest.mark.asyncio
    async def test_unknown_task_type(self, agent):
        task = self._make_task("nonexistent_task")
        result = await agent.process_task(task)
        assert result["success"] is False
        assert "Unknown task type" in result["error"]
