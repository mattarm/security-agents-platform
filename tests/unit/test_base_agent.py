"""Tests for BaseSecurityAgent — the contract all agents must fulfill."""

import pytest
from datetime import datetime
from typing import Dict, Any, List

from security_agents.core.base_agent import BaseSecurityAgent
from security_agents.core.models import (
    AgentType, AgentStatus, IntelligenceType, Priority,
    SecurityTask, TaskStatus, IntelligencePacket,
)


class StubAgent(BaseSecurityAgent):
    """Minimal concrete agent for testing the base class."""

    AGENT_ID = "test_stub"
    AGENT_TYPE = AgentType.GAMMA
    DISPLAY_NAME = "Test Stub Agent"
    CAPABILITIES = ["testing"]
    SUBSCRIPTIONS = [IntelligenceType.CORRELATION]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.setup_called = False
        self.last_intelligence = None
        self.process_result = {"status": "ok"}

    async def _setup(self):
        self.setup_called = True

    async def process_task(self, task: SecurityTask) -> Dict[str, Any]:
        return self.process_result

    async def on_intelligence(self, packet: IntelligencePacket):
        self.last_intelligence = packet


class FailingAgent(BaseSecurityAgent):
    """Agent whose _setup always fails."""

    AGENT_ID = "test_failing"
    AGENT_TYPE = AgentType.GAMMA
    DISPLAY_NAME = "Failing Agent"
    CAPABILITIES = []
    SUBSCRIPTIONS = []

    async def _setup(self):
        raise RuntimeError("Setup explosion")

    async def process_task(self, task: SecurityTask) -> Dict[str, Any]:
        raise RuntimeError("Task explosion")

    async def on_intelligence(self, packet: IntelligencePacket):
        pass


class TestBaseAgentLifecycle:
    @pytest.mark.asyncio
    async def test_initialize_success(self):
        agent = StubAgent()
        result = await agent.initialize()
        assert result is True
        assert agent.status == AgentStatus.ACTIVE
        assert agent.setup_called

    @pytest.mark.asyncio
    async def test_initialize_failure(self):
        agent = FailingAgent()
        result = await agent.initialize()
        assert result is False
        assert agent.status == AgentStatus.ERROR

    @pytest.mark.asyncio
    async def test_shutdown(self):
        agent = StubAgent()
        await agent.initialize()
        await agent.shutdown()
        assert agent.status == AgentStatus.OFFLINE


class TestBaseAgentInfo:
    def test_get_info(self):
        agent = StubAgent()
        info = agent.get_info()
        assert info.agent_id == "test_stub"
        assert info.capabilities == ["testing"]
        assert info.status == AgentStatus.INITIALIZING

    def test_heartbeat(self):
        agent = StubAgent()
        before = agent._last_heartbeat
        agent.heartbeat()
        assert agent._last_heartbeat >= before


class TestBaseAgentTaskExecution:
    @pytest.mark.asyncio
    async def test_execute_success(self):
        agent = StubAgent()
        await agent.initialize()

        task = SecurityTask(
            task_id="T-001",
            task_type="test",
            priority=Priority.MEDIUM,
            assigned_agent="test_stub",
            status=TaskStatus.PENDING,
            created_at=datetime.now(),
        )

        result = await agent.execute(task)
        assert result == {"status": "ok"}
        assert task.status == TaskStatus.COMPLETED
        assert task.completed_at is not None
        assert agent._tasks_completed == 1
        assert agent.status == AgentStatus.ACTIVE

    @pytest.mark.asyncio
    async def test_execute_failure(self):
        agent = FailingAgent()
        # Manually set active so we can test execution path
        agent.status = AgentStatus.ACTIVE

        task = SecurityTask(
            task_id="T-002",
            task_type="test",
            priority=Priority.HIGH,
            assigned_agent="test_failing",
            status=TaskStatus.PENDING,
            created_at=datetime.now(),
        )

        with pytest.raises(RuntimeError, match="Task explosion"):
            await agent.execute(task)

        assert task.status == TaskStatus.FAILED
        assert agent._tasks_failed == 1


class TestBaseAgentIntelligence:
    @pytest.mark.asyncio
    async def test_receive_intelligence(self):
        agent = StubAgent()
        await agent.initialize()

        packet = IntelligencePacket(
            packet_id="PKT-001",
            source_agent="alpha_4_threat_intel",
            target_agents=["test_stub"],
            intelligence_type=IntelligenceType.CORRELATION,
            priority=Priority.HIGH,
            confidence=90.0,
            timestamp=datetime.now(),
            data={"test": True},
            correlation_keys=["key1"],
        )

        await agent.receive_intelligence(packet)
        assert agent.last_intelligence is not None
        assert agent.last_intelligence.packet_id == "PKT-001"

    def test_create_intelligence_packet(self):
        agent = StubAgent()
        packet = agent.create_intelligence_packet(
            intelligence_type=IntelligenceType.THREAT_CAMPAIGN,
            priority=Priority.HIGH,
            confidence=85.0,
            data={"campaign": "test"},
            correlation_keys=["ioc1", "ioc2"],
        )
        assert packet.source_agent == "test_stub"
        assert packet.target_agents == ["all"]
        assert packet.confidence == 85.0


class TestBaseAgentSkills:
    @pytest.mark.asyncio
    async def test_register_and_execute_skill(self):
        agent = StubAgent()
        await agent.initialize()

        # Mock skill
        class MockSkill:
            async def execute(self, params):
                from security_agents.core.models import SkillResult
                return SkillResult(
                    success=True,
                    skill_name="mock_skill",
                    agent_id="test_stub",
                    data={"result": "ok"},
                )

        agent.register_skill("mock_skill", MockSkill())
        assert "mock_skill" in agent.skills

        result = await agent.execute_skill("mock_skill", {})
        assert result.success
        assert result.data["result"] == "ok"

    @pytest.mark.asyncio
    async def test_execute_unregistered_skill(self):
        agent = StubAgent()
        result = await agent.execute_skill("nonexistent", {})
        assert not result.success
        assert "not registered" in result.errors[0]


class TestBaseAgentValidation:
    def test_agent_id_required(self):
        class BadAgent(BaseSecurityAgent):
            AGENT_ID = ""
            async def _setup(self): pass
            async def process_task(self, task): pass
            async def on_intelligence(self, packet): pass

        with pytest.raises(ValueError, match="must define AGENT_ID"):
            BadAgent()
