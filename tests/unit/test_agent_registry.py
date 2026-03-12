"""Tests for AgentRegistry — dynamic agent discovery and instantiation."""

import pytest
from typing import Dict, Any

from security_agents.core.base_agent import BaseSecurityAgent
from security_agents.core.agent_registry import AgentRegistry, register_agent
from security_agents.core.models import (
    AgentType, IntelligenceType, SecurityTask, IntelligencePacket,
)


class _TestAgent(BaseSecurityAgent):
    AGENT_ID = "registry_test_agent"
    AGENT_TYPE = AgentType.GAMMA
    DISPLAY_NAME = "Registry Test Agent"
    CAPABILITIES = ["test"]
    SUBSCRIPTIONS = [IntelligenceType.CORRELATION]

    async def _setup(self):
        pass

    async def process_task(self, task: SecurityTask) -> Dict[str, Any]:
        return {"ok": True}

    async def on_intelligence(self, packet: IntelligencePacket):
        pass


class TestAgentRegistry:
    def setup_method(self):
        """Save and clear the registry before each test."""
        self._saved = dict(AgentRegistry._registry)
        AgentRegistry.clear()

    def teardown_method(self):
        """Restore original registry after each test."""
        AgentRegistry._registry = self._saved

    def test_register_and_create(self):
        AgentRegistry.register(_TestAgent)
        agent = AgentRegistry.create("registry_test_agent")
        assert agent.AGENT_ID == "registry_test_agent"
        assert isinstance(agent, BaseSecurityAgent)

    def test_create_unknown_agent_raises(self):
        with pytest.raises(ValueError, match="Unknown agent"):
            AgentRegistry.create("nonexistent_agent")

    def test_create_all(self):
        AgentRegistry.register(_TestAgent)
        agents = AgentRegistry.create_all()
        assert "registry_test_agent" in agents

    def test_create_all_respects_enabled(self):
        AgentRegistry.register(_TestAgent)
        configs = {"registry_test_agent": {"enabled": False}}
        agents = AgentRegistry.create_all(configs, only_enabled=True)
        assert "registry_test_agent" not in agents

    def test_list_agents(self):
        AgentRegistry.register(_TestAgent)
        listing = AgentRegistry.list_agents()
        assert len(listing) == 1
        assert listing[0]["agent_id"] == "registry_test_agent"
        assert listing[0]["display_name"] == "Registry Test Agent"

    def test_decorator_registration(self):
        @register_agent
        class _DecoratedAgent(BaseSecurityAgent):
            AGENT_ID = "decorated_test"
            AGENT_TYPE = AgentType.DELTA
            DISPLAY_NAME = "Decorated"
            CAPABILITIES = []
            SUBSCRIPTIONS = []

            async def _setup(self): pass
            async def process_task(self, task): return {}
            async def on_intelligence(self, packet): pass

        assert AgentRegistry.get_agent_class("decorated_test") is _DecoratedAgent

    def test_clear(self):
        AgentRegistry.register(_TestAgent)
        assert len(AgentRegistry._registry) > 0
        AgentRegistry.clear()
        assert len(AgentRegistry._registry) == 0
