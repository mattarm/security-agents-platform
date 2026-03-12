#!/usr/bin/env python3
"""
Agent Registry & Factory - Dynamic agent registration, discovery, and instantiation.
Eliminates hardcoded agent routing in the orchestrator.
"""

import logging
from typing import Dict, List, Any, Optional, Type

from security_agents.core.base_agent import BaseSecurityAgent
from security_agents.core.models import AgentType, AgentStatus, IntelligenceType

logger = logging.getLogger(__name__)


class AgentRegistry:
    """
    Central registry for all security agents.

    Agents self-register at import time using the @register_agent decorator
    or via AgentRegistry.register(). The orchestrator uses the registry to
    discover, instantiate, and route tasks to agents dynamically — no more
    hardcoded if/elif chains.
    """

    _registry: Dict[str, Type[BaseSecurityAgent]] = {}

    @classmethod
    def register(cls, agent_class: Type[BaseSecurityAgent]):
        """Register an agent class by its AGENT_ID."""
        agent_id = agent_class.AGENT_ID
        if not agent_id:
            raise ValueError(
                f"Cannot register {agent_class.__name__}: AGENT_ID is not set"
            )
        if agent_id in cls._registry:
            logger.warning(
                f"Overwriting existing registration for {agent_id} "
                f"({cls._registry[agent_id].__name__} -> {agent_class.__name__})"
            )
        cls._registry[agent_id] = agent_class
        logger.info(f"Registered agent: {agent_id} ({agent_class.__name__})")
        return agent_class

    @classmethod
    def create(
        cls, agent_id: str, config: Optional[Dict[str, Any]] = None
    ) -> BaseSecurityAgent:
        """Instantiate a registered agent by ID."""
        if agent_id not in cls._registry:
            available = list(cls._registry.keys())
            raise ValueError(
                f"Unknown agent '{agent_id}'. Available: {available}"
            )
        agent_class = cls._registry[agent_id]
        return agent_class(config=config)

    @classmethod
    def create_all(
        cls,
        agent_configs: Optional[Dict[str, Dict[str, Any]]] = None,
        only_enabled: bool = True,
    ) -> Dict[str, BaseSecurityAgent]:
        """
        Instantiate all registered agents. If agent_configs is provided,
        only agents with enabled=True (or missing from config) are created.
        """
        agents = {}
        configs = agent_configs or {}

        for agent_id, agent_class in cls._registry.items():
            agent_cfg = configs.get(agent_id, {})

            if only_enabled and not agent_cfg.get("enabled", True):
                logger.info(f"Skipping disabled agent: {agent_id}")
                continue

            try:
                agents[agent_id] = agent_class(config=agent_cfg)
                logger.info(f"Created agent: {agent_id}")
            except Exception as e:
                logger.error(f"Failed to create agent {agent_id}: {e}")

        return agents

    @classmethod
    def get_agent_class(cls, agent_id: str) -> Optional[Type[BaseSecurityAgent]]:
        """Look up a registered agent class."""
        return cls._registry.get(agent_id)

    @classmethod
    def list_agents(cls) -> List[Dict[str, Any]]:
        """Return metadata for all registered agents."""
        result = []
        for agent_id, agent_class in cls._registry.items():
            result.append({
                "agent_id": agent_id,
                "class_name": agent_class.__name__,
                "display_name": agent_class.DISPLAY_NAME,
                "capabilities": list(agent_class.CAPABILITIES),
                "subscriptions": [s.value for s in agent_class.SUBSCRIPTIONS],
            })
        return result

    @classmethod
    def clear(cls):
        """Clear the registry (primarily for testing)."""
        cls._registry.clear()


def register_agent(cls: Type[BaseSecurityAgent]) -> Type[BaseSecurityAgent]:
    """Decorator to auto-register an agent class."""
    AgentRegistry.register(cls)
    return cls
