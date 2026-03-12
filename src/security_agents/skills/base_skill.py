#!/usr/bin/env python3
"""
Base Security Skill - Abstract base class for all agent skills.
Skills are composable units of capability that can be shared across agents.
"""

import logging
import time
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional

from security_agents.core.models import SkillResult, IntelligencePacket


class BaseSecuritySkill(ABC):
    """
    Abstract base class for all security skills.

    A skill encapsulates a specific security capability (e.g., phishing
    analysis, threat hunting, vulnerability assessment) that can be
    registered with one or more agents.
    """

    SKILL_NAME: str = ""
    DESCRIPTION: str = ""
    VERSION: str = "1.0.0"
    COMPATIBLE_AGENTS: List[str] = []  # Empty = all agents
    REQUIRED_INTEGRATIONS: List[str] = []

    def __init__(self, agent_id: str, config: Optional[Dict[str, Any]] = None):
        if not self.SKILL_NAME:
            raise ValueError(f"{self.__class__.__name__} must define SKILL_NAME")
        self.agent_id = agent_id
        self.config = config or {}
        self.initialized = False
        self.logger = logging.getLogger(f"skill.{self.SKILL_NAME}.{agent_id}")

    async def initialize(self) -> bool:
        """Initialize the skill. Override _setup for skill-specific init."""
        try:
            await self._setup()
            self.initialized = True
            self.logger.info(f"Skill '{self.SKILL_NAME}' initialized for agent {self.agent_id}")
            return True
        except Exception as e:
            self.logger.error(f"Skill '{self.SKILL_NAME}' init failed: {e}")
            return False

    async def execute(self, parameters: Dict[str, Any]) -> SkillResult:
        """
        Execute the skill with given parameters. Handles timing and
        error wrapping, delegates to _execute for skill-specific logic.
        """
        if not self.initialized:
            return SkillResult(
                success=False,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                errors=[f"Skill '{self.SKILL_NAME}' not initialized. Call initialize() first."],
            )

        start = time.monotonic()
        try:
            result = await self._execute(parameters)
            elapsed = (time.monotonic() - start) * 1000
            result.execution_time_ms = elapsed
            return result
        except Exception as e:
            elapsed = (time.monotonic() - start) * 1000
            self.logger.error(f"Skill execution failed: {e}")
            return SkillResult(
                success=False,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                errors=[str(e)],
                execution_time_ms=elapsed,
            )

    def get_metadata(self) -> Dict[str, Any]:
        """Return skill metadata for discovery and documentation."""
        return {
            "skill_name": self.SKILL_NAME,
            "description": self.DESCRIPTION,
            "version": self.VERSION,
            "compatible_agents": self.COMPATIBLE_AGENTS,
            "required_integrations": self.REQUIRED_INTEGRATIONS,
            "initialized": self.initialized,
        }

    # -------------------------------------------------------------------------
    # Abstract methods — every skill MUST implement these
    # -------------------------------------------------------------------------

    @abstractmethod
    async def _setup(self):
        """Skill-specific initialization."""
        ...

    @abstractmethod
    async def _execute(self, parameters: Dict[str, Any]) -> SkillResult:
        """
        Core skill execution logic. Must return a SkillResult.
        Parameters dict structure is skill-specific.
        """
        ...

    async def _teardown(self):
        """Skill-specific cleanup. Override if needed."""
        pass
