#!/usr/bin/env python3
"""
Base Security Agent - Abstract base class that all agents must implement.
Provides unified lifecycle, task processing, and intelligence fusion interface.
"""

import asyncio
import logging
import uuid
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Any, Optional

from security_agents.core.models import (
    AgentType, AgentStatus, AgentInfo, SecurityTask, TaskStatus,
    IntelligencePacket, IntelligenceType, Priority, SkillResult,
)

logger = logging.getLogger(__name__)


class BaseSecurityAgent(ABC):
    """
    Abstract base class for all security agents.

    Every agent in the platform (Alpha-4, Beta-4, Gamma, Delta, Sigma)
    must inherit from this class and implement the abstract methods.
    This guarantees the orchestrator can manage any agent uniformly.
    """

    # Subclasses MUST override these class-level attributes
    AGENT_ID: str = ""
    AGENT_TYPE: AgentType = None
    DISPLAY_NAME: str = ""
    CAPABILITIES: List[str] = []
    SUBSCRIPTIONS: List[IntelligenceType] = []

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        if not self.AGENT_ID:
            raise ValueError(f"{self.__class__.__name__} must define AGENT_ID")

        self.config = config or {}
        self.status = AgentStatus.INITIALIZING
        self.skills: Dict[str, Any] = {}
        self._tasks_completed = 0
        self._tasks_failed = 0
        self._last_heartbeat = datetime.now()
        self.logger = logging.getLogger(f"agent.{self.AGENT_ID}")

    # -------------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------------

    async def initialize(self) -> bool:
        """
        Initialize the agent: load config, register skills, connect to services.
        Returns True if initialization succeeded.
        """
        self.logger.info(f"Initializing {self.DISPLAY_NAME}...")
        try:
            await self._setup()
            self.status = AgentStatus.ACTIVE
            self.logger.info(f"{self.DISPLAY_NAME} initialized successfully")
            return True
        except Exception as e:
            self.status = AgentStatus.ERROR
            self.logger.error(f"{self.DISPLAY_NAME} initialization failed: {e}")
            return False

    async def shutdown(self):
        """Gracefully shut down the agent."""
        self.logger.info(f"Shutting down {self.DISPLAY_NAME}...")
        await self._teardown()
        self.status = AgentStatus.OFFLINE

    def get_info(self) -> AgentInfo:
        """Return current agent registration info for the orchestrator."""
        return AgentInfo(
            agent_id=self.AGENT_ID,
            agent_type=self.AGENT_TYPE.value if self.AGENT_TYPE else self.AGENT_ID,
            status=self.status,
            capabilities=list(self.CAPABILITIES),
            last_heartbeat=self._last_heartbeat,
            tasks_completed=self._tasks_completed,
            tasks_failed=self._tasks_failed,
            metadata={
                "display_name": self.DISPLAY_NAME,
                "skills": list(self.skills.keys()),
            },
        )

    def heartbeat(self):
        """Update heartbeat timestamp — called by the orchestrator monitor."""
        self._last_heartbeat = datetime.now()

    # -------------------------------------------------------------------------
    # Task Execution (unified interface for the orchestrator)
    # -------------------------------------------------------------------------

    async def execute(self, task: SecurityTask) -> Dict[str, Any]:
        """
        Execute a security task. This is the single entry point the
        orchestrator calls — it handles status bookkeeping and delegates
        to the agent-specific `process_task` implementation.
        """
        self.status = AgentStatus.BUSY
        task.status = TaskStatus.RUNNING
        task.started_at = datetime.now()

        try:
            results = await self.process_task(task)
            task.status = TaskStatus.COMPLETED
            task.completed_at = datetime.now()
            task.results = results
            self._tasks_completed += 1
            self.status = AgentStatus.ACTIVE
            return results
        except Exception as e:
            task.status = TaskStatus.FAILED
            task.completed_at = datetime.now()
            task.error_message = str(e)
            self._tasks_failed += 1
            self.status = AgentStatus.ACTIVE
            self.logger.error(f"Task {task.task_id} failed: {e}")
            raise

    # -------------------------------------------------------------------------
    # Intelligence Fusion
    # -------------------------------------------------------------------------

    async def receive_intelligence(self, packet: IntelligencePacket):
        """
        Called by the fusion engine when intelligence relevant to this
        agent is available. Default implementation logs; override for
        agent-specific enrichment.
        """
        self.logger.info(
            f"Received intelligence: {packet.intelligence_type.value} "
            f"from {packet.source_agent} (confidence={packet.confidence})"
        )
        await self.on_intelligence(packet)

    def create_intelligence_packet(
        self,
        intelligence_type: IntelligenceType,
        priority: Priority,
        confidence: float,
        data: Dict[str, Any],
        correlation_keys: List[str],
        target_agents: Optional[List[str]] = None,
    ) -> IntelligencePacket:
        """Helper to create a properly formatted intelligence packet."""
        return IntelligencePacket(
            packet_id=f"PKT-{self.AGENT_ID}-{uuid.uuid4().hex[:8]}",
            source_agent=self.AGENT_ID,
            target_agents=target_agents or ["all"],
            intelligence_type=intelligence_type,
            priority=priority,
            confidence=confidence,
            timestamp=datetime.now(),
            data=data,
            correlation_keys=correlation_keys,
        )

    # -------------------------------------------------------------------------
    # Abstract methods — every agent MUST implement these
    # -------------------------------------------------------------------------

    @abstractmethod
    async def _setup(self):
        """Agent-specific initialization (load models, connect to APIs, etc.)."""
        ...

    @abstractmethod
    async def process_task(self, task: SecurityTask) -> Dict[str, Any]:
        """
        Process a security task and return results as a dict.
        This is the core work method each agent specializes.
        """
        ...

    @abstractmethod
    async def on_intelligence(self, packet: IntelligencePacket):
        """React to incoming intelligence from the fusion engine."""
        ...

    async def _teardown(self):
        """Agent-specific cleanup. Override if needed."""
        pass

    # -------------------------------------------------------------------------
    # Skill management
    # -------------------------------------------------------------------------

    def register_skill(self, skill_name: str, skill_instance):
        """Register a skill with this agent."""
        self.skills[skill_name] = skill_instance
        self.logger.info(f"Registered skill: {skill_name}")

    async def execute_skill(self, skill_name: str, parameters: Dict[str, Any]) -> SkillResult:
        """Execute a registered skill by name."""
        if skill_name not in self.skills:
            return SkillResult(
                success=False,
                skill_name=skill_name,
                agent_id=self.AGENT_ID,
                errors=[f"Skill '{skill_name}' not registered"],
            )
        skill = self.skills[skill_name]
        return await skill.execute(parameters)
