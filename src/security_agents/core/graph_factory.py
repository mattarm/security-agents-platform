#!/usr/bin/env python3
"""
Graph Factory — builds and compiles the LangGraph orchestrator.

Used by the API server to get a ready-to-invoke compiled graph:
    factory = GraphFactory()
    app = await factory.build()
    result = await app.ainvoke(state, config={"configurable": {"thread_id": request_id}})
"""

from __future__ import annotations

import logging
from typing import Optional

from langgraph.graph.state import CompiledStateGraph

from security_agents.core.graph_orchestrator import build_orchestrator_graph

logger = logging.getLogger(__name__)


class GraphFactory:
    """Builds the compiled LangGraph orchestrator with optional checkpointing."""

    def __init__(self, db_url: Optional[str] = None):
        self._db_url = db_url
        self._compiled: Optional[CompiledStateGraph] = None

    async def build(self, with_checkpointer: bool = False) -> CompiledStateGraph:
        """Build and return the compiled orchestrator graph.

        Args:
            with_checkpointer: If True, attaches PostgreSQL checkpointer for
                              state persistence. Requires DATABASE_URL.

        Raises:
            RuntimeError: If graph compilation fails.
        """
        graph = build_orchestrator_graph()

        checkpointer = None
        if with_checkpointer:
            from security_agents.core.checkpointer import create_checkpointer
            checkpointer = await create_checkpointer(self._db_url)
            if checkpointer is None:
                logger.warning(
                    "Checkpointer unavailable — graph state will not be persisted. "
                    "Check DATABASE_URL and PostgreSQL connectivity."
                )
            else:
                logger.info("Checkpointer attached — state will be persisted to PostgreSQL")

        try:
            self._compiled = graph.compile(checkpointer=checkpointer)
        except Exception as exc:
            raise RuntimeError(f"Failed to compile orchestrator graph: {exc}") from exc

        logger.info("Orchestrator graph compiled and ready")
        return self._compiled

    @property
    def compiled(self) -> CompiledStateGraph:
        """Return the compiled graph. Raises if build() has not been called."""
        if self._compiled is None:
            raise RuntimeError("Graph not compiled yet — call await factory.build() first")
        return self._compiled
