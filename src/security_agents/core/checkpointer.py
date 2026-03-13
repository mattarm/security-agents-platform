#!/usr/bin/env python3
"""
LangGraph Checkpointer — PostgreSQL-backed state persistence.

Uses AsyncPostgresSaver for full graph state persistence after every node.
Enables replay, audit trail, and resume after failure.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

logger = logging.getLogger(__name__)


async def create_checkpointer(db_url: Optional[str] = None) -> Optional[AsyncPostgresSaver]:
    """Create and initialize an async PostgreSQL checkpointer.

    Args:
        db_url: PostgreSQL connection string. Falls back to DATABASE_URL env var.

    Returns:
        Initialized AsyncPostgresSaver ready for use with StateGraph,
        or None if the database connection fails.
    """
    try:
        url = db_url or os.environ.get(
            "DATABASE_URL",
            "postgresql://postgres:postgres@localhost:5432/security_agents",
        )

        checkpointer = AsyncPostgresSaver.from_conn_string(url)
        await checkpointer.setup()
        return checkpointer
    except Exception as exc:
        logger.warning("Failed to create PostgreSQL checkpointer: %s. State will not be persisted.", exc)
        return None
