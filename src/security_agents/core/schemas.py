#!/usr/bin/env python3
"""
Pydantic v2 Schemas + LangGraph State — additive layer over existing dataclasses.

Existing models.py dataclasses remain untouched. This module provides:
1. LangGraph-specific state (OrchestratorState TypedDict)
2. Structured LLM output models (AgentResult, RouterDecision, SynthesisResult)
"""

from __future__ import annotations

import operator
from typing import Annotated, Any, Dict, List, Optional, TypedDict

from langchain_core.messages import AnyMessage
from langgraph.graph.message import add_messages
from pydantic import BaseModel, Field


# =============================================================================
# Structured LLM Output Models
# =============================================================================

class AgentResult(BaseModel):
    """Structured result from a single agent's execution."""
    agent_id: str
    agent_name: str
    status: str = "completed"
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    intelligence_packets: List[Dict[str, Any]] = Field(default_factory=list)
    risk_delta: float = Field(default=0.0, description="Change in risk score from this analysis")
    recommended_next_agents: List[str] = Field(
        default_factory=list,
        description="Other agents that should run based on these findings",
    )
    errors: List[str] = Field(default_factory=list)
    execution_time_ms: float = 0.0


# Used as structured output format reference for LLM prompts
# (see prompts/router.py and prompts/synthesis.py)

class RouterDecision(BaseModel):
    """Structured output from the router node — which agents to invoke."""
    agents: List[str] = Field(description="Agent IDs to invoke")
    rationale: str = Field(description="Why these agents were selected")
    execution_order: str = Field(
        default="parallel",
        description="'parallel' or 'sequential'",
    )
    priority_overrides: Dict[str, str] = Field(
        default_factory=dict,
        description="Per-agent priority overrides",
    )


class SynthesisResult(BaseModel):
    """Structured output from the synthesis node."""
    executive_summary: str
    risk_score: float = Field(ge=0.0, le=100.0)
    key_findings: List[Dict[str, Any]] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    compliance_impact: Optional[Dict[str, Any]] = None
    next_steps: List[str] = Field(default_factory=list)


# =============================================================================
# LangGraph Orchestrator State (TypedDict with reducers)
# =============================================================================

class OrchestratorState(TypedDict):
    """
    Shared state for the LangGraph orchestrator graph.

    Annotated fields use reducers for fan-in from parallel agent execution:
    - messages: append-only message list (add_messages handles dedup)
    - agent_results: list of AgentResult dicts, merged via operator.add
    - intelligence_packets: list of packet dicts, merged via operator.add
    """
    messages: Annotated[list[AnyMessage], add_messages]
    request: dict
    agent_results: Annotated[list[dict], operator.add]
    intelligence_packets: Annotated[list[dict], operator.add]
    fusion_results: dict
    autonomy_tier: int
    human_feedback: Optional[dict]
    current_phase: str
