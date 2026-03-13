"""Shared utilities for building agent sub-graphs."""

from __future__ import annotations

from typing import List

from langchain_anthropic import ChatAnthropic
from langgraph.prebuilt import create_react_agent


def build_react_agent(
    model_name: str,
    tools: List,
    system_prompt: str,
    agent_id: str,
):
    """Build a ReAct agent sub-graph for a security agent.

    Args:
        model_name: Anthropic model ID (e.g., "claude-sonnet-4-6")
        tools: List of @tool-decorated functions
        system_prompt: Agent system prompt
        agent_id: Agent identifier for metadata
    """
    llm = ChatAnthropic(model=model_name, max_tokens=4096)

    graph = create_react_agent(
        model=llm,
        tools=tools,
        prompt=system_prompt,
        name=agent_id,
    )

    return graph
